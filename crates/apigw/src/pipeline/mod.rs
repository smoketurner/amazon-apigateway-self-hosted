//! Request execution in API Gateway's order. Each stage is a method on
//! [`Pipeline`]; later stages (authorizers, validation, throttling, caching,
//! mapping templates) slot in between the existing ones in this order:
//!
//! ```text
//! route match (router) → resource policy → API key → authorizer
//!   → request validation → throttling → cache → integration request
//!   → integration → integration response → gateway response on error
//! ```

pub(crate) mod context;

use axum::body::{Body, Bytes};
use axum::extract::{FromRequestParts as _, RawPathParams, Request};
use axum::http::header;
use axum::response::{IntoResponse as _, Response};

pub(crate) use context::RequestContext;

use crate::gateway::{ApiContext, GatewayError, MAX_BODY_BYTES};
use crate::gateway_response::Failure;
use crate::integration::{Integration, MockResponse};
use crate::model::Protection;
use crate::route::Route;

/// One route's handling of one request.
pub(crate) struct Pipeline<'a> {
    api: &'a ApiContext,
    route: &'a Route,
}

impl<'a> Pipeline<'a> {
    pub(crate) fn new(api: &'a ApiContext, route: &'a Route) -> Self {
        Self { api, route }
    }

    pub(crate) async fn run(self, request: Request) -> Response {
        let (mut parts, body) = request.into_parts();
        let path_params = RawPathParams::from_request_parts(&mut parts, &())
            .await
            .map(|params| {
                params
                    .iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect::<Vec<_>>()
            });
        let readable = path_params.is_ok();
        let mut ctx = RequestContext::new(
            self.api,
            Some(self.route),
            parts,
            path_params.unwrap_or_default(),
        );
        if let Some(protection) = self.refusal() {
            return self.fail(&ctx, &protection.refusal(self.api.kind));
        }
        if !readable {
            return self.fail(&ctx, &GatewayError::InvalidRequest.failure(self.api.kind));
        }
        match self.receive(body).await {
            Ok(body) => ctx.body = body,
            Err(error) => return self.fail(&ctx, &error.failure(self.api.kind)),
        }
        match self.integrate(&mut ctx).await {
            Ok(response) => response,
            Err(error) => self.fail(&ctx, &error.failure(self.api.kind)),
        }
    }

    fn fail(&self, ctx: &RequestContext, failure: &Failure) -> Response {
        self.api.respond(ctx, failure)
    }

    /// The protection that refuses this request, if any: routes whose
    /// protections this gateway can't evaluate are refused in API Gateway's
    /// evaluation order.
    fn refusal(&self) -> Option<Protection> {
        self.api.enforcement.refusals(self.route).next()
    }

    /// Buffers the body (API Gateway buffers too, up to [`MAX_BODY_BYTES`]).
    async fn receive(&self, body: Body) -> Result<Bytes, GatewayError> {
        axum::body::to_bytes(body, MAX_BODY_BYTES)
            .await
            .map_err(|_| GatewayError::RequestTooLarge)
    }

    async fn integrate(&self, ctx: &mut RequestContext) -> Result<Response, GatewayError> {
        match self.route.integration {
            Integration::HttpProxy(ref target) => {
                target.forward(&self.api.http, self.route, ctx).await
            }
            Integration::Lambda(ref target) => {
                target
                    .invoke(&self.api.aws, self.route, ctx, &self.api.stage_variables)
                    .await
            }
            Integration::Mock(ref mock) => Ok(mock.respond()),
            Integration::Unsupported { ref reason } => {
                tracing::warn!(route = %self.route.key, reason, "unsupported integration invoked");
                Err(GatewayError::UnsupportedIntegration)
            }
        }
    }
}

impl MockResponse {
    fn respond(&self) -> Response {
        let mut response = Response::new(Body::from(self.body.clone()));
        *response.status_mut() = self.status;
        let headers = response.headers_mut();
        if let Some(ref content_type) = self.content_type {
            headers.insert(header::CONTENT_TYPE, content_type.clone());
        }
        for (name, value) in &self.headers {
            headers.insert(name.clone(), value.clone());
        }
        response.into_response()
    }
}
