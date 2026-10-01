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

use axum::body::Body;
use axum::extract::{FromRequestParts as _, RawPathParams, Request};
use axum::http::header;
use axum::response::{IntoResponse as _, Response};
use uuid::Uuid;

pub(crate) use context::{ApiInfo, AuthorizerContext, IntegrationOutcome, QueryString, RequestContext};

use crate::authz::{AuthRequest, Denial, RouteAuthorizer};
use crate::gateway::{ApiContext, AuthorizationMode, GatewayError, MAX_BODY_BYTES, RequestId};
use crate::identity::ClientIdentity;
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
        if let Some(protection) = self.refusal() {
            return protection.refusal_response(self.api.kind);
        }
        let mut ctx = match self.receive(request).await {
            Ok(ctx) => ctx,
            Err(error) => return error.response(self.api.kind),
        };
        if let Err(denial) = self.authorize(&mut ctx).await {
            return denial.response(self.api.kind);
        }
        self.integrate(ctx).await
    }

    /// The protection that refuses this request, if any: routes whose
    /// protections this gateway can't evaluate are refused in API Gateway's
    /// evaluation order.
    fn refusal(&self) -> Option<Protection> {
        self.api.enforcement.refusals(self.route).next()
    }

    /// Buffers the body (API Gateway buffers too, up to [`MAX_BODY_BYTES`]) and
    /// captures everything later stages read into a [`RequestContext`].
    async fn receive(&self, request: Request) -> Result<RequestContext, GatewayError> {
        let (mut parts, body) = request.into_parts();
        let path_params = RawPathParams::from_request_parts(&mut parts, &())
            .await
            .map_err(|_| GatewayError::InvalidRequest)?
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        let body = axum::body::to_bytes(body, MAX_BODY_BYTES)
            .await
            .map_err(|_| GatewayError::RequestTooLarge)?;
        let request_id = parts
            .extensions
            .get::<RequestId>()
            .map_or_else(Uuid::now_v7, |id| id.0);
        let identity = parts
            .extensions
            .remove::<ClientIdentity>()
            .unwrap_or_else(|| {
                tracing::warn!("request reached the pipeline without a client identity");
                ClientIdentity::unknown()
            });
        Ok(RequestContext {
            api: ApiInfo {
                kind: self.api.kind,
                api_id: self.api.api_id.clone(),
                stage: self.api.stage.clone(),
            },
            route_key: self.route.key.clone(),
            resource_path: self.route.path.to_string(),
            request_id,
            received: jiff::Timestamp::now(),
            method: parts.method,
            path: parts.uri.path().to_owned(),
            query: QueryString::new(parts.uri.query()),
            headers: parts.headers,
            path_params,
            identity,
            body,
            authorizer: AuthorizerContext::default(),
            integration: IntegrationOutcome::default(),
        })
    }

    /// Runs the route's authorizer and records what it contributes to
    /// `$context.authorizer`. `--insecure-skip-authorization` skips it.
    async fn authorize(&self, ctx: &mut RequestContext) -> Result<(), Denial> {
        let RouteAuthorizer::Evaluated(ref authorizer) = self.route.authorizer else {
            return Ok(());
        };
        if self.api.enforcement.authorization == AuthorizationMode::Skip {
            return Ok(());
        }
        let request = AuthRequest {
            aws: &self.api.aws,
            ctx,
            stage_variables: &self.api.stage_variables,
        };
        ctx.authorizer = authorizer.authorize(&request).await?;
        Ok(())
    }

    async fn integrate(&self, ctx: RequestContext) -> Response {
        match self.route.integration {
            Integration::HttpProxy(ref target) => {
                target.forward(&self.api.http, self.route, ctx).await
            }
            Integration::Lambda(ref target) => {
                target
                    .invoke(&self.api.aws, self.route, &ctx, &self.api.stage_variables)
                    .await
            }
            Integration::Mock(ref mock) => mock.respond(),
            Integration::Unsupported { ref reason } => {
                tracing::warn!(route = %self.route.key, reason, "unsupported integration invoked");
                GatewayError::UnsupportedIntegration.response(self.api.kind)
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
