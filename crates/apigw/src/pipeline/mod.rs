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

use std::time::Instant;

use axum::body::{Body, Bytes};
use axum::extract::{FromRequestParts as _, RawPathParams, Request};
use axum::http::header;
use axum::response::{IntoResponse as _, Response};

pub(crate) use context::RequestContext;

use crate::authz::{AuthRequest, Denial};
use crate::cache::CacheOutcome;
use crate::cors::Cors;
use crate::gateway::{ApiContext, GatewayError, MAX_BODY_BYTES};
use crate::gateway_response::Failure;
use crate::integration::{Integration, MockResponse};
use crate::model::{ApiKind, Protection, ResponseTransferMode, ResponseType};
use crate::observability::IntegrationTiming;
use crate::payload::PayloadSettings;
use crate::route::Route;
use crate::state::Admission;

/// One route's handling of one request.
pub(crate) struct Pipeline<'a> {
    api: &'a ApiContext,
    route: &'a Route,
    /// Path parameters the router already matched; when absent they are read
    /// from the request.
    path_params: Option<Vec<(String, String)>>,
}

impl<'a> Pipeline<'a> {
    pub(crate) fn new(api: &'a ApiContext, route: &'a Route) -> Self {
        Self {
            api,
            route,
            path_params: None,
        }
    }

    #[must_use]
    pub(crate) fn with_path_params(mut self, params: Vec<(String, String)>) -> Self {
        self.path_params = Some(params);
        self
    }

    pub(crate) async fn run(self, request: Request) -> Response {
        let (mut parts, body) = request.into_parts();
        let path_params = match self.path_params {
            Some(ref params) => Ok(params.clone()),
            None => RawPathParams::from_request_parts(&mut parts, &())
                .await
                .map(|params| {
                    params
                        .iter()
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect::<Vec<_>>()
                }),
        };
        let readable = path_params.is_ok();
        let mut ctx = RequestContext::new(
            self.api,
            Some(self.route),
            parts,
            path_params.unwrap_or_default(),
        );
        let mut response = self.process(&mut ctx, body, readable).await;
        if let Some(ref cors) = self.api.cors {
            cors.decorate(&ctx, &mut response);
        }
        response
    }

    async fn process(&self, ctx: &mut RequestContext, body: Body, readable: bool) -> Response {
        if let Some(protection) = self.refusal() {
            return self.fail(ctx, &protection.refusal(self.api.kind));
        }
        if let Some(failure) = self.throttled().await {
            return self.fail(ctx, &failure);
        }
        if !readable {
            return self.fail(ctx, &GatewayError::InvalidRequest.failure(self.api.kind));
        }
        if let Err(denial) = self.authorize(ctx).await {
            return self.fail(ctx, &denial.failure(self.api.kind));
        }
        if let Some(ref cors) = self.api.cors
            && Cors::is_preflight(ctx)
        {
            return cors.preflight(ctx);
        }
        match self.receive(body).await {
            Ok(body) => ctx.body = body,
            Err(error) => return self.fail(ctx, &error.failure(self.api.kind)),
        }
        if let Err(error) = self.decode_request(ctx) {
            return self.fail(ctx, &error.failure(self.api.kind));
        }
        let plan = match self.route.cache.as_ref().map(|cache| cache.plan(ctx)) {
            Some(Ok(plan)) => plan,
            Some(Err(failure)) => return self.fail(ctx, &failure),
            None => None,
        };
        if let Some(ref plan) = plan
            && let Some(hit) = plan.lookup(&self.api.state).await
        {
            return self.encode(ctx, hit).await;
        }
        let started = Instant::now();
        let result = self.integrate(ctx).await;
        let timing = IntegrationTiming(started.elapsed());
        let succeeded = result.is_ok();
        let mut response = match result {
            Ok(response) => response,
            Err(error) => self.fail(ctx, &error.failure(self.api.kind)),
        };
        response.extensions_mut().insert(timing);
        let response = match plan {
            Some(plan) if succeeded => match plan.store(&self.api.state, response).await {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(%error, "the integration response failed while being read");
                    return self.fail(
                        ctx,
                        &GatewayError::IntegrationFailure.failure(self.api.kind),
                    );
                }
            },
            Some(plan) => {
                plan.finish(&mut response, CacheOutcome::Miss);
                response
            }
            None => response,
        };
        if succeeded {
            self.encode(ctx, response).await
        } else {
            response
        }
    }

    /// Compresses an integration response for this client, or answers with the
    /// gateway error when that fails.
    async fn encode(&self, ctx: &RequestContext, response: Response) -> Response {
        match self.encode_response(ctx, response).await {
            Ok(response) => response,
            Err(error) => self.fail(ctx, &error.failure(self.api.kind)),
        }
    }

    /// REST APIs decompress `gzip` and `deflate` request bodies before the
    /// integration sees them.
    fn decode_request(&self, ctx: &mut RequestContext) -> Result<(), GatewayError> {
        if self.api.kind != ApiKind::Rest {
            return Ok(());
        }
        let body = std::mem::take(&mut ctx.body);
        ctx.body = PayloadSettings::decompress_request(&mut ctx.headers, body)?;
        Ok(())
    }

    /// REST APIs with a `minimumCompressionSize` compress buffered integration
    /// responses for clients that accept a coding. Streamed responses are never
    /// compressed.
    async fn encode_response(
        &self,
        ctx: &RequestContext,
        response: Response,
    ) -> Result<Response, GatewayError> {
        if self.api.kind != ApiKind::Rest
            || ctx.integration.transfer_mode == Some(ResponseTransferMode::Stream)
        {
            return Ok(response);
        }
        self.api
            .payload
            .compress_response(&ctx.headers, response)
            .await
    }

    /// The failure for a request over the route's throttle limit. Runs before
    /// the body is read, so a throttled request costs no buffering.
    async fn throttled(&self) -> Option<Failure> {
        let throttle = self.route.throttle.as_ref()?;
        match throttle.admit(&self.api.state).await {
            Admission::Admitted => None,
            Admission::Throttled => Some(Failure::new(ResponseType::Throttled)),
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

    /// Checks the resource policy and the route's authorizer, and records what
    /// the authorizer contributes to `$context.authorizer`. Authorization
    /// happens before the body is read so that a request that is turned away
    /// costs no buffering. `--insecure-skip-authorization` skips authorizers
    /// but never the resource policy.
    async fn authorize(&self, ctx: &mut RequestContext) -> Result<(), Denial> {
        let request = AuthRequest {
            aws: &self.api.aws,
            keys: &self.api.keys,
            state: &self.api.state,
            ctx,
        };
        let context = request
            .authorize(self.route, self.api.enforcement.authorization)
            .await?;
        ctx.authorizer = context;
        Ok(())
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
