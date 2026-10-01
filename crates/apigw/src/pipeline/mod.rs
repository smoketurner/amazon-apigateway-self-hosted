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
use axum::response::Response;

pub(crate) use context::{ApiKeyIdentity, RequestContext};

use crate::authz::{AuthRequest, Denial};
use crate::cache::CacheOutcome;
use crate::cors::Cors;
use crate::digest::Sha256Digest;
use crate::gateway::{ApiContext, AuthorizationMode, GatewayError, MAX_BODY_BYTES};
use crate::gateway_response::Failure;
use crate::integration::Integration;
use crate::model::{ApiKeySource, ApiKind, Protection, ResponseTransferMode, ResponseType};
use crate::observability::IntegrationTiming;
use crate::payload::PayloadSettings;
use crate::route::Route;
use crate::state::Admission;
use crate::usage::{KeyValue, RouteApiKey, UsageOutcome};

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
        let authorizer_key = match self.authorize(ctx).await {
            Ok(key) => key,
            Err(denial) => return self.fail(ctx, &denial.failure(self.api.kind)),
        };
        if let Err(failure) = self.api_key(ctx, authorizer_key).await {
            return self.fail(ctx, &failure);
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
    /// but never the resource policy. Returns the API key the authorizer named
    /// for usage plans, if any.
    async fn authorize(&self, ctx: &mut RequestContext) -> Result<Option<Sha256Digest>, Denial> {
        let request = AuthRequest {
            aws: &self.api.aws,
            keys: &self.api.keys,
            state: &self.api.state,
            ctx,
        };
        let admitted = request
            .authorize(self.route, self.api.enforcement.authorization)
            .await?;
        ctx.authorizer = admitted.context;
        Ok(admitted.usage_key)
    }

    /// Checks the API key on a method that requires one: it must exist, be
    /// enabled, and belong to a usage plan of the stage, whose throttle and
    /// quota then count the request. `--insecure-skip-authorization` skips it.
    async fn api_key(
        &self,
        ctx: &mut RequestContext,
        authorizer_key: Option<Sha256Digest>,
    ) -> Result<(), Failure> {
        let RouteApiKey::Required(source) = self.route.api_key else {
            return Ok(());
        };
        if self.api.enforcement.authorization == AuthorizationMode::Skip {
            return Ok(());
        }
        let invalid = || Failure::new(ResponseType::InvalidApiKey);
        let Some(ref usage) = self.api.usage else {
            return Err(invalid());
        };
        let (digest, value) = match source {
            ApiKeySource::Header => {
                let presented = ctx
                    .header_str("x-api-key")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(invalid)?;
                (KeyValue::digest(presented), Some(presented.to_owned()))
            }
            ApiKeySource::Authorizer => (authorizer_key.ok_or_else(invalid)?, None),
        };
        let Some(data) = usage.current() else {
            tracing::warn!(
                "API keys have not been read recently enough to be trusted; refusing the request"
            );
            return Err(invalid());
        };
        let access = data.lookup_digest(&digest).ok_or_else(invalid)?;
        let method = self.route.plan_throttle_key();
        for plan in &access.plans {
            let outcome = usage
                .checker()
                .admit(&self.api.state, &plan.limits, &plan.id, access.key, &method)
                .await;
            match outcome {
                UsageOutcome::Admitted => {}
                UsageOutcome::Throttled => return Err(Failure::new(ResponseType::Throttled)),
                UsageOutcome::QuotaExceeded => {
                    return Err(Failure::new(ResponseType::QuotaExceeded));
                }
            }
        }
        ctx.api_key = Some(ApiKeyIdentity::new(access.key.0.clone(), value));
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
            Integration::Mapped(ref mapped) => mapped.run(self.api, self.route, ctx).await,
            Integration::Unsupported { ref reason } => {
                tracing::warn!(route = %self.route.key, reason, "unsupported integration invoked");
                Err(GatewayError::UnsupportedIntegration)
            }
        }
    }
}
