//! Non-proxy REST integrations (`HTTP` and `MOCK`): the method request becomes
//! an integration request through parameter mappings and a Velocity template,
//! the backend answers, and an integration response is selected by
//! `selectionPattern` and mapped back into the method response.
//!
//! ```text
//! method request → requestParameters → request template (by Content-Type,
//!   else passthroughBehavior) → backend → selectionPattern → responseParameters
//!   → response template (by Accept) → method response
//! ```
//!
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-integration-settings.html>

pub(crate) mod content;
#[cfg(test)]
mod end_to_end;
mod request;
mod response;
mod vtl;

use axum::body::Bytes;
use axum::response::Response;
use serde_json::Value;

pub(crate) use request::{BackendRequest, RequestSide};
pub(crate) use response::{BackendReply, ResponseSide};
pub(crate) use vtl::RequestOverrides;

use crate::gateway::{ApiContext, GatewayError};
use crate::integration::HttpProxy;
use crate::model::IntegrationSpec;
use crate::pipeline::RequestContext;
use crate::route::Route;

/// Where a non-proxy integration sends the integration request.
#[derive(Debug, Clone)]
pub(crate) enum Backend {
    Http(Box<HttpProxy>),
    /// No backend: the rendered request template's `statusCode` picks the
    /// integration response.
    Mock,
}

/// A compiled non-proxy integration.
#[derive(Debug, Clone)]
pub(crate) struct MappedIntegration {
    pub(crate) backend: Backend,
    request: RequestSide,
    response: ResponseSide,
}

impl MappedIntegration {
    pub(crate) fn compile(spec: &IntegrationSpec, backend: Backend) -> Self {
        Self {
            backend,
            request: RequestSide::compile(spec),
            response: ResponseSide::compile(spec),
        }
    }

    pub(crate) fn kind(&self) -> &'static str {
        match self.backend {
            Backend::Http(_) => "HTTP",
            Backend::Mock => "MOCK",
        }
    }

    /// The backend's address, for `/routes`.
    pub(crate) fn target(&self) -> Option<String> {
        match self.backend {
            Backend::Http(ref http) => Some(http.uri.clone()),
            Backend::Mock => None,
        }
    }

    /// Templates and patterns that cannot work, for `/routes`.
    pub(crate) fn problems(&self) -> Vec<String> {
        let mut problems = self.request.problems();
        problems.extend(self.response.problems());
        problems
    }

    pub(crate) async fn run(
        &self,
        api: &ApiContext,
        route: &Route,
        ctx: &mut RequestContext,
    ) -> Result<Response, GatewayError> {
        let request = self.request.prepare(api, ctx)?;
        let reply = match self.backend {
            Backend::Http(ref http) => http.exchange(&api.http, route, ctx, request).await?,
            Backend::Mock => mock_reply(&request),
        };
        self.response.finish(api, ctx, &reply)
    }
}

/// A MOCK integration's answer: the request template's output is the body, and
/// its `statusCode` is the status the integration response is selected by.
/// Output with no usable `statusCode` selects status 200.
fn mock_reply(request: &BackendRequest) -> BackendReply {
    let status = serde_json::from_slice::<Value>(&request.body)
        .ok()
        .and_then(|document| match document.get("statusCode")? {
            Value::Number(number) => number.as_u64().and_then(|n| u16::try_from(n).ok()),
            Value::String(text) => text.trim().parse().ok(),
            Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
        })
        .unwrap_or(200);
    BackendReply {
        status,
        headers: axum::http::HeaderMap::new(),
        body: Bytes::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapped::vtl::RequestOverrides;

    fn request(body: &'static str) -> BackendRequest {
        BackendRequest {
            body: Bytes::from_static(body.as_bytes()),
            content_type: None,
            overrides: RequestOverrides::default(),
        }
    }

    #[test]
    fn mock_status_comes_from_the_rendered_template() {
        assert_eq!(mock_reply(&request(r#"{"statusCode": 418}"#)).status, 418);
        assert_eq!(mock_reply(&request(r#"{"statusCode": "204"}"#)).status, 204);
    }

    #[test]
    fn mock_status_defaults_to_200() {
        for body in [
            "",
            "not json",
            "{}",
            r#"{"statusCode": true}"#,
            r#"{"statusCode": 99999}"#,
        ] {
            assert_eq!(mock_reply(&request(body)).status, 200, "{body}");
        }
    }
}
