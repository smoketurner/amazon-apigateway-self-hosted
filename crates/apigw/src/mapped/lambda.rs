//! The backend of a non-proxy Lambda integration: the rendered request
//! template is the function's event, and the function's output (or its error)
//! goes back through the integration response.

use std::time::Duration;

use axum::body::Bytes;
use axum::http::HeaderMap;
use serde_json::Value;

use crate::aws::{FunctionArn, InvocationType, RoleArn};
use crate::gateway::{ApiContext, GatewayError};
use crate::lambda::LAMBDA_PAYLOAD_LIMIT;
use crate::mapped::{BackendReply, BackendRequest};
use crate::model::{ApiKind, IntegrationSpec};
use crate::pipeline::RequestContext;
use crate::request_parameters::RequestParameters;

/// The header that makes an invocation asynchronous (`Event`).
const INVOCATION_TYPE_HEADER: &str = "x-amz-invocation-type";

/// A compiled non-proxy Lambda integration.
#[derive(Debug, Clone)]
pub(crate) struct LambdaBackend {
    pub(crate) function: FunctionArn,
    pub(crate) role: Option<RoleArn>,
    timeout: Duration,
    parameters: RequestParameters,
}

impl LambdaBackend {
    pub(crate) fn compile(
        spec: &IntegrationSpec,
        function: FunctionArn,
        role: Option<RoleArn>,
        timeout: Duration,
    ) -> Self {
        Self {
            function,
            role,
            timeout,
            parameters: RequestParameters::compile(&spec.request_parameters, ApiKind::Rest),
        }
    }

    /// Invokes the function with the rendered request template as its event.
    /// `X-Amz-Invocation-Type`, set by a header mapping or the template, picks
    /// synchronous (`RequestResponse`, the default) or asynchronous (`Event`).
    pub(crate) async fn exchange(
        &self,
        api: &ApiContext,
        ctx: &mut RequestContext,
        request: BackendRequest,
    ) -> Result<BackendReply, GatewayError> {
        let mut headers = HeaderMap::new();
        self.parameters
            .add_headers(&mut headers, ctx, &request.overrides);
        let invocation_type = match headers.get(INVOCATION_TYPE_HEADER) {
            None => InvocationType::default(),
            Some(value) => value
                .to_str()
                .map_err(|err| err.to_string())
                .and_then(str::parse)
                .map_err(|reason| {
                    tracing::error!(function = %self.function, reason, "invalid X-Amz-Invocation-Type");
                    GatewayError::ApiConfiguration
                })?,
        };
        if request.body.len() > LAMBDA_PAYLOAD_LIMIT {
            tracing::warn!(function = %self.function, bytes = request.body.len(), "event is larger than Lambda's invocation payload limit");
            return Err(GatewayError::IntegrationFailure);
        }
        let call = api.aws.invoke_lambda_as(
            &self.function,
            self.role.as_ref(),
            request.body.to_vec(),
            ctx.trace_header(),
            invocation_type,
        );
        let invocation = match tokio::time::timeout(self.timeout, call).await {
            Err(_) => {
                tracing::warn!(function = %self.function, "Lambda invocation timed out");
                return Err(GatewayError::IntegrationTimeout);
            }
            Ok(Err(err)) => {
                tracing::error!(function = %self.function, %err, "Lambda invocation failed");
                return Err(GatewayError::IntegrationFailure);
            }
            Ok(Ok(invocation)) => invocation,
        };
        if invocation.payload.len() > LAMBDA_PAYLOAD_LIMIT {
            tracing::error!(function = %self.function, bytes = invocation.payload.len(), "Lambda response is larger than the invocation payload limit");
            return Err(GatewayError::IntegrationFailure);
        }
        ctx.integration.status = Some(invocation.status);
        let error_message = invocation
            .function_error
            .as_ref()
            .and_then(|_| error_message(&invocation.payload));
        Ok(BackendReply::lambda(
            invocation.status,
            Bytes::from(invocation.payload),
            error_message,
        ))
    }
}

/// The `errorMessage` of a function error's payload.
fn error_message(payload: &[u8]) -> Option<String> {
    let document: Value = serde_json::from_slice(payload).ok()?;
    document.get("errorMessage")?.as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_error_message_is_read_from_the_function_error_payload() {
        assert_eq!(
            error_message(br#"{"errorMessage":"boom","errorType":"Error"}"#),
            Some("boom".to_owned())
        );
        for payload in [&b""[..], b"not json", b"{}", br#"{"errorMessage":3}"#] {
            assert_eq!(error_message(payload), None);
        }
    }
}
