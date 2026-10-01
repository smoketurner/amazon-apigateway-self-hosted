//! The backend of a REST `AWS` integration that names a service other than
//! Lambda: the integration request is signed with `SigV4` and sent to the
//! service's API.

use std::time::Duration;

use axum::http::{HeaderMap, Method, header};

use crate::aws::RoleArn;
use crate::aws_service::{ServiceCall, ServiceUri, UriTarget};
use crate::gateway::{ApiContext, GatewayError};
use crate::mapped::{BackendReply, BackendRequest};
use crate::model::{ApiKind, IntegrationSpec};
use crate::pipeline::RequestContext;
use crate::request_parameters::RequestParameters;

/// A compiled REST `AWS` integration to an AWS service.
#[derive(Debug, Clone)]
pub(crate) struct AwsBackend {
    /// The integration URI as written, for `/routes`.
    pub(crate) uri_text: String,
    uri: ServiceUri,
    method: Method,
    pub(crate) role: Option<RoleArn>,
    timeout: Duration,
    parameters: RequestParameters,
}

impl AwsBackend {
    /// # Errors
    ///
    /// Fails when the integration has no usable `httpMethod`.
    pub(crate) fn compile(
        spec: &IntegrationSpec,
        uri_text: String,
        uri: ServiceUri,
        role: Option<RoleArn>,
        timeout: Duration,
    ) -> Result<Self, String> {
        let method = spec
            .http_method
            .as_deref()
            .ok_or("an AWS integration needs an httpMethod")?;
        let method = Method::from_bytes(method.to_ascii_uppercase().as_bytes())
            .map_err(|_| format!("invalid integration httpMethod {method:?}"))?;
        Ok(Self {
            uri_text,
            uri,
            method,
            role,
            timeout,
            parameters: RequestParameters::compile(&spec.request_parameters, ApiKind::Rest),
        })
    }

    pub(crate) async fn exchange(
        &self,
        api: &ApiContext,
        ctx: &mut RequestContext,
        request: BackendRequest,
    ) -> Result<BackendReply, GatewayError> {
        let (path, action) = match self.uri.target {
            UriTarget::Action(ref action) => ("/".to_owned(), Some(action.clone())),
            UriTarget::Path(ref path) => {
                let template = format!("/{path}");
                let expanded = self
                    .parameters
                    .expand(&template, ctx, &request.overrides, None)
                    .map_err(|reason| {
                        tracing::error!(uri = self.uri_text, reason, "invalid integration URI");
                        GatewayError::ApiConfiguration
                    })?;
                (expanded, None)
            }
        };
        let mut headers = HeaderMap::new();
        self.parameters
            .add_headers(&mut headers, ctx, &request.overrides);
        if let Some(content_type) = request.content_type
            && !headers.contains_key(header::CONTENT_TYPE)
        {
            headers.insert(header::CONTENT_TYPE, content_type);
        }
        let call = ServiceCall {
            service: self.uri.service,
            partition: self.uri.partition.clone(),
            region: self.uri.region.clone(),
            method: self.method.clone(),
            path,
            query: self.parameters.query_pairs(ctx, &request.overrides),
            headers,
            body: request.body,
            action,
        };
        let reply = call
            .execute(&api.aws, &api.http, self.role.as_ref(), self.timeout)
            .await
            .map_err(|error| {
                tracing::warn!(uri = self.uri_text, %error, "AWS service call failed");
                GatewayError::from(&error)
            })?;
        ctx.integration.status = Some(reply.status);
        Ok(reply)
    }
}
