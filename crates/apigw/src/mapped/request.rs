//! The integration request of a non-proxy integration: which request template
//! applies, what `passthroughBehavior` does when none does, and what the
//! template overrides.

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::http::{HeaderValue, header};

use crate::gateway::GatewayError;
use crate::mapped::content::{self, DEFAULT_MEDIA_TYPE, Payload, media_type};
use crate::mapped::vtl::{CompiledTemplate, GatewayInput, RequestOverrides, render};
use crate::model::{ContentHandling, IntegrationSpec, PassthroughBehavior};
use crate::pipeline::RequestContext;

/// The request side of a non-proxy integration.
#[derive(Debug, Clone)]
pub(crate) struct RequestSide {
    /// Request templates by lowercase content type.
    templates: BTreeMap<String, Template>,
    passthrough: PassthroughBehavior,
    content_handling: Option<ContentHandling>,
}

#[derive(Debug, Clone)]
struct Template {
    /// The content type as the integration spells it, sent to the backend.
    content_type: String,
    compiled: CompiledTemplate,
}

/// The integration request after mapping: what is sent besides the parameters
/// `requestParameters` map.
#[derive(Debug, Clone)]
pub(crate) struct BackendRequest {
    pub(crate) body: Bytes,
    pub(crate) content_type: Option<HeaderValue>,
    pub(crate) overrides: RequestOverrides,
}

impl RequestSide {
    pub(crate) fn compile(spec: &IntegrationSpec) -> Self {
        let mut templates = BTreeMap::new();
        for (content_type, source) in &spec.request_templates {
            let Some(source) = source else {
                continue;
            };
            templates.insert(
                media_type(content_type),
                Template {
                    content_type: content_type.clone(),
                    compiled: CompiledTemplate::compile(source),
                },
            );
        }
        Self {
            templates,
            passthrough: spec
                .passthrough_behavior
                .unwrap_or(PassthroughBehavior::WhenNoMatch),
            content_handling: spec.content_handling,
        }
    }

    /// Why a template cannot run, for `/routes`.
    pub(crate) fn problems(&self) -> Vec<String> {
        self.templates
            .iter()
            .filter_map(|(content_type, template)| {
                template.compiled.problem().map(|reason| {
                    format!("request template for {content_type} is invalid: {reason}")
                })
            })
            .collect()
    }

    /// Builds the integration request: converts the payload as
    /// `contentHandling` says, then renders the template for the request's
    /// content type, or applies `passthroughBehavior` when there is none.
    pub(crate) fn prepare(&self, ctx: &RequestContext) -> Result<BackendRequest, GatewayError> {
        let declared = ctx.header_str(header::CONTENT_TYPE.as_str());
        let content_type = declared.unwrap_or(DEFAULT_MEDIA_TYPE);
        let payload = if ctx.payload.request_is_binary(&ctx.headers) {
            Payload::Binary
        } else {
            Payload::Text
        };
        let body =
            content::apply(self.content_handling, ctx.body.clone(), payload).map_err(|err| {
                tracing::warn!(%err, "request payload could not be converted");
                GatewayError::ApiConfiguration
            })?;
        let Some(template) = self.template_for(content_type) else {
            return self.passthrough(body, declared);
        };
        let CompiledTemplate::Ready(ref parsed) = template.compiled else {
            tracing::error!(content_type, "request template is invalid");
            return Err(GatewayError::ApiConfiguration);
        };
        let input = GatewayInput::new(String::from_utf8_lossy(&body).into_owned(), ctx);
        let rendered = render(parsed, &input, ctx).map_err(|err| {
            tracing::warn!(%err, content_type, "request template failed");
            GatewayError::ApiConfiguration
        })?;
        Ok(BackendRequest {
            overrides: rendered.request_overrides(),
            body: Bytes::from(rendered.output),
            content_type: HeaderValue::try_from(template.content_type.as_str()).ok(),
        })
    }

    /// The template for a request's content type: the whole header value, then
    /// its media type without parameters.
    fn template_for(&self, content_type: &str) -> Option<&Template> {
        self.templates
            .get(&content_type.trim().to_ascii_lowercase())
            .or_else(|| self.templates.get(&media_type(content_type)))
    }

    fn passthrough(
        &self,
        body: Bytes,
        declared: Option<&str>,
    ) -> Result<BackendRequest, GatewayError> {
        let allowed = match self.passthrough {
            PassthroughBehavior::WhenNoMatch => true,
            PassthroughBehavior::WhenNoTemplates => self.templates.is_empty(),
            PassthroughBehavior::Never => false,
        };
        if !allowed {
            return Err(GatewayError::UnsupportedMediaType);
        }
        Ok(BackendRequest {
            body,
            content_type: declared.and_then(|value| HeaderValue::try_from(value).ok()),
            overrides: RequestOverrides::default(),
        })
    }
}
