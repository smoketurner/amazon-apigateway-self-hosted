//! Request validators: the required parameters and JSON Schema (draft 4) body
//! models a REST API's validators check before the integration runs. See
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html>.
//!
//! A route whose models cannot be compiled is [`RouteValidation::Unevaluable`]
//! and answers `501`: serving it unvalidated would let requests past a check
//! its owner configured. Model `$ref`s resolve only against the API's own
//! models (`#/components/schemas/...`); nothing is ever fetched.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Bytes;
use jsonschema::Validator;
use serde_json::{Value, json};

use crate::gateway_response::Failure;
use crate::model::{ApiModel, Operation, ParameterLocation, ParameterSpec, ResponseType};
use crate::pipeline::RequestContext;

/// How many schema violations a `$context.error.validationErrorString` lists.
const MAX_REPORTED_ERRORS: usize = 10;
/// The longest `validationErrorString`, so a violation that quotes a large
/// value of the request cannot make the response large.
const MAX_ERROR_CHARS: usize = 1024;
/// Bodies larger than this are parsed and checked off the async threads.
const INLINE_BODY_BYTES: usize = 64 * 1024;
/// The content type assumed for a request that names none.
const DEFAULT_CONTENT_TYPE: &str = "application/json";
/// The model API Gateway applies to content types without a model of their own.
const DEFAULT_MODEL: &str = "$default";

/// Compiles the validators of one API definition.
#[derive(Debug, Clone)]
pub(crate) struct RequestValidators {
    models: BTreeMap<String, Value>,
}

impl RequestValidators {
    pub(crate) fn compile(model: &ApiModel) -> Self {
        Self {
            models: model.models.clone(),
        }
    }

    pub(crate) fn for_route(&self, operation: &Operation) -> RouteValidation {
        let Some(spec) = operation.validator.filter(|spec| spec.validates()) else {
            return RouteValidation::None;
        };
        let required = if spec.validate_request_parameters {
            RequiredParameter::of(&operation.parameters)
        } else {
            Vec::new()
        };
        let mut models = BTreeMap::new();
        if spec.validate_request_body
            && let Some(ref body) = operation.request_body
        {
            for (content_type, schema) in &body.schemas {
                match self.body_model(schema) {
                    Ok(validator) => {
                        models.insert(content_type.to_ascii_lowercase(), Arc::new(validator));
                    }
                    Err(reason) => {
                        return RouteValidation::Unevaluable(format!(
                            "the request model for {content_type} cannot be compiled: {reason}"
                        ));
                    }
                }
            }
        }
        if required.is_empty() && models.is_empty() {
            return RouteValidation::None;
        }
        RouteValidation::Checks(Arc::new(RequestChecks { required, models }))
    }

    /// A draft 4 validator for `schema`, with the API's models reachable at
    /// `#/components/schemas/{name}` so `$ref`s into them resolve.
    fn body_model(&self, schema: &Value) -> Result<Validator, String> {
        let Value::Object(fields) = schema else {
            return Err("a model must be a JSON object".to_owned());
        };
        let mut root = fields.clone();
        root.insert("components".to_owned(), json!({"schemas": self.models}));
        jsonschema::draft4::options()
            .should_validate_formats(false)
            .build(&Value::Object(root))
            .map_err(|error| error.to_string())
    }
}

/// What one route's validator checks.
#[derive(Debug, Clone)]
pub(crate) enum RouteValidation {
    None,
    Checks(Arc<RequestChecks>),
    /// The route has a validator that cannot be run; the reason is reported.
    Unevaluable(String),
}

impl RouteValidation {
    pub(crate) fn is_unevaluable(&self) -> bool {
        matches!(*self, Self::Unevaluable(_))
    }

    pub(crate) fn unevaluable_reason(&self) -> Option<&str> {
        match *self {
            Self::Unevaluable(ref reason) => Some(reason),
            Self::None | Self::Checks(_) => None,
        }
    }

    /// The failure for a request that does not pass, parameters first.
    pub(crate) async fn check(&self, ctx: &RequestContext) -> Result<(), Failure> {
        let Self::Checks(checks) = self else {
            return Ok(());
        };
        checks.check_parameters(ctx)?;
        checks.check_body(ctx).await
    }
}

/// A parameter a request must carry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RequiredParameter {
    name: String,
    location: ParameterLocation,
}

impl RequiredParameter {
    /// The required query string and header parameters. Path parameters are
    /// always present on a matched route, and API Gateway has no cookie
    /// parameters.
    fn of(parameters: &[ParameterSpec]) -> Vec<Self> {
        parameters
            .iter()
            .filter(|parameter| {
                parameter.required
                    && matches!(
                        parameter.location,
                        ParameterLocation::Query | ParameterLocation::Header
                    )
            })
            .map(|parameter| Self {
                name: parameter.name.clone(),
                location: parameter.location,
            })
            .collect()
    }

    /// Whether the request carries the parameter with a value that is not blank.
    fn is_present(&self, ctx: &RequestContext) -> bool {
        match self.location {
            ParameterLocation::Query => ctx
                .query
                .pairs()
                .iter()
                .any(|(name, value)| *name == self.name && !value.trim().is_empty()),
            ParameterLocation::Header => ctx
                .headers
                .get_all(self.name.as_str())
                .iter()
                .any(|value| !value.as_bytes().trim_ascii().is_empty()),
            ParameterLocation::Path | ParameterLocation::Cookie => true,
        }
    }
}

/// The checks of one route.
#[derive(Debug)]
pub(crate) struct RequestChecks {
    required: Vec<RequiredParameter>,
    /// Body models by lowercase media type, or [`DEFAULT_MODEL`].
    models: BTreeMap<String, Arc<Validator>>,
}

impl RequestChecks {
    fn check_parameters(&self, ctx: &RequestContext) -> Result<(), Failure> {
        let missing: Vec<&str> = self
            .required
            .iter()
            .filter(|parameter| !parameter.is_present(ctx))
            .map(|parameter| parameter.name.as_str())
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        Err(
            Failure::new(ResponseType::BadRequestParameters).with_message(format!(
                "Missing required request parameters: [{}]",
                missing.join(", ")
            )),
        )
    }

    /// The model for the request's content type: its own, else `$default`.
    /// A content type with neither is not validated.
    fn model_for(&self, ctx: &RequestContext) -> Option<&Arc<Validator>> {
        let content_type = ctx
            .header_str("content-type")
            .and_then(|value| value.split(';').next())
            .map(|media_type| media_type.trim().to_ascii_lowercase())
            .filter(|media_type| !media_type.is_empty())
            .unwrap_or_else(|| DEFAULT_CONTENT_TYPE.to_owned());
        self.models
            .get(&content_type)
            .or_else(|| self.models.get(DEFAULT_MODEL))
    }

    async fn check_body(&self, ctx: &RequestContext) -> Result<(), Failure> {
        let Some(model) = self.model_for(ctx) else {
            return Ok(());
        };
        let outcome = if ctx.body.len() > INLINE_BODY_BYTES {
            let (model, body) = (Arc::clone(model), ctx.body.clone());
            match tokio::task::spawn_blocking(move || BodyModel(&model).check(&body)).await {
                Ok(outcome) => outcome,
                Err(error) => {
                    tracing::error!(%error, "request body validation did not finish");
                    Err("the request could not be validated".to_owned())
                }
            }
        } else {
            BodyModel(model).check(&ctx.body)
        };
        outcome.map_err(|violations| {
            Failure::new(ResponseType::BadRequestBody).with_validation_error(violations)
        })
    }
}

/// A compiled body model applied to a request body.
struct BodyModel<'a>(&'a Validator);

impl BodyModel<'_> {
    /// `Err` carries the `validationErrorString`.
    fn check(&self, body: &Bytes) -> Result<(), String> {
        let instance: Value = serde_json::from_slice(body)
            .map_err(|error| Self::bracketed(std::iter::once(error.to_string())))?;
        let violations: Vec<String> = self
            .0
            .iter_errors(&instance)
            .take(MAX_REPORTED_ERRORS)
            .map(|violation| violation.to_string())
            .collect();
        if violations.is_empty() {
            Ok(())
        } else {
            Err(Self::bracketed(violations))
        }
    }

    fn bracketed(violations: impl IntoIterator<Item = String>) -> String {
        let joined = violations.into_iter().collect::<Vec<_>>().join(", ");
        let mut text: String = format!("[{joined}]")
            .chars()
            .take(MAX_ERROR_CHARS)
            .collect();
        if !text.ends_with(']') {
            text.push_str("...]");
        }
        text
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests;
