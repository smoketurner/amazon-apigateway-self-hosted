//! Lambda authorizers: REST `TOKEN` and `REQUEST`, and HTTP API `REQUEST` with
//! payload formats 1.0 and 2.0 and simple responses.
//!
//! API Gateway invokes the function with the caller's credentials, caches what
//! it returns by identity source, and evaluates the returned policy against the
//! method being called on every request, cached or not.

use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::cache::TtlCache;
use super::identity_source::{IdentitySource, IdentitySources};
use super::policy::{AccessRequest, Decision, MethodArn, PolicyDocument};
use super::{AuthRequest, Denial};
use crate::aws::{ArnScope, FunctionArn, IntegrationCredentials, RoleArn};
use crate::integration::{LambdaProxy, StageVariables};
use crate::lambda::ProxyEvent;
use crate::model::{ApiKind, AuthorizerSpec, PayloadVersion};
use crate::pipeline::context::AuthorizerContext;

/// How long API Gateway waits for an authorizer function.
const INVOKE_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest an authorizer result may be cached.
const MAX_TTL: Duration = Duration::from_hours(1);
/// What a REST authorizer caches for when no TTL is configured.
const DEFAULT_REST_TTL: Duration = Duration::from_mins(5);
/// Distinct identities whose results are kept per authorizer.
const CACHE_CAPACITY: usize = 10_000;

/// A `TOKEN` authorizer's `identityValidationExpression`. A token that does not
/// match is rejected with 401 before the function is invoked.
///
/// The expression is a Java regular expression matched against the whole
/// token. This is compiled as a Rust regular expression with ASCII classes,
/// which accepts the common subset (anchors, classes, groups, alternation,
/// quantifiers) and rejects anything else, such as look-around, when the
/// definition loads.
// TODO(#22): translate Java syntax with the shared regex translator.
#[derive(Debug)]
struct TokenPattern(regex::bytes::Regex);

impl FromStr for TokenPattern {
    type Err = regex::Error;

    fn from_str(expression: &str) -> Result<Self, Self::Err> {
        regex::bytes::RegexBuilder::new(&format!(r"\A(?:{expression})\z"))
            .unicode(false)
            .build()
            .map(Self)
    }
}

impl TokenPattern {
    fn is_match(&self, token: &str) -> bool {
        self.0.is_match(token.as_bytes())
    }
}

#[derive(Debug)]
enum Flavor {
    RestToken {
        validation: Option<TokenPattern>,
    },
    RestRequest,
    Http {
        payload: PayloadVersion,
        simple_responses: bool,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LambdaConfig {
    authorizer_uri: Option<String>,
    authorizer_credentials: Option<String>,
    identity_source: Option<Value>,
    authorizer_result_ttl_in_seconds: Option<u64>,
    identity_validation_expression: Option<String>,
    authorizer_payload_format_version: Option<PayloadVersion>,
    #[serde(default)]
    enable_simple_responses: bool,
}

/// What a function returned, kept so it can be evaluated again for another
/// method while it is cached.
#[derive(Debug)]
enum AuthorizerResponse {
    Policy {
        principal_id: String,
        policy: PolicyDocument,
        context: Map<String, Value>,
    },
    Simple {
        authorized: bool,
        context: Map<String, Value>,
    },
}

#[derive(Debug)]
pub(crate) struct LambdaAuthorizer {
    flavor: Flavor,
    function: FunctionArn,
    credentials: Option<RoleArn>,
    sources: IdentitySources,
    ttl: Duration,
    scope: ArnScope,
    cache: TtlCache<Vec<String>, AuthorizerResponse>,
}

impl LambdaAuthorizer {
    pub(super) fn compile(
        spec: &AuthorizerSpec,
        kind: ApiKind,
        variables: &StageVariables,
    ) -> Result<Self, String> {
        let config = LambdaConfig::deserialize(&spec.config).map_err(|e| e.to_string())?;
        let is_token = spec
            .config
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| t.eq_ignore_ascii_case("token"));
        let uri = variables.substitute(
            config
                .authorizer_uri
                .as_deref()
                .ok_or("the authorizer has no authorizerUri")?,
        );
        let function: FunctionArn = LambdaProxy::function_arn(&uri)
            .ok_or("authorizerUri is not a Lambda function")?
            .parse()?;
        let scope = function
            .scope()
            .ok_or("the authorizer function must be given as a full ARN")?;
        let credentials = match config
            .authorizer_credentials
            .as_deref()
            .map(str::parse)
            .transpose()?
        {
            None => None,
            Some(IntegrationCredentials::Role(role)) => Some(role),
            Some(IntegrationCredentials::Caller) => {
                return Err("authorizerCredentials cannot pass the caller's credentials".to_owned());
            }
        };
        let flavor = match (kind, is_token) {
            (ApiKind::Rest, true) => Flavor::RestToken {
                validation: config
                    .identity_validation_expression
                    .as_deref()
                    .map(str::parse)
                    .transpose()
                    .map_err(|e: regex::Error| {
                        format!("identityValidationExpression cannot be evaluated: {e}")
                    })?,
            },
            (ApiKind::Rest, false) => Flavor::RestRequest,
            (ApiKind::Http, false) => Flavor::Http {
                payload: config
                    .authorizer_payload_format_version
                    .unwrap_or(PayloadVersion::V1),
                simple_responses: config.enable_simple_responses,
            },
            (ApiKind::Http, true) => {
                return Err("HTTP APIs have no TOKEN authorizers".to_owned());
            }
        };
        let sources = Self::identity_sources(&flavor, spec, config.identity_source.as_ref())?;
        let ttl = match (&flavor, config.authorizer_result_ttl_in_seconds) {
            (_, Some(seconds)) => Duration::from_secs(seconds).min(MAX_TTL),
            (Flavor::RestToken { .. } | Flavor::RestRequest, None) => DEFAULT_REST_TTL,
            (Flavor::Http { .. }, None) => Duration::ZERO,
        };
        Ok(Self {
            flavor,
            function,
            credentials,
            sources,
            ttl,
            scope,
            cache: TtlCache::new(CACHE_CAPACITY),
        })
    }

    /// A `TOKEN` authorizer reads one header: the `identitySource` or, when the
    /// definition has none, the header its security scheme names.
    fn identity_sources(
        flavor: &Flavor,
        spec: &AuthorizerSpec,
        configured: Option<&Value>,
    ) -> Result<IdentitySources, String> {
        let configured = IdentitySources::from_config(configured).map_err(|e| e.to_string())?;
        let Flavor::RestToken { .. } = *flavor else {
            return Ok(configured);
        };
        if configured.is_empty() {
            let header = spec
                .header_name
                .as_deref()
                .ok_or("the TOKEN authorizer names no header")?;
            return format!("method.request.header.{header}")
                .parse::<IdentitySource>()
                .map(IdentitySources::single)
                .map_err(|e| e.to_string());
        }
        if configured.len() == 1 {
            Ok(configured)
        } else {
            Err("a TOKEN authorizer reads exactly one identity source".to_owned())
        }
    }

    pub(super) async fn authorize(
        &self,
        request: &AuthRequest<'_>,
    ) -> Result<AuthorizerContext, Denial> {
        let ctx = request.ctx;
        let identity = self
            .sources
            .extract(ctx, &ctx.stage_variables)
            .ok_or(Denial::Unauthorized)?;
        if let Flavor::RestToken {
            validation: Some(ref pattern),
        } = self.flavor
            && !identity
                .first()
                .is_some_and(|token| pattern.is_match(token))
        {
            return Err(Denial::Unauthorized);
        }
        let arn = MethodArn::new(
            &self.scope,
            &ctx.api.api_id,
            ctx.api.stage_name(),
            &ctx.method,
            &ctx.path,
        );
        if arn.is_too_long() {
            return Err(Denial::UriTooLong);
        }
        let cacheable = !self.ttl.is_zero() && !identity.is_empty();
        if cacheable && let Some(cached) = self.cache.get(&identity) {
            return cached.authorize(&arn);
        }
        let response = self.invoke(request, &identity, &arn).await?;
        let decision = response.authorize(&arn);
        if cacheable {
            self.cache.insert(identity, response, self.ttl);
        }
        decision
    }

    fn event(&self, request: &AuthRequest<'_>, identity: &[String], arn: &MethodArn) -> Value {
        let proxy = ProxyEvent::new(request.ctx, &request.ctx.stage_variables);
        match self.flavor {
            Flavor::RestToken { .. } => json!({
                "type": "TOKEN",
                "authorizationToken": identity.first(),
                "methodArn": arn.as_str(),
            }),
            Flavor::RestRequest => proxy.authorizer_request(PayloadVersion::V1, arn, None),
            Flavor::Http { payload, .. } => proxy.authorizer_request(payload, arn, Some(identity)),
        }
    }

    async fn invoke(
        &self,
        request: &AuthRequest<'_>,
        identity: &[String],
        arn: &MethodArn,
    ) -> Result<AuthorizerResponse, Denial> {
        let event = self.event(request, identity, arn);
        let call = request.aws.invoke_lambda(
            &self.function,
            self.credentials.as_ref(),
            event.to_string().into_bytes(),
            request.ctx.trace_header(),
        );
        let invocation = match tokio::time::timeout(INVOKE_TIMEOUT, call).await {
            Err(_) => {
                tracing::warn!(function = %self.function, "authorizer timed out");
                return Err(Denial::AuthorizerConfiguration);
            }
            Ok(Err(error)) => {
                tracing::error!(function = %self.function, %error, "authorizer invocation failed");
                return Err(Denial::AuthorizerConfiguration);
            }
            Ok(Ok(invocation)) => invocation,
        };
        if invocation.function_error.is_some() {
            return Err(Self::function_error_denial(&invocation.payload));
        }
        AuthorizerResponse::parse(&invocation.payload, &self.flavor).inspect_err(|_| {
            tracing::error!(function = %self.function, "authorizer returned an invalid response");
        })
    }

    /// A function that fails with the message `Unauthorized` answers 401; any
    /// other failure answers 500.
    fn function_error_denial(payload: &[u8]) -> Denial {
        let message = serde_json::from_slice::<Value>(payload)
            .ok()
            .and_then(|error| {
                error
                    .get("errorMessage")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        if message.as_deref() == Some("Unauthorized") {
            Denial::Unauthorized
        } else {
            tracing::warn!("authorizer function raised an error");
            Denial::AuthorizerFailure
        }
    }
}

impl AuthorizerResponse {
    fn parse(payload: &[u8], flavor: &Flavor) -> Result<Self, Denial> {
        let value: Value =
            serde_json::from_slice(payload).map_err(|_| Denial::AuthorizerConfiguration)?;
        let Value::Object(mut fields) = value else {
            return Err(Denial::AuthorizerConfiguration);
        };
        let context = match fields.remove("context") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(context)) => context,
            Some(_) => return Err(Denial::AuthorizerConfiguration),
        };
        let context = match *flavor {
            Flavor::Http { .. } => context,
            Flavor::RestToken { .. } | Flavor::RestRequest => Self::stringified(context)?,
        };
        if let Flavor::Http {
            simple_responses: true,
            ..
        } = *flavor
        {
            let Some(Value::Bool(authorized)) = fields.remove("isAuthorized") else {
                return Err(Denial::AuthorizerConfiguration);
            };
            return Ok(Self::Simple {
                authorized,
                context,
            });
        }
        let Some(Value::String(principal_id)) = fields.remove("principalId") else {
            return Err(Denial::AuthorizerConfiguration);
        };
        let policy = fields
            .get("policyDocument")
            .ok_or(Denial::AuthorizerConfiguration)
            .and_then(|document| {
                PolicyDocument::from_json(document).map_err(|_| Denial::AuthorizerConfiguration)
            })?;
        Ok(Self::Policy {
            principal_id,
            policy,
            context,
        })
    }

    /// REST authorizer context values must be strings, numbers, or booleans,
    /// and reach the backend as strings.
    fn stringified(context: Map<String, Value>) -> Result<Map<String, Value>, Denial> {
        context
            .into_iter()
            .map(|(key, value)| match value {
                Value::String(_) => Ok((key, value)),
                Value::Number(_) | Value::Bool(_) => Ok((key, Value::String(value.to_string()))),
                Value::Null | Value::Array(_) | Value::Object(_) => {
                    Err(Denial::AuthorizerConfiguration)
                }
            })
            .collect()
    }

    /// Evaluates this response for `arn`: what `$context.authorizer` becomes if
    /// the method is allowed.
    fn authorize(&self, arn: &MethodArn) -> Result<AuthorizerContext, Denial> {
        match *self {
            Self::Policy {
                ref principal_id,
                ref policy,
                ref context,
            } => match policy.evaluate(&AccessRequest::invoke(arn)) {
                Decision::Allow => {
                    let mut values = context.clone();
                    values.insert(
                        "principalId".to_owned(),
                        Value::String(principal_id.clone()),
                    );
                    Ok(AuthorizerContext::lambda(values))
                }
                Decision::ExplicitDeny => Err(Denial::ExplicitDeny),
                Decision::ImplicitDeny => Err(Denial::ImplicitDeny),
            },
            Self::Simple {
                authorized,
                ref context,
            } => {
                if authorized {
                    Ok(AuthorizerContext::lambda(context.clone()))
                } else {
                    Err(Denial::ExplicitDeny)
                }
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests;
