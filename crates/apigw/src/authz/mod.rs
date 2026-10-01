//! Authorizers: deciding whether a caller may invoke a route.
//!
//! Each authorizer in the API's definition is compiled once into an
//! [`Authorizer`]; a route that uses one holds a [`RouteAuthorizer`]. Anything
//! that cannot be evaluated faithfully compiles to
//! [`RouteAuthorizer::Unevaluable`], and the route then refuses requests.

mod condition;
mod glob;
mod identity_source;
mod jwt;
mod lambda;
mod pattern;
mod policy;
mod resource_policy;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod usage_tests;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;

pub(crate) use jwt::{IssuerEndpoint, KeyStore};
pub(crate) use policy::MethodArn;
pub(crate) use resource_policy::{ResourcePolicies, RoutePolicy};

use crate::aws::AwsClients;
use crate::digest::Sha256Digest;
use crate::gateway::AuthorizationMode;
use crate::gateway_response::Failure;
use crate::integration::StageVariables;
use crate::model::{ApiKind, ApiModel, AuthorizerSpec, Operation, Protection, ResponseType};
use crate::pipeline::RequestContext;
use crate::pipeline::context::AuthorizerContext;
use crate::route::Route;
use crate::state::StateBackend;

use self::jwt::JwtAuthorizer;
use self::lambda::LambdaAuthorizer;
use self::policy::Decision;
use self::resource_policy::{DeniedBy, Identity, Verdict};

/// Why a request was turned away, with the response API Gateway gives for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Denial {
    /// No credentials, credentials in the wrong shape, or an authorizer that
    /// said so: 401.
    Unauthorized,
    /// The authorizer's policy denies this method explicitly: 403.
    ExplicitDeny,
    /// The authorizer's policy does not allow this method: 403.
    ImplicitDeny,
    /// The authorizer function failed: 500.
    AuthorizerFailure,
    /// The authorizer could not be invoked, or answered in an invalid format,
    /// including a timeout: 500.
    AuthorizerConfiguration,
    /// The method ARN is longer than API Gateway allows: 414.
    UriTooLong,
    /// A valid token that grants none of the scopes the route requires: 403.
    InsufficientScope,
    /// The API's resource policy denies the request: 403. `resource` is the
    /// method ARN as API Gateway shows it, with the account masked.
    ResourcePolicy { resource: String, explicit: bool },
}

impl Denial {
    /// The gateway response that answers the request.
    pub(crate) fn failure(&self, kind: ApiKind) -> Failure {
        match (self, kind) {
            (Self::Unauthorized, _) => Failure::new(ResponseType::Unauthorized),
            (Self::ExplicitDeny, ApiKind::Rest) => Failure::new(ResponseType::AccessDenied)
                .with_message(
                    "User is not authorized to access this resource with an explicit deny in an identity-based policy",
                ),
            (Self::ImplicitDeny | Self::InsufficientScope, ApiKind::Rest) => {
                Failure::new(ResponseType::AccessDenied)
                    .with_message("User is not authorized to access this resource")
            }
            (
                Self::ExplicitDeny
                | Self::ImplicitDeny
                | Self::InsufficientScope
                | Self::ResourcePolicy { .. },
                ApiKind::Http,
            ) => Failure::new(ResponseType::AccessDenied).with_message("Forbidden"),
            (
                Self::ResourcePolicy { resource, explicit },
                ApiKind::Rest,
            ) => Failure::new(ResponseType::AccessDenied).with_message(if *explicit {
                format!(
                    "User: anonymous is not authorized to perform: execute-api:Invoke on resource: {resource} with an explicit deny in a resource-based policy"
                )
            } else {
                format!(
                    "User: anonymous is not authorized to perform: execute-api:Invoke on resource: {resource} because no resource-based policy allows the execute-api:Invoke action"
                )
            }),
            (Self::AuthorizerFailure, ApiKind::Rest) => {
                Failure::new(ResponseType::AuthorizerFailure)
            }
            (Self::AuthorizerConfiguration, ApiKind::Rest) => {
                Failure::new(ResponseType::AuthorizerConfigurationError)
            }
            (Self::AuthorizerFailure, ApiKind::Http) => Failure::new(ResponseType::AuthorizerFailure)
                .with_message("Internal Server Error"),
            (Self::AuthorizerConfiguration, ApiKind::Http) => {
                Failure::new(ResponseType::AuthorizerConfigurationError)
                    .with_message("Internal Server Error")
            }
            (Self::UriTooLong, _) => {
                Failure::gateway(StatusCode::URI_TOO_LONG, "Request URI too long")
            }
        }
    }
}

/// What an authorizer decided, and what it contributes to
/// `$context.authorizer`.
#[derive(Debug)]
pub(crate) struct Authorized {
    pub(crate) context: AuthorizerContext,
    /// Allow, an explicit deny, or (no statement applied) an implicit deny.
    pub(crate) decision: Decision,
    /// The API key a Lambda authorizer named in `usageIdentifierKey`, hashed.
    pub(crate) usage_key: Option<Sha256Digest>,
}

impl Authorized {
    pub(crate) fn allow(context: AuthorizerContext) -> Self {
        Self {
            context,
            decision: Decision::Allow,
            usage_key: None,
        }
    }
}

/// What the authorization of a request leaves for later stages.
#[derive(Debug, Default)]
pub(crate) struct Admitted {
    pub(crate) context: AuthorizerContext,
    pub(crate) usage_key: Option<Sha256Digest>,
}

/// What an authorizer needs to know about the request being authorized.
pub(crate) struct AuthRequest<'a> {
    pub(crate) aws: &'a AwsClients,
    pub(crate) keys: &'a KeyStore,
    pub(crate) state: &'a StateBackend,
    pub(crate) ctx: &'a RequestContext,
}

impl AuthRequest<'_> {
    /// Decides whether the request may proceed, in API Gateway's order: the
    /// resource policy is checked for an explicit deny, then the caller is
    /// authenticated, then the two are combined. Returns what the authorizer
    /// contributes to `$context.authorizer`.
    ///
    /// With `--insecure-skip-authorization` the authorizer is not run and its
    /// answer is taken to be an allow, as if a proxy in front had approved the
    /// caller; the resource policy is evaluated regardless.
    ///
    /// # Errors
    ///
    /// With the [`Denial`] that answers the request.
    pub(crate) async fn authorize(
        &self,
        route: &Route,
        mode: AuthorizationMode,
    ) -> Result<Admitted, Denial> {
        let policy = match route.policy {
            RoutePolicy::Evaluated(ref policy) => Some(policy),
            RoutePolicy::None | RoutePolicy::Unevaluable(_) => None,
        };
        let resource = policy.map(|policy| policy.decide(self.ctx));
        if let Some(policy) = policy
            && resource == Some(Decision::ExplicitDeny)
        {
            return Err(policy.denial(self.ctx, true));
        }
        let (identity, authorized) = match (&route.authorizer, mode) {
            (RouteAuthorizer::None, _) => (None, None),
            (RouteAuthorizer::Unevaluable(_), AuthorizationMode::Enforce) => {
                return Err(Denial::Unauthorized);
            }
            (RouteAuthorizer::Unevaluable(_), AuthorizationMode::Skip) => (
                Some(Identity::Authorizer),
                Some(Authorized::allow(AuthorizerContext::default())),
            ),
            (RouteAuthorizer::Evaluated { authorizer, .. }, AuthorizationMode::Skip) => (
                Some(authorizer.identity()),
                Some(Authorized::allow(AuthorizerContext::default())),
            ),
            (RouteAuthorizer::Evaluated { authorizer, scopes }, AuthorizationMode::Enforce) => (
                Some(authorizer.identity()),
                Some(authorizer.authorize(self, scopes).await?),
            ),
        };
        let identity_decision = authorized.as_ref().map(|a| a.decision);
        let verdict = match (identity, identity_decision, resource) {
            (None, _, None) | (Some(_), Some(Decision::Allow), None) => Verdict::Allow,
            (Some(_), Some(denied), None) => Verdict::Deny {
                explicit: denied == Decision::ExplicitDeny,
                by: DeniedBy::Identity,
            },
            (None, _, Some(resource)) => {
                Verdict::combine(Identity::Anonymous, Decision::Allow, resource)
            }
            (Some(kind), Some(identity), Some(resource)) => {
                Verdict::combine(kind, identity, resource)
            }
            // An authorizer always yields a decision.
            (Some(_), None, _) => return Err(Denial::Unauthorized),
        };
        match verdict {
            Verdict::Allow => Ok(authorized
                .map(|a| Admitted {
                    context: a.context,
                    usage_key: a.usage_key,
                })
                .unwrap_or_default()),
            Verdict::Deny {
                explicit,
                by: DeniedBy::ResourcePolicy,
            } => match policy {
                Some(policy) => Err(policy.denial(self.ctx, explicit)),
                None => Err(Denial::Unauthorized),
            },
            Verdict::Deny {
                explicit,
                by: DeniedBy::Identity,
            } => Err(if explicit {
                Denial::ExplicitDeny
            } else {
                Denial::ImplicitDeny
            }),
        }
    }
}

/// A compiled authorizer definition.
#[derive(Debug)]
pub(crate) enum Authorizer {
    Lambda(Box<LambdaAuthorizer>),
    Jwt(JwtAuthorizer),
}

impl Authorizer {
    /// Compiles an authorizer definition from the export.
    ///
    /// # Errors
    ///
    /// With the reason, when the definition is of a type this gateway does not
    /// evaluate or is not valid.
    pub(crate) fn compile(
        name: &str,
        spec: &AuthorizerSpec,
        kind: ApiKind,
        variables: &StageVariables,
    ) -> Result<Self, String> {
        let authorizer_type = spec
            .config
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        match authorizer_type.to_ascii_lowercase().as_str() {
            "token" | "request" => LambdaAuthorizer::compile(name, spec, kind, variables)
                .map(|a| Self::Lambda(Box::new(a))),
            "jwt" if kind == ApiKind::Http => JwtAuthorizer::compile_http(spec).map(Self::Jwt),
            "cognito_user_pools" if kind == ApiKind::Rest => {
                JwtAuthorizer::compile_cognito(spec, variables).map(Self::Jwt)
            }
            other => Err(format!(
                "{other:?} authorizers are not evaluated by this gateway yet"
            )),
        }
    }

    /// Decides whether the request may proceed and what the authorizer
    /// contributes to `$context.authorizer`.
    ///
    /// # Errors
    ///
    /// With the [`Denial`] that answers the request.
    pub(crate) async fn authorize(
        &self,
        request: &AuthRequest<'_>,
        scopes: &[String],
    ) -> Result<Authorized, Denial> {
        match *self {
            Self::Lambda(ref authorizer) => authorizer.authorize(request).await,
            Self::Jwt(ref authorizer) => authorizer.authorize(request, scopes).await,
        }
    }

    /// How a caller this authorizer accepted counts as authenticated, which
    /// decides how the resource policy combines with it.
    pub(crate) fn identity(&self) -> Identity {
        match *self {
            Self::Lambda(_) => Identity::Authorizer,
            Self::Jwt(_) => Identity::UserPool,
        }
    }
}

/// How a route is authorized.
#[derive(Debug, Clone)]
pub(crate) enum RouteAuthorizer {
    /// The route has no authorizer.
    None,
    /// The authorizer, and the OAuth scopes the route asks of it.
    Evaluated {
        authorizer: Arc<Authorizer>,
        scopes: Vec<String>,
    },
    /// The route needs an authorizer this gateway cannot run, for the reason
    /// given.
    Unevaluable(String),
}

impl RouteAuthorizer {
    /// Whether the route's authorization requirements can be checked here.
    pub(crate) fn is_unevaluable(&self) -> bool {
        matches!(self, Self::Unevaluable(_))
    }

    pub(crate) fn unevaluable_reason(&self) -> Option<&str> {
        match *self {
            Self::Unevaluable(ref reason) => Some(reason),
            Self::None | Self::Evaluated { .. } => None,
        }
    }
}

/// Every authorizer of one API definition, compiled.
#[derive(Debug, Default)]
pub(crate) struct Authorizers(BTreeMap<String, Result<Arc<Authorizer>, String>>);

impl Authorizers {
    pub(crate) fn compile(model: &ApiModel, variables: &StageVariables) -> Self {
        Self(
            model
                .authorizers
                .iter()
                .map(|(name, spec)| {
                    let compiled = Authorizer::compile(name, spec, model.kind, variables)
                        .map(Arc::new)
                        .inspect_err(|reason| {
                            tracing::warn!(
                                authorizer = name,
                                reason,
                                "authorizer cannot be evaluated"
                            );
                        });
                    (name.clone(), compiled)
                })
                .collect(),
        )
    }

    /// The authorizer a route is protected by.
    pub(crate) fn for_route(&self, operation: &Operation) -> RouteAuthorizer {
        if !operation
            .protections
            .iter()
            .any(|protection| protection == Protection::Authorizer)
        {
            return RouteAuthorizer::None;
        }
        let Some(ref reference) = operation.authorizer else {
            return RouteAuthorizer::Unevaluable(
                "the route's security scheme has no authorizer definition".to_owned(),
            );
        };
        match self.0.get(&reference.name) {
            Some(Ok(authorizer)) => RouteAuthorizer::Evaluated {
                authorizer: Arc::clone(authorizer),
                scopes: reference.scopes.clone(),
            },
            Some(Err(reason)) => {
                RouteAuthorizer::Unevaluable(format!("authorizer {:?}: {reason}", reference.name))
            }
            None => RouteAuthorizer::Unevaluable(format!(
                "authorizer {:?} is not defined",
                reference.name
            )),
        }
    }
}
