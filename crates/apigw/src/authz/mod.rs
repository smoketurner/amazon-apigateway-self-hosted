//! Authorizers: deciding whether a caller may invoke a route.
//!
//! Each authorizer in the API's definition is compiled once into an
//! [`Authorizer`]; a route that uses one holds a [`RouteAuthorizer`]. Anything
//! that cannot be evaluated faithfully compiles to
//! [`RouteAuthorizer::Unevaluable`], and the route then refuses requests.

mod cache;
mod glob;
mod identity_source;
mod lambda;
mod policy;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;

pub(crate) use policy::MethodArn;

use crate::aws::AwsClients;
use crate::gateway_response::Failure;
use crate::integration::StageVariables;
use crate::model::{ApiKind, ApiModel, AuthorizerSpec, Operation, Protection, ResponseType};
use crate::pipeline::RequestContext;
use crate::pipeline::context::AuthorizerContext;

use self::lambda::LambdaAuthorizer;

/// Why a request was turned away, with the response API Gateway gives for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl Denial {
    /// The gateway response that answers the request.
    pub(crate) fn failure(self, kind: ApiKind) -> Failure {
        match (self, kind) {
            (Self::Unauthorized, _) => Failure::new(ResponseType::Unauthorized),
            (Self::ExplicitDeny, ApiKind::Rest) => Failure::new(ResponseType::AccessDenied)
                .with_message(
                    "User is not authorized to access this resource with an explicit deny in an identity-based policy",
                ),
            (Self::ImplicitDeny, ApiKind::Rest) => Failure::new(ResponseType::AccessDenied)
                .with_message("User is not authorized to access this resource"),
            (Self::ExplicitDeny | Self::ImplicitDeny, ApiKind::Http) => {
                Failure::new(ResponseType::AccessDenied).with_message("Forbidden")
            }
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

/// What an authorizer needs to know about the request being authorized.
pub(crate) struct AuthRequest<'a> {
    pub(crate) aws: &'a AwsClients,
    pub(crate) ctx: &'a RequestContext,
}

/// A compiled authorizer definition.
#[derive(Debug)]
pub(crate) enum Authorizer {
    Lambda(LambdaAuthorizer),
}

impl Authorizer {
    /// Compiles an authorizer definition from the export.
    ///
    /// # Errors
    ///
    /// With the reason, when the definition is of a type this gateway does not
    /// evaluate or is not valid.
    pub(crate) fn compile(
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
            "token" | "request" => {
                LambdaAuthorizer::compile(spec, kind, variables).map(Self::Lambda)
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
    ) -> Result<AuthorizerContext, Denial> {
        match *self {
            Self::Lambda(ref authorizer) => authorizer.authorize(request).await,
        }
    }
}

/// How a route is authorized.
#[derive(Debug, Clone)]
pub(crate) enum RouteAuthorizer {
    /// The route has no authorizer.
    None,
    Evaluated(Arc<Authorizer>),
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
            Self::None | Self::Evaluated(_) => None,
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
                    let compiled = Authorizer::compile(spec, model.kind, variables)
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
            Some(Ok(authorizer)) => RouteAuthorizer::Evaluated(Arc::clone(authorizer)),
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
