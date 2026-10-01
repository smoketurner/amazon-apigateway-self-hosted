//! API resource policies, and how their verdict combines with the caller's
//! authentication.
//!
//! API Gateway evaluates a resource policy in two phases (see
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-authorization-flow.html>):
//! before authentication it looks only for an explicit `Deny`, which ends the
//! request; after authentication it combines the policy with what the
//! authenticator decided, per the flow's outcome tables:
//!
//! | caller | rule |
//! |---|---|
//! | no authentication | the policy must explicitly allow (Table A with nothing else) |
//! | Lambda authorizer | Table A: an `Allow` from either is enough, a `Deny` from either wins |
//! | Cognito user pool | Table B: both must allow, a `Deny` from either wins |
//!
//! Callers here are never IAM-authenticated (a `SigV4` signature cannot be
//! verified without the caller's secret), so every statement is evaluated for an
//! anonymous caller: only principals naming everyone (`"*"`) apply.

use std::sync::Arc;

use serde_json::Value;

use super::Denial;
use super::condition::RequestAttributes;
use super::policy::{AccessRequest, Decision, MethodArn, PolicyDocument, PolicyError};
use crate::aws::ArnScope;
use crate::model::{ApiModel, Operation, Protection};
use crate::pipeline::RequestContext;

/// Where a verdict's denial came from, which decides the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeniedBy {
    Identity,
    ResourcePolicy,
}

/// The final decision for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Allow,
    Deny { explicit: bool, by: DeniedBy },
}

/// How the caller was authenticated, which picks the outcome table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Identity {
    /// Not authenticated: the resource policy decides alone.
    Anonymous,
    /// A Lambda authorizer, or trust in the front proxy standing in for one:
    /// Table A.
    Authorizer,
    /// A Cognito user pool: Table B.
    UserPool,
}

impl Verdict {
    const fn deny(explicit: bool, by: DeniedBy) -> Self {
        Self::Deny { explicit, by }
    }

    /// The outcome of the authenticator's decision (`identity`) and the
    /// resource policy's (`resource`), where "neither allow nor deny" is
    /// [`Decision::ImplicitDeny`].
    pub(crate) fn combine(kind: Identity, identity: Decision, resource: Decision) -> Self {
        match kind {
            Identity::Anonymous => match resource {
                Decision::Allow => Self::Allow,
                Decision::ExplicitDeny => Self::deny(true, DeniedBy::ResourcePolicy),
                Decision::ImplicitDeny => Self::deny(false, DeniedBy::ResourcePolicy),
            },
            Identity::Authorizer => Self::table_a(identity, resource),
            Identity::UserPool => Self::table_b(identity, resource),
        }
    }

    /// Both in the same account: an `Allow` from either suffices.
    fn table_a(identity: Decision, resource: Decision) -> Self {
        match (identity, resource) {
            (Decision::Allow, Decision::Allow | Decision::ImplicitDeny)
            | (Decision::ImplicitDeny, Decision::Allow) => Self::Allow,
            (Decision::ImplicitDeny, Decision::ImplicitDeny) => {
                Self::deny(false, DeniedBy::ResourcePolicy)
            }
            (_, Decision::ExplicitDeny) => Self::deny(true, DeniedBy::ResourcePolicy),
            (Decision::ExplicitDeny, Decision::Allow | Decision::ImplicitDeny) => {
                Self::deny(true, DeniedBy::Identity)
            }
        }
    }

    /// Different accounts: both must allow.
    fn table_b(identity: Decision, resource: Decision) -> Self {
        match (identity, resource) {
            (Decision::Allow, Decision::Allow) => Self::Allow,
            (Decision::Allow | Decision::ImplicitDeny, Decision::ImplicitDeny)
            | (Decision::ImplicitDeny, Decision::Allow) => {
                Self::deny(false, DeniedBy::ResourcePolicy)
            }
            (_, Decision::ExplicitDeny) => Self::deny(true, DeniedBy::ResourcePolicy),
            (Decision::ExplicitDeny, Decision::Allow | Decision::ImplicitDeny) => {
                Self::deny(true, DeniedBy::Identity)
            }
        }
    }
}

/// An API's resource policy, ready to evaluate.
#[derive(Debug)]
pub(crate) struct ResourcePolicy {
    document: PolicyDocument,
    scope: ArnScope,
}

impl ResourcePolicy {
    /// Where the API is, as far as its policy says: the partition, region, and
    /// account of the first `execute-api` ARN in it that names them.
    fn scope_in(value: &Value) -> Option<ArnScope> {
        match value {
            Value::String(text) => {
                let mut parts = text.split(':');
                let (
                    Some("arn"),
                    Some(partition),
                    Some("execute-api"),
                    Some(region),
                    Some(account),
                ) = (
                    parts.next(),
                    parts.next(),
                    parts.next(),
                    parts.next(),
                    parts.next(),
                )
                else {
                    return None;
                };
                let concrete = |part: &str| !part.is_empty() && !part.contains(['*', '?']);
                (concrete(partition) && concrete(region) && concrete(account)).then(|| ArnScope {
                    partition: partition.to_owned(),
                    region: region.to_owned(),
                    account: account.to_owned(),
                })
            }
            Value::Array(items) => items.iter().find_map(Self::scope_in),
            Value::Object(fields) => fields.values().find_map(Self::scope_in),
            Value::Null | Value::Bool(_) | Value::Number(_) => None,
        }
    }

    /// Rewrites the resources of the policy to name this API.
    fn expand_shorthand(value: &mut Value, api_id: &str) {
        match value {
            Value::Object(fields) => {
                for (name, field) in fields {
                    if matches!(name.as_str(), "Resource" | "NotResource") {
                        Self::expand_resources(field, api_id);
                    } else {
                        Self::expand_shorthand(field, api_id);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    Self::expand_shorthand(item, api_id);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    /// A policy resource written for this API, as a pattern naming `api_id`:
    /// the shorthand `execute-api:/stage/METHOD/path`, or an `execute-api` ARN
    /// with a concrete API id. The policy is the API's own, so every API id it
    /// names concretely is this API, whatever id the gateway was given (a file
    /// source has none of AWS's).
    fn for_this_api(resource: &str, api_id: &str) -> Option<String> {
        if let Some(rest) = resource.strip_prefix("execute-api:/") {
            return Some(format!("arn:*:execute-api:*:*:{api_id}/{rest}"));
        }
        let mut parts = resource.splitn(6, ':');
        let (
            Some("arn"),
            Some(partition),
            Some("execute-api"),
            Some(region),
            Some(account),
            Some(rest),
        ) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        )
        else {
            return None;
        };
        let (named, tail) = rest.split_once('/').unwrap_or((rest, ""));
        if named.is_empty() || named.contains(['*', '?']) {
            return None;
        }
        Some(format!(
            "arn:{partition}:execute-api:{region}:{account}:{api_id}/{tail}"
        ))
    }

    fn expand_resources(value: &mut Value, api_id: &str) {
        match value {
            Value::String(text) => {
                if let Some(rewritten) = Self::for_this_api(text, api_id) {
                    *text = rewritten;
                }
            }
            Value::Array(items) => {
                for item in items {
                    Self::expand_resources(item, api_id);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => {}
        }
    }

    /// Compiles the policy document of the API `api_id`. `fallback` says where
    /// the API is when the policy does not.
    ///
    /// # Errors
    ///
    /// When the document is not a valid policy.
    pub(crate) fn compile(
        document: &Value,
        api_id: &str,
        fallback: ArnScope,
    ) -> Result<Self, PolicyError> {
        let scope = Self::scope_in(document).unwrap_or(fallback);
        let mut expanded = document.clone();
        Self::expand_shorthand(&mut expanded, api_id);
        Ok(Self {
            document: PolicyDocument::from_json(&expanded)?,
            scope,
        })
    }

    fn arn(&self, ctx: &RequestContext) -> MethodArn {
        MethodArn::new(
            &self.scope,
            &ctx.api.api_id,
            ctx.api.stage_name(),
            &ctx.method,
            &ctx.path,
        )
    }

    /// What the policy says about this request: allowed, explicitly denied, or
    /// neither.
    pub(crate) fn decide(&self, ctx: &RequestContext) -> Decision {
        let arn = self.arn(ctx);
        let attributes = RequestAttributes::of(ctx);
        self.document
            .evaluate(&AccessRequest::anonymous(&arn, &attributes))
    }

    /// The denial that answers `ctx` when this policy is to blame.
    pub(crate) fn denial(&self, ctx: &RequestContext, explicit: bool) -> Denial {
        Denial::ResourcePolicy {
            resource: self.arn(ctx).masked(),
            explicit,
        }
    }
}

/// How a route relates to the API's resource policy.
#[derive(Debug, Clone)]
pub(crate) enum RoutePolicy {
    /// The API has no resource policy.
    None,
    Evaluated(Arc<ResourcePolicy>),
    /// The API has a policy this gateway could not read, for the reason given.
    Unevaluable(String),
}

impl RoutePolicy {
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

/// The compiled resource policy of one API definition.
#[derive(Debug)]
pub(crate) struct ResourcePolicies {
    compiled: Result<Option<Arc<ResourcePolicy>>, String>,
}

impl ResourcePolicies {
    /// Where an API with no ARNs in its policy is taken to be, for messages.
    const FALLBACK_PARTITION: &'static str = "aws";
    const FALLBACK_REGION: &'static str = "us-east-1";
    const FALLBACK_ACCOUNT: &'static str = "000000000000";

    pub(crate) fn compile(model: &ApiModel, api_id: &str) -> Self {
        let compiled = match model.settings.resource_policy {
            None => Ok(None),
            Some(ref document) => {
                let fallback = ArnScope {
                    partition: Self::FALLBACK_PARTITION.to_owned(),
                    region: Self::FALLBACK_REGION.to_owned(),
                    account: Self::FALLBACK_ACCOUNT.to_owned(),
                };
                ResourcePolicy::compile(document, api_id, fallback)
                    .map(|policy| Some(Arc::new(policy)))
                    .map_err(|error| error.to_string())
            }
        };
        if let Err(ref reason) = compiled {
            tracing::warn!(reason, "the resource policy cannot be evaluated");
        }
        Self { compiled }
    }

    /// How `operation` is covered by the policy.
    pub(crate) fn for_route(&self, operation: &Operation) -> RoutePolicy {
        if !operation.protections.contains(Protection::ResourcePolicy) {
            return RoutePolicy::None;
        }
        match self.compiled {
            Ok(Some(ref policy)) => RoutePolicy::Evaluated(Arc::clone(policy)),
            Ok(None) => RoutePolicy::Unevaluable("the policy could not be read".to_owned()),
            Err(ref reason) => RoutePolicy::Unevaluable(reason.clone()),
        }
    }
}

#[cfg(test)]
mod tests;
