//! A route compiled from the model: what the router matches and the gateway
//! executes.

use crate::authz::{Authorizers, ResourcePolicies, RouteAuthorizer, RoutePolicy};
use crate::integration::{Integration, StageVariables};
use crate::model::{ApiKind, Feature, MethodMatch, Operation, Protections, RouteKey, RoutePath};
use crate::throttle::{RouteThrottle, ThrottleSettings};
use crate::usage::{ApiKeyRules, RouteApiKey};
use crate::vpc_link::VpcLinks;

#[derive(Debug, Clone)]
pub(crate) struct Route {
    pub(crate) method: MethodMatch,
    pub(crate) path: RoutePath,
    pub(crate) key: RouteKey,
    pub(crate) integration: Integration,
    pub(crate) protections: Protections,
    pub(crate) authorizer: RouteAuthorizer,
    pub(crate) policy: RoutePolicy,
    pub(crate) api_key: RouteApiKey,
    pub(crate) unenforced: Vec<Feature>,
    pub(crate) throttle: Option<RouteThrottle>,
}

/// What decides who may call the routes of one API definition.
pub(crate) struct AccessRules<'a> {
    pub(crate) authorizers: &'a Authorizers,
    pub(crate) policies: &'a ResourcePolicies,
    pub(crate) api_keys: &'a ApiKeyRules,
}

impl Route {
    /// The key of this route's entry in a usage plan's per-method throttles:
    /// `{resource path}/{METHOD}`, with `*` for `ANY`.
    pub(crate) fn plan_throttle_key(&self) -> String {
        let method = match self.method {
            MethodMatch::Any => "*".to_owned(),
            MethodMatch::Exact(ref method) => method.as_str().to_owned(),
        };
        format!("{}/{method}", self.path)
    }

    pub(crate) fn compile(
        operation: &Operation,
        kind: ApiKind,
        variables: &StageVariables,
        access: &AccessRules<'_>,
        throttling: &ThrottleSettings,
        vpc_links: &VpcLinks,
    ) -> Self {
        Self {
            method: operation.method.clone(),
            path: operation.path.clone(),
            key: operation.route_key.clone(),
            integration: Integration::compile(
                operation.integration.as_ref(),
                kind,
                variables,
                vpc_links,
            ),
            protections: operation.protections.clone(),
            authorizer: access.authorizers.for_route(operation),
            policy: access.policies.for_route(operation),
            api_key: access.api_keys.for_route(operation),
            unenforced: operation.unenforced(),
            throttle: throttling.for_route(&operation.method, &operation.path),
        }
    }
}
