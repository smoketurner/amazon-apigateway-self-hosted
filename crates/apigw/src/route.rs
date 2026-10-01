//! A route compiled from the model: what the router matches and the gateway
//! executes.

use crate::authz::{Authorizers, ResourcePolicies, RouteAuthorizer, RoutePolicy};
use crate::cache::RouteCache;
use crate::integration::{Integration, StageVariables};
use crate::model::{ApiKind, Feature, MethodMatch, Operation, Protections, RouteKey, RoutePath};
use crate::throttle::{RouteThrottle, ThrottleSettings};
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
    pub(crate) unenforced: Vec<Feature>,
    pub(crate) throttle: Option<RouteThrottle>,
    pub(crate) cache: Option<RouteCache>,
}

impl Route {
    pub(crate) fn compile(
        operation: &Operation,
        kind: ApiKind,
        variables: &StageVariables,
        authorizers: &Authorizers,
        policies: &ResourcePolicies,
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
            authorizer: authorizers.for_route(operation),
            policy: policies.for_route(operation),
            unenforced: operation.unenforced(),
            throttle: throttling.for_route(&operation.method, &operation.path),
            cache: None,
        }
    }
}
