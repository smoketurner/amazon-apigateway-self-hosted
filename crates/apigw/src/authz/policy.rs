//! IAM policy documents as API Gateway evaluates them: the policy a Lambda
//! authorizer returns, and (later) an API's resource policy.
//!
//! Evaluation is deny-overrides: an applicable `Deny` wins, otherwise an
//! applicable `Allow` grants access, otherwise access is implicitly denied. A
//! statement this gateway cannot evaluate (for example one with a condition)
//! applies when it is a `Deny` and does not apply when it is an `Allow`, so
//! doubt never grants access.

use std::fmt;

use axum::http::Method;
use serde::Deserialize;
use serde_json::Value;

use super::glob::{CaseSensitivity, Glob};
use crate::aws::ArnScope;

/// The only action API Gateway checks.
pub(crate) const INVOKE_ACTION: &str = "execute-api:Invoke";

/// API Gateway's limit on a method ARN, beyond which it answers 414.
const MAX_METHOD_ARN_BYTES: usize = 1600;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PolicyError {
    #[error("not a valid IAM policy document: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("a statement needs Action or NotAction")]
    MissingAction,
    #[error("a statement needs Resource or NotResource")]
    MissingResource,
}

/// `arn:aws:execute-api:{region}:{account}:{apiId}/{stage}/{METHOD}/{path}`,
/// the resource a request is authorized against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MethodArn(String);

impl MethodArn {
    pub(crate) fn new(
        scope: &ArnScope,
        api_id: &str,
        stage: &str,
        method: &Method,
        path: &str,
    ) -> Self {
        let ArnScope {
            ref partition,
            ref region,
            ref account,
        } = *scope;
        let path = path.strip_prefix('/').unwrap_or(path);
        Self(format!(
            "arn:{partition}:execute-api:{region}:{account}:{api_id}/{stage}/{method}/{path}"
        ))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// API Gateway answers 414 for a method ARN longer than 1600 bytes, which
    /// path parameter values can cause.
    pub(crate) fn is_too_long(&self) -> bool {
        self.0.len() > MAX_METHOD_ARN_BYTES
    }
}

impl fmt::Display for MethodArn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a policy is asked about.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AccessRequest<'a> {
    pub(crate) action: &'a str,
    pub(crate) resource: &'a str,
}

impl<'a> AccessRequest<'a> {
    pub(crate) fn invoke(resource: &'a MethodArn) -> Self {
        Self {
            action: INVOKE_ACTION,
            resource: resource.as_str(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) enum Effect {
    Allow,
    Deny,
}

/// The outcome of evaluating a policy document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    Allow,
    ExplicitDeny,
    /// No statement applied.
    ImplicitDeny,
}

/// How a statement relates to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Applicability {
    Applies,
    DoesNotApply,
    /// The statement cannot be evaluated here.
    Unknown,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(one) => vec![one],
            Self::Many(many) => many,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawStatement {
    effect: Effect,
    action: Option<OneOrMany<String>>,
    not_action: Option<OneOrMany<String>>,
    resource: Option<OneOrMany<String>>,
    not_resource: Option<OneOrMany<String>>,
    condition: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawDocument {
    statement: OneOrMany<RawStatement>,
}

/// An `Action` or `Resource` element: the patterns, and whether they select
/// what they list or everything else.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Selector {
    globs: Vec<Glob>,
    negated: bool,
}

impl Selector {
    fn new(
        listed: Option<OneOrMany<String>>,
        negated: Option<OneOrMany<String>>,
        case: CaseSensitivity,
    ) -> Option<Self> {
        let (values, negated) = match (listed, negated) {
            (Some(values), None) => (values, false),
            (None, Some(values)) => (values, true),
            (Some(_), Some(_)) | (None, None) => return None,
        };
        Some(Self {
            globs: values
                .into_vec()
                .iter()
                .map(|v| Glob::new(v, case))
                .collect(),
            negated,
        })
    }

    fn applicability(&self, value: &str) -> Applicability {
        if self.globs.iter().any(Glob::has_variable) {
            return Applicability::Unknown;
        }
        let listed = self.globs.iter().any(|glob| glob.matches(value));
        if listed == self.negated {
            Applicability::DoesNotApply
        } else {
            Applicability::Applies
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Statement {
    effect: Effect,
    actions: Selector,
    resources: Selector,
    has_condition: bool,
}

impl Statement {
    fn applicability(&self, request: &AccessRequest<'_>) -> Applicability {
        let selected = [
            self.actions.applicability(request.action),
            self.resources.applicability(request.resource),
        ];
        if selected.contains(&Applicability::DoesNotApply) {
            Applicability::DoesNotApply
        } else if selected.contains(&Applicability::Unknown) || self.has_condition {
            Applicability::Unknown
        } else {
            Applicability::Applies
        }
    }

    /// Whether this statement takes effect: unknowns count for a `Deny` and
    /// not for an `Allow`.
    fn takes_effect(&self, request: &AccessRequest<'_>) -> bool {
        match self.applicability(request) {
            Applicability::Applies => true,
            Applicability::DoesNotApply => false,
            Applicability::Unknown => self.effect == Effect::Deny,
        }
    }
}

impl TryFrom<RawStatement> for Statement {
    type Error = PolicyError;

    fn try_from(raw: RawStatement) -> Result<Self, Self::Error> {
        Ok(Self {
            effect: raw.effect,
            actions: Selector::new(raw.action, raw.not_action, CaseSensitivity::Insensitive)
                .ok_or(PolicyError::MissingAction)?,
            resources: Selector::new(raw.resource, raw.not_resource, CaseSensitivity::Sensitive)
                .ok_or(PolicyError::MissingResource)?,
            has_condition: raw
                .condition
                .as_ref()
                .is_some_and(|c| !matches!(c, Value::Object(o) if o.is_empty())),
        })
    }
}

/// An IAM policy document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyDocument {
    statements: Vec<Statement>,
}

impl PolicyDocument {
    /// Reads a policy document from JSON.
    ///
    /// # Errors
    ///
    /// When the value is not a policy document, or a statement lacks an action
    /// or a resource element.
    pub(crate) fn from_json(value: &Value) -> Result<Self, PolicyError> {
        let raw = RawDocument::deserialize(value)?;
        let statements = raw
            .statement
            .into_vec()
            .into_iter()
            .map(Statement::try_from)
            .collect::<Result<_, _>>()?;
        Ok(Self { statements })
    }

    pub(crate) fn evaluate(&self, request: &AccessRequest<'_>) -> Decision {
        let mut allowed = false;
        for statement in &self.statements {
            if !statement.takes_effect(request) {
                continue;
            }
            match statement.effect {
                Effect::Deny => return Decision::ExplicitDeny,
                Effect::Allow => allowed = true,
            }
        }
        if allowed {
            Decision::Allow
        } else {
            Decision::ImplicitDeny
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use serde_json::json;

    use super::*;

    fn scope() -> ArnScope {
        "arn:aws:lambda:us-east-1:123456789012:function:auth"
            .parse::<crate::aws::FunctionArn>()
            .unwrap()
            .scope()
            .unwrap()
    }

    fn arn(method: &Method, path: &str) -> MethodArn {
        MethodArn::new(&scope(), "abc", "prod", method, path)
    }

    fn decide(policy: &Value, arn: &MethodArn) -> Decision {
        PolicyDocument::from_json(policy)
            .unwrap()
            .evaluate(&AccessRequest::invoke(arn))
    }

    fn statement(effect: &str, resource: &str) -> Value {
        json!({"Version": "2012-10-17", "Statement": [
            {"Effect": effect, "Action": "execute-api:Invoke", "Resource": resource}
        ]})
    }

    #[test]
    fn method_arns_follow_api_gateways_format() {
        let arn = arn(&Method::GET, "/pets/7");
        assert_eq!(
            arn.as_str(),
            "arn:aws:execute-api:us-east-1:123456789012:abc/prod/GET/pets/7"
        );
        assert_eq!(
            self::arn(&Method::POST, "/").as_str(),
            "arn:aws:execute-api:us-east-1:123456789012:abc/prod/POST/"
        );
    }

    #[test]
    fn overlong_method_arns_are_detected() {
        assert!(!arn(&Method::GET, "/x").is_too_long());
        assert!(arn(&Method::GET, &"x".repeat(1600)).is_too_long());
    }

    #[test]
    fn allow_for_the_exact_arn_or_a_wildcard() {
        let target = arn(&Method::GET, "/pets/7");
        assert_eq!(decide(&statement("Allow", &target.to_string()), &target), Decision::Allow);
        assert_eq!(
            decide(&statement("Allow", "arn:aws:execute-api:*:*:abc/*/*/*"), &target),
            Decision::Allow
        );
        assert_eq!(decide(&statement("Allow", "*"), &target), Decision::Allow);
    }

    #[test]
    fn a_cached_policy_is_checked_against_each_method_arn() {
        let policy = statement("Allow", "arn:aws:execute-api:*:*:abc/prod/GET/pets/7");
        assert_eq!(decide(&policy, &arn(&Method::GET, "/pets/7")), Decision::Allow);
        assert_eq!(
            decide(&policy, &arn(&Method::GET, "/pets/8")),
            Decision::ImplicitDeny
        );
        assert_eq!(
            decide(&policy, &arn(&Method::DELETE, "/pets/7")),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn an_applicable_deny_overrides_an_allow() {
        let target = arn(&Method::DELETE, "/pets/7");
        let policy = json!({"Statement": [
            {"Effect": "Allow", "Action": "execute-api:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "execute-api:Invoke", "Resource": "arn:*:*:*:*:*/*/DELETE/*"},
        ]});
        assert_eq!(decide(&policy, &target), Decision::ExplicitDeny);
        assert_eq!(decide(&policy, &arn(&Method::GET, "/pets/7")), Decision::Allow);
    }

    #[test]
    fn no_statement_means_implicit_deny() {
        let target = arn(&Method::GET, "/");
        assert_eq!(decide(&json!({"Statement": []}), &target), Decision::ImplicitDeny);
        assert_eq!(
            decide(&statement("Allow", "arn:aws:execute-api:*:*:other/*"), &target),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn other_actions_do_not_grant_invoke() {
        let target = arn(&Method::GET, "/");
        let policy = json!({"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}});
        assert_eq!(decide(&policy, &target), Decision::ImplicitDeny);
        let policy = json!({"Statement": {"Effect": "Allow", "Action": "EXECUTE-API:invoke", "Resource": "*"}});
        assert_eq!(decide(&policy, &target), Decision::Allow);
    }

    #[test]
    fn not_resource_and_not_action_invert_the_selection() {
        let target = arn(&Method::GET, "/pets");
        let policy = json!({"Statement": {"Effect": "Allow", "Action": "execute-api:Invoke",
            "NotResource": "arn:*:*:*:*:*/*/*/admin/*"}});
        assert_eq!(decide(&policy, &target), Decision::Allow);
        assert_eq!(decide(&policy, &arn(&Method::GET, "/admin/x")), Decision::ImplicitDeny);
        let policy = json!({"Statement": {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}});
        assert_eq!(decide(&policy, &target), Decision::Allow);
    }

    #[test]
    fn unevaluable_statements_deny_but_never_allow() {
        let target = arn(&Method::GET, "/");
        let conditional = |effect: &str| {
            json!({"Statement": {"Effect": effect, "Action": "execute-api:Invoke", "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}}}})
        };
        assert_eq!(decide(&conditional("Allow"), &target), Decision::ImplicitDeny);
        assert_eq!(decide(&conditional("Deny"), &target), Decision::ExplicitDeny);
        let variable = |effect: &str| statement(effect, "arn:*:*:*:*:*/${aws:username}/*");
        assert_eq!(decide(&variable("Allow"), &target), Decision::ImplicitDeny);
        assert_eq!(decide(&variable("Deny"), &target), Decision::ExplicitDeny);
    }

    #[test]
    fn an_empty_condition_block_is_no_condition() {
        let target = arn(&Method::GET, "/");
        let policy = json!({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {}}});
        assert_eq!(decide(&policy, &target), Decision::Allow);
    }

    #[test]
    fn malformed_documents_are_errors() {
        for bad in [
            json!("a string"),
            json!({}),
            json!({"Statement": [{"Effect": "Maybe", "Action": "*", "Resource": "*"}]}),
            json!({"Statement": [{"Effect": "Allow", "Resource": "*"}]}),
            json!({"Statement": [{"Effect": "Allow", "Action": "*"}]}),
            json!({"Statement": [{"Effect": "Allow", "Action": "*", "NotAction": "*", "Resource": "*"}]}),
            json!({"Statement": [{"Effect": "Allow", "Action": 7, "Resource": "*"}]}),
        ] {
            assert!(PolicyDocument::from_json(&bad).is_err(), "{bad}");
        }
    }
}
