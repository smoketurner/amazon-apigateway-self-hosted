//! Token authorizers: HTTP API JWT authorizers, REST API JWT authorizers, and
//! REST API Cognito user pool authorizers.
//!
//! Each verifies a bearer token's signature against the issuer's published
//! keys, checks its claims, and exposes the claims as `$context.authorizer`.
//! See <https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html>,
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-jwt-authorizer.html>,
//! and <https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-enable-cognito-user-pool.html>.

mod claims;
mod keys;
mod rest;
mod token;

#[cfg(test)]
mod tests;

use serde::Deserialize;
use serde_json::{Value, json};

pub(crate) use keys::{IssuerEndpoint, KeyStore};

use self::claims::ClaimStyle;
use self::keys::{Issuer, KEY_TTL, KeyLocation};
use self::rest::{CLOCK_SKEW_SECONDS, RestJwt};
use self::token::{Claims, IssuerConfig, SigningAlgorithm, TokenError, Verifier};
use super::identity_source::IdentitySources;
use super::pattern::TokenPattern;
use super::{AuthRequest, Authorized, Denial};
use crate::integration::StageVariables;
use crate::model::AuthorizerSpec;
use crate::pipeline::context::AuthorizerContext;

/// What the identity source holds when the definition names none.
const DEFAULT_IDENTITY_SOURCE: &str = "$request.header.Authorization";

#[derive(Debug)]
enum Flavor {
    /// An HTTP API JWT authorizer: the token must be for one of these audiences.
    Http { audiences: Vec<String> },
    /// A REST API Cognito user pool authorizer, with its optional validation
    /// expression for the `aud` claim.
    Cognito { audience: Option<TokenPattern> },
    /// A REST API JWT authorizer, with each issuer's audiences and claim rules.
    Rest(RestJwt),
}

impl Flavor {
    /// How far apart the issuer's clock and this one may be.
    fn clock_skew(&self) -> i64 {
        match *self {
            Self::Rest(_) => CLOCK_SKEW_SECONDS,
            Self::Http { .. } | Self::Cognito { .. } => 0,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpConfig {
    identity_source: Option<Value>,
    jwt_configuration: JwtConfiguration,
}

#[derive(Deserialize)]
struct JwtConfiguration {
    issuer: String,
    #[serde(default)]
    audience: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CognitoConfig {
    #[serde(rename = "providerARNs", default)]
    provider_arns: Vec<String>,
    identity_source: Option<Value>,
    identity_validation_expression: Option<String>,
}

/// A Cognito user pool, from its ARN
/// (`arn:aws:cognito-idp:{region}:{account}:userpool/{id}`).
struct UserPool<'a> {
    domain_suffix: &'static str,
    region: &'a str,
    id: &'a str,
}

impl<'a> UserPool<'a> {
    fn parse(arn: &'a str) -> Result<Self, String> {
        let mut parts = arn.split(':');
        let (
            Some("arn"),
            Some(partition),
            Some("cognito-idp"),
            Some(region),
            Some(_account),
            Some(resource),
            None,
        ) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        )
        else {
            return Err(format!("{arn:?} is not a Cognito user pool ARN"));
        };
        let id = resource
            .strip_prefix("userpool/")
            .filter(|id| !id.is_empty() && !region.is_empty())
            .ok_or_else(|| format!("{arn:?} is not a Cognito user pool ARN"))?;
        let domain_suffix = match partition {
            "aws" => "amazonaws.com",
            "aws-cn" => "amazonaws.com.cn",
            other => {
                return Err(format!(
                    "Cognito in the {other:?} partition is not supported"
                ));
            }
        };
        Ok(Self {
            domain_suffix,
            region,
            id,
        })
    }

    /// The pool's issuer, which tokens carry as `iss`.
    fn issuer(&self) -> Issuer {
        Issuer::new(format!(
            "https://cognito-idp.{}.{}/{}",
            self.region, self.domain_suffix, self.id
        ))
    }
}

#[derive(Debug)]
pub(crate) struct JwtAuthorizer {
    flavor: Flavor,
    sources: IdentitySources,
    issuers: Vec<IssuerConfig>,
    algorithms: Vec<SigningAlgorithm>,
}

impl JwtAuthorizer {
    /// An HTTP API `jwt` authorizer.
    pub(super) fn compile_http(spec: &AuthorizerSpec) -> Result<Self, String> {
        let config = HttpConfig::deserialize(&spec.config).map_err(|e| e.to_string())?;
        let JwtConfiguration { issuer, audience } = config.jwt_configuration;
        if !issuer.starts_with("https://") {
            return Err(format!("the issuer {issuer:?} is not an https URL"));
        }
        if audience.is_empty() {
            return Err("the authorizer lists no audience".to_owned());
        }
        let sources = Self::single_source(config.identity_source.as_ref())?;
        Ok(Self {
            flavor: Flavor::Http {
                audiences: audience,
            },
            sources,
            issuers: vec![IssuerConfig {
                issuer: Issuer::new(issuer),
                location: KeyLocation::Discovery,
                max_age: KEY_TTL,
            }],
            algorithms: SigningAlgorithm::RSA.to_vec(),
        })
    }

    /// A REST API `jwt` authorizer.
    pub(super) fn compile_rest(spec: &AuthorizerSpec) -> Result<Self, String> {
        let compiled = RestJwt::compile(spec)?;
        Ok(Self {
            flavor: Flavor::Rest(compiled.rest),
            sources: Self::single_source(Some(&json!(compiled.identity_source)))?,
            issuers: compiled.issuers,
            algorithms: compiled.algorithms,
        })
    }

    /// A REST API `cognito_user_pools` authorizer.
    pub(super) fn compile_cognito(
        spec: &AuthorizerSpec,
        variables: &StageVariables,
    ) -> Result<Self, String> {
        let config = CognitoConfig::deserialize(&spec.config).map_err(|e| e.to_string())?;
        if config.provider_arns.is_empty() {
            return Err("the authorizer lists no user pool".to_owned());
        }
        let issuers = config
            .provider_arns
            .iter()
            .map(|arn| {
                let arn = variables.substitute(arn);
                UserPool::parse(&arn).map(|pool| IssuerConfig {
                    issuer: pool.issuer(),
                    location: KeyLocation::WellKnownJwks,
                    max_age: KEY_TTL,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let configured = match (&config.identity_source, &spec.header_name) {
            (Some(source), _) => Some(source.clone()),
            (None, Some(header)) => Some(json!(format!("method.request.header.{header}"))),
            (None, None) => None,
        };
        let audience = config
            .identity_validation_expression
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|e| format!("identityValidationExpression cannot be evaluated: {e}"))?;
        Ok(Self {
            flavor: Flavor::Cognito { audience },
            sources: Self::single_source(configured.as_ref())?,
            issuers,
            algorithms: SigningAlgorithm::RSA.to_vec(),
        })
    }

    fn single_source(configured: Option<&Value>) -> Result<IdentitySources, String> {
        let default = json!(DEFAULT_IDENTITY_SOURCE);
        let sources = IdentitySources::from_config(Some(configured.unwrap_or(&default)))
            .map_err(|e| e.to_string())?;
        if sources.len() == 1 {
            Ok(sources)
        } else {
            Err("a token authorizer reads exactly one identity source".to_owned())
        }
    }

    /// Verifies the request's token. `required` are the OAuth scopes the route
    /// asks for.
    pub(super) async fn authorize(
        &self,
        request: &AuthRequest<'_>,
        required: &[String],
    ) -> Result<Authorized, Denial> {
        let ctx = request.ctx;
        let identity = self
            .sources
            .extract(ctx, &ctx.stage_variables)
            .ok_or(Denial::Unauthorized)?;
        let token = identity.first().map_or("", |value| Self::bearer(value));
        let verifier = Verifier {
            keys: request.keys,
            issuers: &self.issuers,
            algorithms: &self.algorithms,
        };
        let claims = verifier.verify(token).await.map_err(|e| Self::reject(&e))?;
        claims
            .check_times(ctx.received.as_second(), self.flavor.clock_skew())
            .map_err(|e| Self::reject(&e))?;
        match self.flavor {
            Flavor::Http { ref audiences } => {
                claims
                    .check_audience(audiences)
                    .map_err(|e| Self::reject(&e))?;
                if !claims.grants_any(required) {
                    return Err(Denial::InsufficientScope);
                }
                Ok(Authorized::allow(Self::http_context(&claims)))
            }
            Flavor::Cognito { ref audience } => {
                Self::check_cognito(&claims, audience.as_ref(), required)?;
                Ok(Authorized::allow(AuthorizerContext::claims(
                    Self::claims_value(ClaimStyle::Rest, &claims),
                )))
            }
            Flavor::Rest(ref rest) => {
                rest.check(&claims, required)?;
                let mut event = serde_json::Map::new();
                event.insert("claims".to_owned(), Value::Object(claims.to_map()));
                Ok(Authorized::allow(
                    AuthorizerContext::claims(Self::claims_value(ClaimStyle::Json, &claims))
                        .with_event(event),
                ))
            }
        }
    }

    /// The token without an optional `Bearer ` prefix.
    fn bearer(value: &str) -> &str {
        match value.split_once(' ') {
            Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => token.trim(),
            Some(_) | None => value,
        }
    }

    fn reject(error: &TokenError) -> Denial {
        tracing::debug!(%error, "token rejected");
        Denial::Unauthorized
    }

    /// A user pool token is an ID token when the route asks for no scopes and
    /// an access token carrying one of them when it does.
    fn check_cognito(
        claims: &Claims,
        audience: Option<&TokenPattern>,
        required: &[String],
    ) -> Result<(), Denial> {
        let expected_use = if required.is_empty() { "id" } else { "access" };
        if claims.text("token_use") != Some(expected_use) || !claims.grants_any(required) {
            return Err(Denial::Unauthorized);
        }
        if let Some(pattern) = audience {
            let matched = match claims.text("aud") {
                Some(aud) => pattern.is_match(aud).map_err(|error| {
                    tracing::warn!(%error, "identityValidationExpression could not be evaluated");
                    Denial::AuthorizerConfiguration
                })?,
                None => false,
            };
            if !matched {
                return Err(Denial::Unauthorized);
            }
        }
        Ok(())
    }

    fn claims_value(style: ClaimStyle, claims: &Claims) -> serde_json::Map<String, Value> {
        let mut values = serde_json::Map::new();
        values.insert("claims".to_owned(), Value::Object(style.claims(claims)));
        values
    }

    fn http_context(claims: &Claims) -> AuthorizerContext {
        let mut values = Self::claims_value(ClaimStyle::Http, claims);
        let scopes = claims.scopes();
        values.insert(
            "scopes".to_owned(),
            if scopes.is_empty() {
                Value::Null
            } else {
                json!(scopes)
            },
        );
        AuthorizerContext::claims(values)
    }
}
