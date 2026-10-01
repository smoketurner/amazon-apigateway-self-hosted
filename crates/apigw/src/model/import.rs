//! Reads an API Gateway `OpenAPI` 3.0 export (REST `GetExport` with
//! `extensions=apigateway,authorizers`, or HTTP `ExportApi` with extensions)
//! into an [`ApiModel`].

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;

use super::{
    ApiKeySource, ApiKind, ApiModel, ApiSettings, AuthorizerRef, AuthorizerSpec, CorsConfig,
    GatewayResponseSpec, IntegrationOverrides, IntegrationSpec, MethodMatch, Operation,
    ParameterSpec, Protection, Protections, RequestBodySpec, RouteKey, RoutePath, StageSettings,
    ValidatorSpec,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ImportError {
    #[error("the export is not a valid OpenAPI document: {0}")]
    Document(#[source] serde_json::Error),
    #[error("{route_key}: {source}")]
    Operation {
        route_key: RouteKey,
        source: serde_json::Error,
    },
    #[error("{route_key}: unresolvable reference {reference:?}")]
    Reference {
        route_key: RouteKey,
        reference: String,
    },
    #[error("integration override for {route_key} is invalid: {source}")]
    InvalidOverride {
        route_key: RouteKey,
        source: serde_json::Error,
    },
    #[error("integration overrides name routes that do not exist: {}", .0.iter().map(RouteKey::as_str).collect::<Vec<_>>().join(", "))]
    UnknownOverrides(Vec<RouteKey>),
}

/// Resolves local `$ref` pointers (`#/components/...`) against the document.
struct References<'a>(&'a Value);

impl References<'_> {
    const MAX_DEPTH: usize = 16;

    /// Follows `$ref` chains at the top of `value`; nested references (such as
    /// model schemas referring to other models) are left for the validator.
    fn resolve<'v>(&'v self, mut value: &'v Value) -> Option<&'v Value> {
        for _ in 0..Self::MAX_DEPTH {
            let Some(reference) = value.get("$ref").and_then(Value::as_str) else {
                return Some(value);
            };
            value = self.0.pointer(reference.strip_prefix('#')?)?;
        }
        None
    }
}

#[derive(Deserialize)]
struct Info {
    title: Option<String>,
}

#[derive(Deserialize)]
struct Document {
    info: Option<Info>,
    #[serde(default)]
    paths: BTreeMap<String, BTreeMap<String, Value>>,
    #[serde(default)]
    security: Option<SecurityRequirements>,
    #[serde(default)]
    components: Components,
    #[serde(rename = "x-amazon-apigateway-policy")]
    policy: Option<ResourcePolicy>,
    #[serde(rename = "x-amazon-apigateway-request-validators", default)]
    validators: BTreeMap<String, ValidatorSpec>,
    #[serde(rename = "x-amazon-apigateway-request-validator")]
    default_validator: Option<String>,
    #[serde(rename = "x-amazon-apigateway-gateway-responses", default)]
    gateway_responses: BTreeMap<String, GatewayResponseSpec>,
    #[serde(rename = "x-amazon-apigateway-binary-media-types", default)]
    binary_media_types: Vec<String>,
    #[serde(rename = "x-amazon-apigateway-minimum-compression-size")]
    minimum_compression_size: Option<u64>,
    #[serde(rename = "x-amazon-apigateway-api-key-source")]
    api_key_source: Option<ApiKeySource>,
    #[serde(rename = "x-amazon-apigateway-cors")]
    cors: Option<CorsConfig>,
    #[serde(rename = "x-amazon-apigateway-endpoint-configuration")]
    endpoint_configuration: Option<EndpointConfiguration>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EndpointConfiguration {
    #[serde(default)]
    disable_execute_api_endpoint: bool,
}

#[derive(Deserialize, Default)]
struct Components {
    #[serde(rename = "securitySchemes", default)]
    security_schemes: BTreeMap<String, SecurityScheme>,
    #[serde(default)]
    schemas: BTreeMap<String, Value>,
}

/// `x-amazon-apigateway-policy`: an IAM policy document, embedded as an object or
/// as a JSON-encoded string.
#[derive(Deserialize)]
#[serde(transparent)]
struct ResourcePolicy(Value);

impl ResourcePolicy {
    /// The policy as an object, if it parses.
    fn document(&self) -> Option<Value> {
        match self.0 {
            Value::String(ref text) => serde_json::from_str(text).ok(),
            Value::Null => None,
            Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => {
                Some(self.0.clone())
            }
        }
    }

    /// A policy protects the API if it has at least one statement. Text that
    /// doesn't parse still counts so the API fails closed.
    fn has_statements(&self) -> bool {
        let Some(document) = self.document() else {
            return matches!(self.0, Value::String(ref text) if !text.trim().is_empty());
        };
        match document.get("Statement") {
            Some(Value::Array(statements)) => !statements.is_empty(),
            Some(Value::Null) | None => false,
            Some(_) => true,
        }
    }
}

/// A `security` list. Alternatives are OR-ed; the schemes inside one alternative
/// are AND-ed.
#[derive(Deserialize, Clone)]
#[serde(transparent)]
struct SecurityRequirements(Vec<BTreeMap<String, Vec<String>>>);

impl SecurityRequirements {
    /// An empty requirement object (`[{}]`) makes authentication optional, so the
    /// route is only protected when every alternative names a scheme.
    fn is_required(&self) -> bool {
        !self.0.is_empty() && self.0.iter().all(|r| !r.is_empty())
    }

    fn schemes(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.0.iter().flat_map(BTreeMap::iter)
    }
}

#[derive(Deserialize, Clone)]
struct SecurityScheme {
    #[serde(rename = "type")]
    scheme_type: Option<String>,
    name: Option<String>,
    #[serde(rename = "x-amazon-apigateway-authtype")]
    auth_type: Option<String>,
    #[serde(rename = "x-amazon-apigateway-authorizer")]
    authorizer: Option<Value>,
}

impl SecurityScheme {
    /// How this scheme authenticates callers.
    fn protection(&self) -> Protection {
        let auth_type = self.auth_type.as_deref();
        if auth_type.is_some_and(|t| t.eq_ignore_ascii_case("awsSigv4")) {
            Protection::Iam
        } else if self.authorizer.is_none()
            && auth_type.is_none()
            && self.scheme_type.as_deref() == Some("apiKey")
        {
            Protection::ApiKey
        } else {
            Protection::Authorizer
        }
    }
}

#[derive(Deserialize)]
struct RawOperation {
    #[serde(rename = "x-amazon-apigateway-integration")]
    integration: Option<Value>,
    #[serde(default)]
    security: Option<SecurityRequirements>,
    #[serde(rename = "x-amazon-apigateway-request-validator")]
    validator: Option<String>,
    #[serde(default)]
    parameters: Vec<Value>,
    #[serde(rename = "requestBody")]
    request_body: Option<Value>,
}

#[derive(Deserialize)]
struct RawRequestBody {
    #[serde(default)]
    required: bool,
    #[serde(default)]
    content: BTreeMap<String, RawMediaType>,
}

#[derive(Deserialize)]
struct RawMediaType {
    schema: Option<Value>,
}

impl Document {
    fn security_requirements<'a>(
        &'a self,
        kind: ApiKind,
        operation: &'a RawOperation,
    ) -> Option<&'a SecurityRequirements> {
        // HTTP APIs apply the document-level `security` to every route; REST APIs
        // only honor per-method requirements.
        match kind {
            ApiKind::Rest => operation.security.as_ref(),
            ApiKind::Http => operation.security.as_ref().or(self.security.as_ref()),
        }
    }

    fn protections(
        &self,
        security: Option<&SecurityRequirements>,
        validator: Option<ValidatorSpec>,
    ) -> Protections {
        let mut protections = Protections::default();
        if let Some(requirements) = security.filter(|r| r.is_required()) {
            for (name, _) in requirements.schemes() {
                // Schemes the document doesn't declare count as authorizers so the
                // route fails closed.
                let protection = self
                    .components
                    .security_schemes
                    .get(name)
                    .map_or(Protection::Authorizer, SecurityScheme::protection);
                protections.insert(protection);
            }
        }
        if self
            .policy
            .as_ref()
            .is_some_and(ResourcePolicy::has_statements)
        {
            protections.insert(Protection::ResourcePolicy);
        }
        if validator.is_some_and(ValidatorSpec::validates) {
            protections.insert(Protection::RequestValidation);
        }
        protections
    }

    /// The validator named by the operation (or the document default). A name
    /// with no definition validates everything so the route fails closed.
    fn validator(&self, operation: &RawOperation) -> Option<ValidatorSpec> {
        let name = operation
            .validator
            .as_ref()
            .or(self.default_validator.as_ref())?;
        Some(self.validators.get(name).copied().unwrap_or(ValidatorSpec {
            validate_request_body: true,
            validate_request_parameters: true,
        }))
    }

    fn authorizer(&self, security: Option<&SecurityRequirements>) -> Option<AuthorizerRef> {
        let requirements = security.filter(|r| r.is_required())?;
        requirements.schemes().find_map(|(name, scopes)| {
            let scheme = self.components.security_schemes.get(name)?;
            (scheme.protection() == Protection::Authorizer).then(|| AuthorizerRef {
                name: name.clone(),
                scopes: scopes.clone(),
            })
        })
    }

    fn authorizers(&self) -> BTreeMap<String, AuthorizerSpec> {
        let mut authorizers = BTreeMap::new();
        for (name, scheme) in &self.components.security_schemes {
            if scheme.protection() == Protection::Authorizer {
                authorizers.insert(
                    name.clone(),
                    AuthorizerSpec {
                        auth_type: scheme.auth_type.clone(),
                        header_name: scheme.name.clone(),
                        config: scheme.authorizer.clone().unwrap_or(Value::Null),
                    },
                );
            }
        }
        authorizers
    }

    fn settings(&self) -> ApiSettings {
        ApiSettings {
            title: self.info.as_ref().and_then(|info| info.title.clone()),
            binary_media_types: self.binary_media_types.clone(),
            minimum_compression_size: self.minimum_compression_size,
            api_key_source: self.api_key_source,
            cors: self.cors.clone(),
            resource_policy: self.policy.as_ref().and_then(ResourcePolicy::document),
            disable_execute_api_endpoint: self
                .endpoint_configuration
                .as_ref()
                .is_some_and(|e| e.disable_execute_api_endpoint),
        }
    }
}

/// One operation being imported: where it is, and the raw JSON it came from.
struct OperationSource<'a> {
    route_key: RouteKey,
    path_parameters: &'a [Value],
    raw: RawOperation,
}

impl OperationSource<'_> {
    fn integration(
        &self,
        references: &References<'_>,
        overrides: &IntegrationOverrides,
    ) -> Result<Option<IntegrationSpec>, ImportError> {
        if let Some(value) = overrides.get(&self.route_key) {
            return IntegrationSpec::deserialize(value)
                .map(Some)
                .map_err(|source| ImportError::InvalidOverride {
                    route_key: self.route_key.clone(),
                    source,
                });
        }
        let Some(ref raw) = self.raw.integration else {
            return Ok(None);
        };
        let value = self.resolve(references, raw)?;
        IntegrationSpec::deserialize(value)
            .map(Some)
            .map_err(|source| self.operation_error(source))
    }

    fn parameters(&self, references: &References<'_>) -> Result<Vec<ParameterSpec>, ImportError> {
        // Operation-level parameters override path-level ones of the same name and
        // location.
        let mut parameters: BTreeMap<(String, String), ParameterSpec> = BTreeMap::new();
        for raw in self.path_parameters.iter().chain(&self.raw.parameters) {
            let parameter = ParameterSpec::deserialize(self.resolve(references, raw)?)
                .map_err(|source| self.operation_error(source))?;
            parameters.insert(
                (
                    parameter.location.as_str().to_owned(),
                    parameter.name.clone(),
                ),
                parameter,
            );
        }
        Ok(parameters.into_values().collect())
    }

    fn request_body(
        &self,
        references: &References<'_>,
    ) -> Result<Option<RequestBodySpec>, ImportError> {
        let Some(ref raw) = self.raw.request_body else {
            return Ok(None);
        };
        let body = RawRequestBody::deserialize(self.resolve(references, raw)?)
            .map_err(|source| self.operation_error(source))?;
        let schemas = body
            .content
            .into_iter()
            .filter_map(|(content_type, media)| media.schema.map(|schema| (content_type, schema)))
            .collect();
        Ok(Some(RequestBodySpec {
            required: body.required,
            schemas,
        }))
    }

    fn resolve<'v>(
        &self,
        references: &'v References<'_>,
        value: &'v Value,
    ) -> Result<&'v Value, ImportError> {
        references
            .resolve(value)
            .ok_or_else(|| ImportError::Reference {
                route_key: self.route_key.clone(),
                reference: value
                    .get("$ref")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            })
    }

    fn operation_error(&self, source: serde_json::Error) -> ImportError {
        ImportError::Operation {
            route_key: self.route_key.clone(),
            source,
        }
    }
}

impl ApiModel {
    /// Imports an export. Every operation is kept, even ones that can't be served,
    /// so they answer with a clear error instead of silently disappearing.
    ///
    /// # Errors
    ///
    /// When the document is not an `OpenAPI` export, an operation is malformed, a
    /// `$ref` can't be resolved, or an override is invalid or names no route.
    pub(crate) fn import(
        export: &Value,
        kind: ApiKind,
        stage: StageSettings,
        overrides: &IntegrationOverrides,
    ) -> Result<Self, ImportError> {
        let document = Document::deserialize(export).map_err(ImportError::Document)?;
        let references = References(export);
        let mut unused: BTreeSet<&RouteKey> = overrides.keys().collect();
        let mut operations = Vec::new();
        for (path, item) in &document.paths {
            let route_path = RoutePath::from_openapi_path(path);
            let path_parameters: Vec<Value> = match item.get("parameters") {
                Some(Value::Array(parameters)) => parameters.clone(),
                Some(_) | None => Vec::new(),
            };
            for (key, raw) in item {
                let Some(method) = MethodMatch::from_openapi_key(key) else {
                    continue;
                };
                let route_key = RouteKey::new(&method, &route_path);
                let raw =
                    RawOperation::deserialize(raw).map_err(|source| ImportError::Operation {
                        route_key: route_key.clone(),
                        source,
                    })?;
                unused.remove(&route_key);
                let source = OperationSource {
                    route_key,
                    path_parameters: &path_parameters,
                    raw,
                };
                let security = document.security_requirements(kind, &source.raw);
                // HTTP APIs have no request validators; whatever an export or a hand-written
                // file says, they never validate.
                let validator = match kind {
                    ApiKind::Rest => document.validator(&source.raw),
                    ApiKind::Http => None,
                };
                operations.push(Operation {
                    method,
                    path: route_path.clone(),
                    protections: document.protections(security, validator),
                    integration: source.integration(&references, overrides)?,
                    parameters: source.parameters(&references)?,
                    request_body: source.request_body(&references)?,
                    validator,
                    authorizer: document.authorizer(security),
                    route_key: source.route_key,
                });
            }
        }
        if !unused.is_empty() {
            return Err(ImportError::UnknownOverrides(
                unused.into_iter().cloned().collect(),
            ));
        }
        Ok(Self {
            kind,
            operations,
            settings: document.settings(),
            authorizers: document.authorizers(),
            gateway_responses: document.gateway_responses.clone(),
            models: document.components.schemas.clone(),
            stage,
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(
    clippy::indexing_slicing,
    reason = "tests index fixtures of known length"
)]
mod tests {
    use serde_json::json;

    use super::super::{
        ConnectionType, ContentHandling, Feature, IntegrationType, ParameterLocation,
        PassthroughBehavior, PayloadVersion, ResponseTransferMode,
    };
    use super::*;

    fn import(doc: &Value, kind: ApiKind) -> ApiModel {
        ApiModel::import(
            doc,
            kind,
            StageSettings::default(),
            &IntegrationOverrides::default(),
        )
        .unwrap()
    }

    fn by_path(model: &ApiModel) -> BTreeMap<String, &Operation> {
        model
            .operations
            .iter()
            .map(|o| (o.path.to_string(), o))
            .collect()
    }

    /// A REST export carrying every extension the importer reads. Hand-written
    /// from the API Gateway extension reference, not recorded from AWS.
    const REST_EXPORT: &str = include_str!("../../tests/fixtures/rest-export.json");
    /// An HTTP API export, hand-written from the same reference.
    const HTTP_EXPORT: &str = include_str!("../../tests/fixtures/http-export.json");

    #[test]
    fn rest_export_extensions_are_imported() {
        let doc: Value = serde_json::from_str(REST_EXPORT).unwrap();
        let model = import(&doc, ApiKind::Rest);
        assert_eq!(
            model.settings.binary_media_types,
            vec!["image/png".to_owned()]
        );
        assert_eq!(model.settings.minimum_compression_size, Some(1024));
        assert_eq!(model.settings.api_key_source, Some(ApiKeySource::Header));
        assert!(model.settings.resource_policy.is_some());
        assert!(model.settings.disable_execute_api_endpoint);
        assert!(
            model
                .gateway_responses
                .contains_key("MISSING_AUTHENTICATION_TOKEN")
        );
        assert!(model.models.contains_key("Pet"));
        assert_eq!(model.authorizers.len(), 2);
        assert_eq!(
            model.unenforced(),
            vec![Feature::BinaryMediaTypes, Feature::Compression]
        );

        let ops = by_path(&model);
        let pets = ops["/pets"];
        assert!(pets.protections.contains(Protection::ApiKey));
        assert!(pets.protections.contains(Protection::ResourcePolicy));
        assert!(pets.protections.contains(Protection::RequestValidation));
        assert_eq!(
            pets.validator,
            Some(ValidatorSpec {
                validate_request_body: true,
                validate_request_parameters: true
            })
        );
        let body = pets.request_body.as_ref().unwrap();
        assert!(body.required);
        assert!(body.schemas.contains_key("application/json"));
        let integration = pets.integration.as_ref().unwrap();
        assert_eq!(integration.integration_type, IntegrationType::Aws);
        assert_eq!(
            integration.passthrough_behavior,
            Some(PassthroughBehavior::WhenNoTemplates)
        );
        assert_eq!(
            integration.content_handling,
            Some(ContentHandling::ConvertToText)
        );
        assert_eq!(
            integration.credentials.as_deref(),
            Some("arn:aws:iam::123456789012:role/apigw-sqs")
        );
        assert_eq!(
            integration.cache_key_parameters,
            vec!["method.request.querystring.page".to_owned()]
        );
        assert_eq!(integration.responses["default"].status(), Some(200));
        assert_eq!(integration.responses["5\\d{2}"].status(), Some(500));

        let pet = ops["/pets/{petId}"];
        assert_eq!(
            pet.authorizer,
            Some(AuthorizerRef {
                name: "token".to_owned(),
                scopes: Vec::new()
            })
        );
        assert_eq!(
            pet.parameters.len(),
            2,
            "path-level parameter merged with operation's"
        );
        assert!(
            pet.parameters
                .iter()
                .any(|p| p.location == ParameterLocation::Path && p.required)
        );
        let referenced = pet.integration.as_ref().unwrap();
        assert_eq!(
            referenced.integration_type,
            IntegrationType::HttpProxy,
            "$ref resolved"
        );
        assert_eq!(referenced.connection_type, Some(ConnectionType::Internet));
        assert!(
            referenced
                .tls_config
                .as_ref()
                .unwrap()
                .insecure_skip_verification
        );

        let stream = ops["/stream"];
        assert_eq!(
            stream.integration.as_ref().unwrap().response_transfer_mode,
            Some(ResponseTransferMode::Stream)
        );
    }

    #[test]
    fn http_apis_never_validate_requests() {
        let doc = json!({
            "x-amazon-apigateway-request-validators": {"all": {"validateRequestBody": true, "validateRequestParameters": true}},
            "x-amazon-apigateway-request-validator": "all",
            "paths": {"/a": {"get": {
                "x-amazon-apigateway-request-validator": "all",
                "x-amazon-apigateway-integration": {"type": "mock"}
            }}}
        });
        let rest = import(&doc, ApiKind::Rest);
        let http = import(&doc, ApiKind::Http);
        let protections = |model: &ApiModel| {
            model
                .operations
                .iter()
                .any(|o| o.protections.contains(Protection::RequestValidation))
        };
        assert!(protections(&rest));
        assert!(!protections(&http));
        assert!(http.operations.iter().all(|o| o.validator.is_none()));
    }

    #[test]
    fn http_export_extensions_are_imported() {
        let doc: Value = serde_json::from_str(HTTP_EXPORT).unwrap();
        let model = import(&doc, ApiKind::Http);
        let cors = model.settings.cors.as_ref().unwrap();
        assert_eq!(cors.allow_origins, vec!["https://example.com".to_owned()]);
        assert_eq!(cors.max_age, Some(300));
        assert!(model.unenforced().is_empty());

        let ops = by_path(&model);
        let orders = ops["/orders"];
        let integration = orders.integration.as_ref().unwrap();
        assert_eq!(integration.integration_type, IntegrationType::AwsProxy);
        assert_eq!(integration.subtype.as_deref(), Some("SQS-SendMessage"));
        assert_eq!(integration.payload_format_version, Some(PayloadVersion::V1));
        assert_eq!(
            orders.authorizer.as_ref().unwrap().scopes,
            vec!["orders:write".to_owned()]
        );
        let items = ops["/items/{id}"];
        assert_eq!(items.unenforced(), vec![Feature::IntegrationTlsConfig]);
        assert!(
            items.protections.contains(Protection::Authorizer),
            "document-level security applies"
        );
        assert!(ops["$default"].integration.is_some());
    }

    #[test]
    fn rest_apis_ignore_document_security() {
        let doc = json!({
            "security": [{"api_key": []}],
            "components": {"securitySchemes": {"api_key": {"type": "apiKey", "name": "x-api-key", "in": "header"}}},
            "paths": {"/a": {"get": {"x-amazon-apigateway-integration": {"type": "mock"}}}}
        });
        assert_eq!(
            import(&doc, ApiKind::Rest).operations[0].protections,
            Protections::default()
        );
        assert!(
            import(&doc, ApiKind::Http).operations[0]
                .protections
                .contains(Protection::ApiKey)
        );
    }

    #[test]
    fn optional_auth_and_undeclared_schemes() {
        let integration = json!({"type": "mock"});
        let doc = json!({"paths": {
            "/optional": {"get": {"security": [{}, {"jwt": []}], "x-amazon-apigateway-integration": integration}},
            "/empty": {"get": {"security": [], "x-amazon-apigateway-integration": integration}},
            "/undeclared": {"get": {"security": [{"mystery": []}], "x-amazon-apigateway-integration": integration}}
        }});
        let model = import(&doc, ApiKind::Http);
        let ops = by_path(&model);
        assert_eq!(ops["/optional"].protections, Protections::default());
        assert_eq!(ops["/empty"].protections, Protections::default());
        assert_eq!(
            ops["/undeclared"].protections,
            Protections::from_iter([Protection::Authorizer])
        );
        assert_eq!(
            ops["/undeclared"].authorizer, None,
            "undeclared schemes have no definition to evaluate"
        );
    }

    #[test]
    fn security_schemes_are_classified() {
        let integration = json!({"type": "mock"});
        let op = |schemes: Value| json!({"security": [schemes], "x-amazon-apigateway-integration": integration});
        let doc = json!({
            "components": {"securitySchemes": {
                "sigv4": {"type": "apiKey", "name": "Authorization", "in": "header", "x-amazon-apigateway-authtype": "awsSigv4"},
                "api_key": {"type": "apiKey", "name": "x-api-key", "in": "header"},
                "lambda": {"type": "apiKey", "name": "Authorization", "in": "header",
                    "x-amazon-apigateway-authtype": "custom", "x-amazon-apigateway-authorizer": {"type": "token"}},
                "cognito": {"type": "apiKey", "name": "Authorization", "in": "header",
                    "x-amazon-apigateway-authtype": "cognito_user_pools", "x-amazon-apigateway-authorizer": {"type": "cognito_user_pools"}}
            }},
            "paths": {
                "/iam": {"get": op(json!({"sigv4": []}))},
                "/key": {"get": op(json!({"api_key": []}))},
                "/lambda-and-key": {"get": op(json!({"lambda": [], "api_key": []}))},
                "/cognito": {"get": op(json!({"cognito": ["email"]}))}
            }
        });
        let model = import(&doc, ApiKind::Rest);
        let ops = by_path(&model);
        let only = |p: &[Protection]| Protections::from_iter(p.iter().copied());
        assert_eq!(ops["/iam"].protections, only(&[Protection::Iam]));
        assert_eq!(ops["/key"].protections, only(&[Protection::ApiKey]));
        assert_eq!(
            ops["/lambda-and-key"].protections,
            only(&[Protection::Authorizer, Protection::ApiKey])
        );
        assert_eq!(
            ops["/cognito"].authorizer,
            Some(AuthorizerRef {
                name: "cognito".to_owned(),
                scopes: vec!["email".to_owned()]
            })
        );
        assert_eq!(model.authorizers.len(), 2);
        assert_eq!(
            model.authorizers["lambda"].auth_type.as_deref(),
            Some("custom")
        );
    }

    #[test]
    fn resource_policies_with_statements_protect_every_route() {
        let paths = json!({"/a": {"get": {"x-amazon-apigateway-integration": {"type": "mock"}}}});
        let statement = json!({"Effect": "Allow", "Principal": "*", "Action": "execute-api:Invoke", "Resource": "*"});
        let cases = [
            (
                json!({"Version": "2012-10-17", "Statement": [statement]}),
                true,
            ),
            (
                json!({"Version": "2012-10-17", "Statement": statement}),
                true,
            ),
            (
                Value::String(json!({"Statement": [statement]}).to_string()),
                true,
            ),
            (Value::String("not json".to_owned()), true),
            (json!({"Version": "2012-10-17", "Statement": []}), false),
            (json!({"Version": "2012-10-17"}), false),
            (Value::String("  ".to_owned()), false),
            (Value::Null, false),
        ];
        for (policy, expected) in cases {
            let doc = json!({"x-amazon-apigateway-policy": policy, "paths": paths});
            let model = import(&doc, ApiKind::Rest);
            assert_eq!(
                model.operations[0]
                    .protections
                    .contains(Protection::ResourcePolicy),
                expected,
                "{policy}"
            );
        }
    }

    #[test]
    fn request_validators_resolve_default_override_and_unknown_names() {
        let integration = json!({"type": "mock"});
        let doc = json!({
            "x-amazon-apigateway-request-validators": {
                "all": {"validateRequestBody": true, "validateRequestParameters": true},
                "params": {"validateRequestParameters": true},
                "none": {"validateRequestBody": false, "validateRequestParameters": false}
            },
            "x-amazon-apigateway-request-validator": "params",
            "paths": {
                "/default": {"get": {"x-amazon-apigateway-integration": integration}},
                "/off": {"get": {"x-amazon-apigateway-request-validator": "none", "x-amazon-apigateway-integration": integration}},
                "/all": {"get": {"x-amazon-apigateway-request-validator": "all", "x-amazon-apigateway-integration": integration}},
                "/unknown": {"get": {"x-amazon-apigateway-request-validator": "missing", "x-amazon-apigateway-integration": integration}}
            }
        });
        let model = import(&doc, ApiKind::Rest);
        let ops = by_path(&model);
        let validates = |path: &str| {
            ops[path]
                .protections
                .contains(Protection::RequestValidation)
        };
        assert!(validates("/default"));
        assert!(!validates("/off"));
        assert!(validates("/all"));
        assert!(validates("/unknown"));
    }

    #[test]
    fn overrides_replace_integrations_and_unknown_or_invalid_ones_are_rejected() {
        let doc = json!({"paths": {"/a": {"get": {"x-amazon-apigateway-integration": {"type": "mock"}}}}});
        let overrides = IntegrationOverrides::from_iter([(
            "GET /a",
            json!({"type": "http_proxy", "uri": "http://x"}),
        )]);
        let model =
            ApiModel::import(&doc, ApiKind::Rest, StageSettings::default(), &overrides).unwrap();
        assert_eq!(
            model.operations[0]
                .integration
                .as_ref()
                .unwrap()
                .integration_type,
            IntegrationType::HttpProxy
        );

        let unknown = IntegrationOverrides::from_iter([
            ("GET /b", json!({"type": "mock"})),
            ("POST /a", json!({"type": "mock"})),
        ]);
        let err =
            ApiModel::import(&doc, ApiKind::Rest, StageSettings::default(), &unknown).unwrap_err();
        assert_eq!(
            err.to_string(),
            "integration overrides name routes that do not exist: GET /b, POST /a"
        );

        let invalid = IntegrationOverrides::from_iter([("GET /a", json!({"uri": "http://x"}))]);
        let err =
            ApiModel::import(&doc, ApiKind::Rest, StageSettings::default(), &invalid).unwrap_err();
        assert!(matches!(err, ImportError::InvalidOverride { .. }), "{err}");
    }

    #[test]
    fn malformed_documents_and_references_are_errors() {
        let err = ApiModel::import(
            &json!({"paths": []}),
            ApiKind::Rest,
            StageSettings::default(),
            &IntegrationOverrides::default(),
        );
        assert!(matches!(err, Err(ImportError::Document(_))));

        let doc = json!({"paths": {"/a": {"get": {"x-amazon-apigateway-integration": {"$ref": "#/components/missing"}}}}});
        let err = ApiModel::import(
            &doc,
            ApiKind::Rest,
            StageSettings::default(),
            &IntegrationOverrides::default(),
        );
        assert!(matches!(err, Err(ImportError::Reference { .. })));

        let looping = json!({"components": {"a": {"$ref": "#/components/a"}},
            "paths": {"/a": {"get": {"x-amazon-apigateway-integration": {"$ref": "#/components/a"}}}}});
        let err = ApiModel::import(
            &looping,
            ApiKind::Rest,
            StageSettings::default(),
            &IntegrationOverrides::default(),
        );
        assert!(matches!(err, Err(ImportError::Reference { .. })));

        let bad_type = json!({"paths": {"/a": {"get": {"x-amazon-apigateway-integration": {"type": "carrier_pigeon"}}}}});
        let err = ApiModel::import(
            &bad_type,
            ApiKind::Rest,
            StageSettings::default(),
            &IntegrationOverrides::default(),
        );
        assert!(matches!(err, Err(ImportError::Operation { .. })));
    }

    #[test]
    fn non_operation_keys_are_skipped() {
        let doc = json!({"paths": {"/a": {"parameters": [], "summary": "x", "get": {
            "x-amazon-apigateway-integration": {"type": "mock"}
        }}}});
        assert_eq!(import(&doc, ApiKind::Rest).operations.len(), 1);
    }
}
