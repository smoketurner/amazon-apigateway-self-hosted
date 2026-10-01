//! YAML request cases: what to send, to which reference API, and which parts of the
//! response and of what the echo backend received are compared.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde::Deserialize;

use crate::error::{ParityError, Result};

const MAX_CASE_NAME_LEN: usize = 100;
const ENV_OPEN: &str = "{{env:";
const ENV_CLOSE: &str = "}}";
const UNSET_PLACEHOLDER: &str = "unset-env";

/// A fixture-file-safe case name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, serde::Serialize)]
#[serde(try_from = "String")]
pub(crate) struct CaseName(String);

impl TryFrom<String> for CaseName {
    type Error = ParityError;

    fn try_from(name: String) -> Result<Self> {
        let valid = !name.is_empty()
            && name.len() <= MAX_CASE_NAME_LEN
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if valid {
            Ok(Self(name))
        } else {
            Err(ParityError::InvalidCaseName(name))
        }
    }
}

impl fmt::Display for CaseName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which reference API a case targets.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ApiName {
    /// The main REST API.
    Rest,
    /// The HTTP API.
    Http,
    /// The REST API that carries a resource policy.
    RestPolicy,
}

impl ApiName {
    pub(crate) const ALL: [Self; 3] = [Self::Rest, Self::Http, Self::RestPolicy];

    /// The `--api-type` value apigw needs to serve this API's export.
    pub(crate) fn api_type(self) -> &'static str {
        match self {
            Self::Rest | Self::RestPolicy => "rest",
            Self::Http => "http",
        }
    }

    pub(crate) fn file_stem(self) -> &'static str {
        match self {
            Self::Rest => "rest",
            Self::Http => "http",
            Self::RestPolicy => "rest_policy",
        }
    }
}

impl fmt::Display for ApiName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.file_stem())
    }
}

/// An HTTP method as written in a case file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct MethodName(reqwest::Method);

impl MethodName {
    pub(crate) fn method(&self) -> reqwest::Method {
        self.0.clone()
    }
}

impl Default for MethodName {
    fn default() -> Self {
        Self(reqwest::Method::GET)
    }
}

impl TryFrom<String> for MethodName {
    type Error = String;

    fn try_from(text: String) -> std::result::Result<Self, String> {
        reqwest::Method::from_bytes(text.to_ascii_uppercase().as_bytes())
            .map(Self)
            .map_err(|err| format!("invalid HTTP method {text:?}: {err}"))
    }
}

/// How the response body is compared.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BodyCompare {
    /// Byte-for-byte after normalization.
    #[default]
    Exact,
    /// As JSON values, so key order and whitespace do not matter.
    Json,
    /// Not compared.
    Ignore,
}

/// A part of the request the echo backend received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EchoField {
    Method,
    Path,
    Query,
    Body,
}

/// Which parts of what the echo backend received are compared: the listed
/// `fields`, plus the listed `headers` by name.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct EchoCompare {
    pub(crate) fields: Vec<EchoField>,
    pub(crate) headers: Vec<String>,
}

impl EchoCompare {
    pub(crate) fn compares(&self, field: EchoField) -> bool {
        self.fields.contains(&field)
    }
}

impl Default for EchoCompare {
    fn default() -> Self {
        Self {
            fields: vec![EchoField::Method, EchoField::Path, EchoField::Query],
            headers: Vec::new(),
        }
    }
}

/// Which parts of an observation a case compares. Everything else is recorded
/// but never fails a replay.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Compare {
    pub(crate) status: bool,
    pub(crate) headers: Vec<String>,
    pub(crate) body: BodyCompare,
    pub(crate) echo: Option<EchoCompare>,
}

impl Default for Compare {
    fn default() -> Self {
        Self {
            status: true,
            headers: Vec::new(),
            body: BodyCompare::Exact,
            echo: None,
        }
    }
}

/// One request and the comparison rules for its response.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Case {
    pub(crate) name: CaseName,
    pub(crate) api: ApiName,
    #[serde(default)]
    pub(crate) method: MethodName,
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) headers: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) query: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) body: Option<String>,
    #[serde(default)]
    pub(crate) compare: Compare,
    /// Issue reference for a feature `apigw` does not implement yet. Replay
    /// expects such a case to differ from its fixture and fails when it matches,
    /// so the marker cannot go stale.
    #[serde(default)]
    pub(crate) known_gap: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseFile {
    cases: Vec<Case>,
}

/// Where `{{env:NAME}}` placeholders get their values.
pub(crate) trait EnvSource {
    fn get(&self, name: &str) -> Option<String>;
}

/// The process environment.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|value| !value.is_empty())
    }
}

impl EnvSource for BTreeMap<String, String> {
    fn get(&self, name: &str) -> Option<String> {
        BTreeMap::get(self, name).cloned()
    }
}

/// What to do when a placeholder names an unset variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnsetEnv {
    /// Fail the case; record mode needs real credentials.
    Fail,
    /// Substitute a fixed token; replay never needs the real value.
    Placeholder,
}

/// Expands `{{env:NAME}}` placeholders in case fields.
#[derive(Debug)]
pub(crate) struct Expander<E> {
    source: E,
    unset: UnsetEnv,
}

impl<E: EnvSource> Expander<E> {
    pub(crate) fn new(source: E, unset: UnsetEnv) -> Self {
        Self { source, unset }
    }

    /// Replaces placeholders in `text`, appending every value it inserted to
    /// `used` so the caller can redact them from recordings.
    fn expand(&self, case: &CaseName, text: &str, used: &mut Vec<String>) -> Result<String> {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some((before, after)) = rest.split_once(ENV_OPEN) {
            out.push_str(before);
            let Some((name, tail)) = after.split_once(ENV_CLOSE) else {
                return Err(ParityError::UnterminatedPlaceholder { case: case.clone() });
            };
            match (self.source.get(name), self.unset) {
                (Some(value), _) => {
                    out.push_str(&value);
                    used.push(value);
                }
                (None, UnsetEnv::Placeholder) => out.push_str(UNSET_PLACEHOLDER),
                (None, UnsetEnv::Fail) => {
                    return Err(ParityError::MissingEnv {
                        case: case.clone(),
                        variable: name.to_owned(),
                    });
                }
            }
            rest = tail;
        }
        out.push_str(rest);
        Ok(out)
    }
}

/// A request with placeholders expanded, ready to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestSpec {
    pub(crate) method: reqwest::Method,
    pub(crate) path: String,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) query: BTreeMap<String, String>,
    pub(crate) body: Option<String>,
}

/// A [`RequestSpec`] plus the secret values that were substituted into it.
#[derive(Debug)]
pub(crate) struct ExpandedRequest {
    pub(crate) spec: RequestSpec,
    pub(crate) secrets: Vec<String>,
}

impl Case {
    pub(crate) fn request<E: EnvSource>(&self, expander: &Expander<E>) -> Result<ExpandedRequest> {
        let mut secrets = Vec::new();
        let mut expand = |text: &str| expander.expand(&self.name, text, &mut secrets);
        let path = expand(&self.path)?;
        let mut headers = BTreeMap::new();
        for (name, value) in &self.headers {
            headers.insert(name.to_ascii_lowercase(), expand(value)?);
        }
        let mut query = BTreeMap::new();
        for (name, value) in &self.query {
            query.insert(name.clone(), expand(value)?);
        }
        let body = self.body.as_deref().map(&mut expand).transpose()?;
        Ok(ExpandedRequest {
            spec: RequestSpec {
                method: self.method.method(),
                path,
                headers,
                query,
                body,
            },
            secrets,
        })
    }
}

/// Every case under a directory, sorted by name.
#[derive(Debug)]
pub(crate) struct CaseSet {
    cases: Vec<Case>,
}

impl CaseSet {
    /// Reads every `*.yaml` / `*.yml` file in `dir`.
    ///
    /// # Errors
    /// Fails when a file cannot be read or parsed, or when two cases share a name.
    pub(crate) fn load(dir: &Path) -> Result<Self> {
        let entries = std::fs::read_dir(dir).map_err(|e| ParityError::io(dir, e))?;
        let mut paths = Vec::new();
        for entry in entries {
            let path = entry.map_err(|e| ParityError::io(dir, e))?.path();
            let is_yaml = path
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml");
            if is_yaml {
                paths.push(path);
            }
        }
        paths.sort();
        let mut cases = Vec::new();
        for path in paths {
            let text = std::fs::read_to_string(&path).map_err(|e| ParityError::io(&path, e))?;
            let file: CaseFile = serde_saphyr::from_str(&text).map_err(|e| ParityError::Yaml {
                path: path.clone(),
                message: e.to_string(),
            })?;
            cases.extend(file.cases);
        }
        Self::from_cases(cases)
    }

    pub(crate) fn from_cases(mut cases: Vec<Case>) -> Result<Self> {
        cases.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(pair) = cases.windows(2).find(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_some_and(|(a, b)| a.name == b.name)
        }) && let Some(duplicate) = pair.first()
        {
            return Err(ParityError::DuplicateCase(duplicate.name.clone()));
        }
        Ok(Self { cases })
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Case> {
        self.cases.iter()
    }

    pub(crate) fn for_api(&self, api: ApiName) -> impl Iterator<Item = &Case> {
        self.cases.iter().filter(move |case| case.api == api)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(
    clippy::indexing_slicing,
    reason = "tests index fixtures of known shape"
)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<CaseFile> {
        serde_saphyr::from_str(yaml).map_err(|e| ParityError::Yaml {
            path: "inline".into(),
            message: e.to_string(),
        })
    }

    const MINIMAL: &str = "cases:\n  - name: a-case\n    api: rest\n    path: /mock\n";

    #[test]
    fn minimal_case_gets_defaults() {
        let file = parse(MINIMAL).unwrap();
        let case = file.cases.first().unwrap();
        assert_eq!(case.method.method(), reqwest::Method::GET);
        assert_eq!(case.compare, Compare::default());
        assert!(case.compare.status);
        assert_eq!(case.compare.body, BodyCompare::Exact);
        assert_eq!(case.known_gap, None);
    }

    #[test]
    fn full_case_parses_every_field() {
        let yaml = "cases:
  - name: full_1
    api: rest_policy
    method: post
    path: /x/{y}
    headers: {X-A: b}
    query: {q: '1'}
    body: '{\"a\":1}'
    known_gap: '#37'
    compare:
      status: false
      headers: [content-type]
      body: json
      echo: {fields: [method, path, query, body], headers: [x-mapped]}
";
        let file = parse(yaml).unwrap();
        let case = file.cases.first().unwrap();
        assert_eq!(case.api, ApiName::RestPolicy);
        assert_eq!(case.method.method(), reqwest::Method::POST);
        assert_eq!(case.known_gap.as_deref(), Some("#37"));
        let echo = case.compare.echo.as_ref().unwrap();
        assert!(echo.compares(EchoField::Body) && echo.compares(EchoField::Method));
        assert_eq!(echo.headers, ["x-mapped"]);
        assert_eq!(case.compare.body, BodyCompare::Json);
    }

    #[test]
    fn invalid_names_methods_and_fields_are_rejected() {
        for name in ["", "UPPER", "has space", "dot.name", &"a".repeat(101)] {
            assert!(
                CaseName::try_from(name.to_owned()).is_err(),
                "{name:?} must be rejected"
            );
        }
        assert!(
            parse("cases:\n  - name: a\n    api: rest\n    path: /\n    method: 'BAD METHOD'\n")
                .is_err()
        );
        assert!(parse("cases:\n  - name: a\n    api: grpc\n    path: /\n").is_err());
        assert!(parse("cases:\n  - name: a\n    api: rest\n    path: /\n    extra: 1\n").is_err());
        assert!(parse("cases:\n  - name: a\n    api: rest\n").is_err());
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let file = parse(&format!(
            "{MINIMAL}  - name: a-case\n    api: http\n    path: /\n"
        ))
        .unwrap();
        assert!(matches!(
            CaseSet::from_cases(file.cases),
            Err(ParityError::DuplicateCase(name)) if name.to_string() == "a-case"
        ));
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn case_with_placeholders() -> Case {
        let yaml = "cases:
  - name: auth
    api: rest
    path: /p/{{env:SEG}}
    headers: {Authorization: 'Bearer {{env:TOKEN}}'}
    query: {k: '{{env:SEG}}-{{env:TOKEN}}'}
    body: '{{env:TOKEN}}'
";
        parse(yaml).unwrap().cases.into_iter().next().unwrap()
    }

    #[test]
    fn placeholders_expand_everywhere_and_report_secrets() {
        let expander = Expander::new(env(&[("TOKEN", "s3cr3t"), ("SEG", "x")]), UnsetEnv::Fail);
        let request = case_with_placeholders().request(&expander).unwrap();
        assert_eq!(request.spec.path, "/p/x");
        assert_eq!(request.spec.headers["authorization"], "Bearer s3cr3t");
        assert_eq!(request.spec.query["k"], "x-s3cr3t");
        assert_eq!(request.spec.body.as_deref(), Some("s3cr3t"));
        assert!(request.secrets.contains(&"s3cr3t".to_owned()));
    }

    #[test]
    fn unset_variables_fail_or_use_a_placeholder() {
        let strict = Expander::new(env(&[("SEG", "x")]), UnsetEnv::Fail);
        assert!(matches!(
            case_with_placeholders().request(&strict),
            Err(ParityError::MissingEnv { variable, .. }) if variable == "TOKEN"
        ));
        let lenient = Expander::new(env(&[("SEG", "x")]), UnsetEnv::Placeholder);
        let request = case_with_placeholders().request(&lenient).unwrap();
        assert_eq!(request.spec.headers["authorization"], "Bearer unset-env");
        assert!(request.secrets.iter().all(|s| s == "x"));
    }

    #[test]
    fn unterminated_placeholder_is_an_error() {
        let mut case = case_with_placeholders();
        case.path = "/{{env:SEG".to_owned();
        let expander = Expander::new(env(&[("SEG", "x")]), UnsetEnv::Fail);
        assert!(matches!(
            case.request(&expander),
            Err(ParityError::UnterminatedPlaceholder { .. })
        ));
    }

    #[test]
    fn load_reads_yaml_files_sorted_and_ignores_others() {
        let dir = std::env::temp_dir().join(format!("apigw-parity-case-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("b.yaml"),
            "cases:\n  - {name: b-case, api: http, path: /b}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("a.yml"),
            "cases:\n  - {name: a-case, api: rest, path: /a}\n",
        )
        .unwrap();
        std::fs::write(dir.join("notes.txt"), "not yaml").unwrap();
        let set = CaseSet::load(&dir).unwrap();
        let names: Vec<_> = set.iter().map(|c| c.name.to_string()).collect();
        assert_eq!(names, ["a-case", "b-case"]);
        assert_eq!(set.for_api(ApiName::Http).count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_directory_is_an_io_error() {
        let dir =
            std::env::temp_dir().join(format!("apigw-parity-missing-{}", uuid::Uuid::now_v7()));
        assert!(matches!(CaseSet::load(&dir), Err(ParityError::Io { .. })));
    }
}
