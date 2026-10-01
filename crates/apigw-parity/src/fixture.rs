//! Normalized fixtures: what API Gateway (or a hand-written expectation of it)
//! answered for a case, and what the echo backend received.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::case::{ApiName, CaseName};
use crate::echo::EchoReceived;
use crate::error::{ParityError, Result};

/// Where a fixture's contents came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FixtureSource {
    /// Captured from a deployed reference API by `apigw-parity record`.
    Recorded,
    /// Written by hand from documented API Gateway behavior and not yet
    /// confirmed by a recording; the nightly recording confirms or corrects it.
    HandWritten,
}

/// A normalized HTTP response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Observed {
    pub(crate) status: u16,
    #[serde(default)]
    pub(crate) headers: BTreeMap<String, String>,
    /// The body as text; absent for an empty or non-UTF-8 body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) body: Option<String>,
    /// The body as base64 when it is not valid UTF-8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) body_base64: Option<String>,
}

impl Observed {
    /// Splits `bytes` into the text or base64 field, whichever represents it.
    pub(crate) fn with_body(mut self, bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok("") => {}
            Ok(text) => self.body = Some(text.to_owned()),
            Err(_) => {
                self.body_base64 = Some(base64::engine::general_purpose::STANDARD.encode(bytes));
            }
        }
        self
    }

    /// The body as one comparable string.
    pub(crate) fn body_text(&self) -> &str {
        self.body
            .as_deref()
            .or(self.body_base64.as_deref())
            .unwrap_or("")
    }
}

/// The comparable result of one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Observation {
    pub(crate) response: Observed,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) echo: Option<EchoReceived>,
}

/// A stored [`Observation`] for one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Fixture {
    pub(crate) name: CaseName,
    pub(crate) source: FixtureSource,
    pub(crate) api: ApiName,
    #[serde(flatten)]
    pub(crate) observation: Observation,
}

/// A directory of `<case>.json` fixture files.
#[derive(Debug, Clone)]
pub(crate) struct FixtureStore {
    dir: PathBuf,
}

impl FixtureStore {
    pub(crate) fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, name: &CaseName) -> PathBuf {
        self.dir.join(format!("{name}.json"))
    }

    /// Reads the fixture for `name`.
    ///
    /// # Errors
    /// [`ParityError::MissingFixture`] when the file does not exist; other I/O and
    /// JSON errors when it cannot be read or parsed.
    pub(crate) fn load(&self, name: &CaseName) -> Result<Fixture> {
        let path = self.path(name);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ParityError::MissingFixture(name.clone()));
            }
            Err(e) => return Err(ParityError::io(path, e)),
        };
        serde_json::from_str(&text).map_err(|source| ParityError::Json { path, source })
    }

    /// Writes `fixture` as pretty JSON, creating the directory if needed.
    ///
    /// # Errors
    /// Fails when the directory or file cannot be written.
    pub(crate) fn save(&self, fixture: &Fixture) -> Result<()> {
        write_json(&self.path(&fixture.name), fixture)
    }
}

/// Writes `value` as pretty JSON with a trailing newline, creating parent directories.
pub(crate) fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ParityError::io(parent, e))?;
    }
    let mut text = serde_json::to_string_pretty(value).map_err(|source| ParityError::Json {
        path: path.to_owned(),
        source,
    })?;
    text.push('\n');
    std::fs::write(path, text).map_err(|e| ParityError::io(path, e))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    fn name(text: &str) -> CaseName {
        CaseName::try_from(text.to_owned()).unwrap()
    }

    fn sample() -> Fixture {
        Fixture {
            name: name("sample"),
            source: FixtureSource::HandWritten,
            api: ApiName::Rest,
            observation: Observation {
                response: Observed {
                    status: 200,
                    headers: BTreeMap::from([("content-type".to_owned(), "text/plain".to_owned())]),
                    ..Observed::default()
                }
                .with_body(b"hello"),
                echo: None,
            },
        }
    }

    #[test]
    fn body_is_text_base64_or_absent() {
        assert_eq!(Observed::default().with_body(b"").body_text(), "");
        let text = Observed::default().with_body("héllo".as_bytes());
        assert_eq!(text.body.as_deref(), Some("héllo"));
        let binary = Observed::default().with_body(&[0xff, 0x00, 0xfe]);
        assert_eq!(binary.body, None);
        assert_eq!(binary.body_base64.as_deref(), Some("/wD+"));
        assert_eq!(binary.body_text(), "/wD+");
    }

    #[test]
    fn fixtures_round_trip_through_the_store() {
        let dir =
            std::env::temp_dir().join(format!("apigw-parity-fixture-{}", uuid::Uuid::now_v7()));
        let store = FixtureStore::new(dir.join("nested"));
        let fixture = sample();
        store.save(&fixture).unwrap();
        assert_eq!(store.load(&fixture.name).unwrap(), fixture);
        let text = std::fs::read_to_string(dir.join("nested/sample.json")).unwrap();
        assert!(text.ends_with("}\n"));
        assert!(text.contains("\"source\": \"hand_written\""));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_and_corrupt_fixtures_are_distinct_errors() {
        let dir =
            std::env::temp_dir().join(format!("apigw-parity-fixture-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = FixtureStore::new(&dir);
        assert!(matches!(
            store.load(&name("absent")),
            Err(ParityError::MissingFixture(_))
        ));
        std::fs::write(dir.join("bad.json"), "{not json").unwrap();
        assert!(matches!(
            store.load(&name("bad")),
            Err(ParityError::Json { .. })
        ));
        std::fs::write(dir.join("extra.json"), r#"{"name":"extra","source":"recorded","api":"rest","response":{"status":1,"surprise":true}}"#).unwrap();
        assert!(matches!(
            store.load(&name("extra")),
            Err(ParityError::Json { .. })
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
