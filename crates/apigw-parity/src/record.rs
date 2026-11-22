//! Record: sends every case to the deployed reference APIs, stores normalized
//! fixtures and the redacted exports, and reports drift from a baseline.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::case::{
    ApiName, Case, CaseName, CaseSet, ClientCert, Compare, Expander, ProcessEnv, UnsetEnv,
};
use crate::client::{ClientOptions, Requester};
use crate::compare::Mismatch;
use crate::error::{ParityError, Result};
use crate::export::{ExportInput, ExportStore};
use crate::fixture::{Fixture, FixtureSource, FixtureStore};
use crate::normalize::{Normalizer, Redactor};
use crate::outputs::RunnerOutputs;

/// A recorded case that no longer matches the baseline fixture.
#[derive(Debug)]
pub(crate) struct Drift {
    case: CaseName,
    kind: DriftKind,
}

#[derive(Debug)]
enum DriftKind {
    Changed(Vec<Mismatch>),
    NoBaseline,
    /// No response at all, such as a connection closed in the TLS handshake.
    RequestFailed(String),
    /// A response to a case that expects none.
    UnexpectedResponse(u16),
}

/// The cases whose recorded behavior differs from the baseline.
#[derive(Debug, Default)]
pub(crate) struct DriftReport {
    entries: Vec<Drift>,
}

impl DriftReport {
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Writes the report as Markdown, suitable for an issue body.
    ///
    /// # Errors
    /// Fails when `out` cannot be written.
    pub(crate) fn write_markdown(&self, out: &mut impl Write) -> std::io::Result<()> {
        writeln!(
            out,
            "API Gateway answered {} case(s) differently from the committed fixtures.\n",
            self.entries.len()
        )?;
        for entry in &self.entries {
            writeln!(out, "### `{}`\n", entry.case)?;
            match &entry.kind {
                DriftKind::NoBaseline => {
                    writeln!(out, "No committed fixture exists for this case.\n")?;
                }
                DriftKind::Changed(mismatches) => {
                    for mismatch in mismatches {
                        writeln!(out, "- {mismatch}")?;
                    }
                    writeln!(out)?;
                }
                DriftKind::RequestFailed(reason) => {
                    writeln!(out, "The request got no response: {reason}\n")?;
                }
                DriftKind::UnexpectedResponse(status) => {
                    writeln!(out, "Expected no response, got {status}.\n")?;
                }
            }
        }
        Ok(())
    }
}

/// A record run.
#[derive(Debug)]
pub(crate) struct Record {
    pub(crate) outputs: RunnerOutputs,
    pub(crate) cases: CaseSet,
    pub(crate) fixtures: FixtureStore,
    pub(crate) exports: ExportStore,
    pub(crate) export_input: Option<ExportInput>,
    pub(crate) baseline: Option<FixtureStore>,
    pub(crate) secret_env: Vec<String>,
    pub(crate) delay: Duration,
    /// Address overrides and certificate checks shared by every request.
    pub(crate) client: ClientOptions,
    /// The client certificates mutual TLS cases present.
    pub(crate) client_certs: Option<ClientCerts>,
}

/// `terraform output -json parity_client_certificates`: PEM certificates and keys.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ClientCerts {
    trusted_cert: String,
    trusted_key: String,
    stranger_cert: String,
    stranger_key: String,
}

impl ClientCerts {
    /// Reads the certificates file.
    ///
    /// # Errors
    /// Fails when the file cannot be read or is not the expected JSON.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| ParityError::io(path, e))?;
        serde_json::from_str(&text).map_err(|source| ParityError::Json {
            path: path.to_owned(),
            source,
        })
    }

    fn identity(&self, which: ClientCert) -> Vec<u8> {
        let (cert, key) = match which {
            ClientCert::Trusted => (&self.trusted_cert, &self.trusted_key),
            ClientCert::Stranger => (&self.stranger_cert, &self.stranger_key),
        };
        format!("{cert}\n{key}").into_bytes()
    }
}

/// One client per certificate a case can present.
struct Requesters {
    plain: Requester,
    with_cert: BTreeMap<ClientCert, Requester>,
}

impl Requesters {
    fn new(options: &ClientOptions, certs: Option<&ClientCerts>) -> Result<Self> {
        let mut with_cert = BTreeMap::new();
        if let Some(certs) = certs {
            for which in [ClientCert::Trusted, ClientCert::Stranger] {
                let options = ClientOptions {
                    identity: Some(certs.identity(which)),
                    ..options.clone()
                };
                with_cert.insert(which, Requester::with_options(&options)?);
            }
        }
        Ok(Self {
            plain: Requester::with_options(options)?,
            with_cert,
        })
    }

    fn for_case(&self, case: &Case) -> Result<&Requester> {
        match case.client_cert {
            None => Ok(&self.plain),
            Some(which) => self
                .with_cert
                .get(&which)
                .ok_or(ParityError::MissingClientCert(which)),
        }
    }
}

impl Record {
    /// Records every case and export.
    ///
    /// # Errors
    /// Fails when a request cannot be made, a case needs an unset environment
    /// variable, or a file cannot be written.
    pub(crate) async fn run(&self) -> Result<DriftReport> {
        let global_secrets = self.global_secrets();
        let requesters = Requesters::new(&self.client, self.client_certs.as_ref())?;
        let expander = Expander::new(ProcessEnv, UnsetEnv::Fail);
        let mut drift = DriftReport::default();
        for (index, case) in self.cases.iter().enumerate() {
            if index > 0 {
                tokio::time::sleep(self.delay).await;
            }
            let request = case.request(&expander)?;
            let base_url = self.outputs.base_url(case.api)?;
            let raw = match requesters
                .for_case(case)?
                .send(&case.name, base_url, &request.spec)
                .await
            {
                Ok(raw) if case.no_response => {
                    drift.entries.push(Drift {
                        case: case.name.clone(),
                        kind: DriftKind::UnexpectedResponse(raw.status),
                    });
                    continue;
                }
                Ok(raw) => raw,
                Err(ParityError::Request { .. }) if case.no_response => {
                    tracing::info!(case = %case.name, "got no response, as expected");
                    continue;
                }
                // One case without a response (a refused handshake) does not
                // stop the rest; it is reported, and no fixture is written.
                Err(ParityError::Request { source, .. }) => {
                    let reason = std::error::Error::source(&source)
                        .map_or_else(|| source.to_string(), |cause| format!("{source}: {cause}"));
                    tracing::warn!(case = %case.name, reason, "request failed");
                    drift.entries.push(Drift {
                        case: case.name.clone(),
                        kind: DriftKind::RequestFailed(reason),
                    });
                    continue;
                }
                Err(err) => return Err(err),
            };
            let redactor = Redactor::new(global_secrets.iter().cloned().chain(request.secrets));
            let observation = Normalizer::new(redactor).observe(case, &raw)?;
            let fixture = Fixture {
                name: case.name.clone(),
                source: FixtureSource::Recorded,
                api: case.api,
                observation,
            };
            if let Some(ref baseline) = self.baseline {
                Self::check_drift(&case.compare, baseline, &fixture, &mut drift);
            }
            self.fixtures.save(&fixture)?;
            tracing::info!(case = %case.name, status = fixture.observation.response.status, "recorded");
        }
        self.record_exports(&Redactor::new(global_secrets))?;
        Ok(drift)
    }

    fn check_drift(
        compare: &Compare,
        baseline: &FixtureStore,
        recorded: &Fixture,
        drift: &mut DriftReport,
    ) {
        let kind = match baseline.load(&recorded.name) {
            Ok(expected) => {
                let mismatches = compare.diff(&expected.observation, &recorded.observation);
                if mismatches.is_empty() {
                    return;
                }
                DriftKind::Changed(mismatches)
            }
            Err(ParityError::MissingFixture(_)) => DriftKind::NoBaseline,
            Err(err) => {
                tracing::warn!(case = %recorded.name, %err, "baseline fixture unreadable; counting as drift");
                DriftKind::NoBaseline
            }
        };
        drift.entries.push(Drift {
            case: recorded.name.clone(),
            kind,
        });
    }

    /// The values of the `--secret-env` variables that are set.
    fn global_secrets(&self) -> Vec<String> {
        self.secret_env
            .iter()
            .filter_map(|name| std::env::var(name).ok())
            .collect()
    }

    fn record_exports(&self, redactor: &Redactor) -> Result<()> {
        let Some(ref input) = self.export_input else {
            tracing::info!("no export directory given; exports were not recorded");
            return Ok(());
        };
        for api in ApiName::EXPORTED {
            let recorded = input.record(
                api,
                &self.outputs.stage,
                &self.outputs.stage_variables,
                redactor,
            )?;
            if let Some(record) = recorded {
                self.exports.save(&record)?;
                tracing::info!(%api, "recorded export");
            } else {
                tracing::warn!(%api, "no downloaded export found");
            }
        }
        Ok(())
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
    use crate::echo::EchoServer;
    use crate::fixture::{Observation, Observed};

    fn fixture(status: u16) -> Fixture {
        Fixture {
            name: CaseName::try_from("c".to_owned()).unwrap(),
            source: FixtureSource::Recorded,
            api: ApiName::Rest,
            observation: Observation {
                response: Observed {
                    status,
                    ..Observed::default()
                },
                echo: None,
            },
        }
    }

    fn record(baseline: Option<FixtureStore>) -> Record {
        Record {
            outputs: serde_json::from_str(
                r#"{"stage":"ref","rest":{"base_url":"u"},"rest_policy":{"base_url":"u"},"http":{"base_url":"u"}}"#,
            )
            .unwrap(),
            cases: CaseSet::from_cases(Vec::new()).unwrap(),
            fixtures: FixtureStore::new("unused"),
            exports: ExportStore::new("unused"),
            export_input: None,
            baseline,
            secret_env: vec!["APIGW_PARITY_TEST_UNSET_VARIABLE".to_owned()],
            delay: Duration::ZERO,
            client: ClientOptions::default(),
            client_certs: None,
        }
    }

    #[test]
    fn client_certificates_join_cert_and_key_and_must_be_given() {
        let certs: ClientCerts = serde_json::from_str(
            r#"{"trusted_cert":"C1","trusted_key":"K1","stranger_cert":"C2","stranger_key":"K2"}"#,
        )
        .unwrap();
        assert_eq!(certs.identity(ClientCert::Stranger), b"C2\nK2");
        let case: Case =
            serde_saphyr::from_str("name: m\napi: domain_mtls\npath: /x\nclient_cert: trusted\n")
                .unwrap();
        let requesters = Requesters::new(&ClientOptions::default(), None).unwrap();
        assert!(matches!(
            requesters.for_case(&case),
            Err(ParityError::MissingClientCert(ClientCert::Trusted))
        ));
    }

    #[test]
    fn drift_distinguishes_changed_missing_and_unchanged() {
        let dir = std::env::temp_dir().join(format!("apigw-parity-drift-{}", uuid::Uuid::now_v7()));
        let baseline = FixtureStore::new(&dir);
        baseline.save(&fixture(200)).unwrap();
        let mut drift = DriftReport::default();

        Record::check_drift(&Compare::default(), &baseline, &fixture(200), &mut drift);
        assert!(drift.is_empty());

        Record::check_drift(&Compare::default(), &baseline, &fixture(500), &mut drift);
        assert_eq!(drift.len(), 1);

        let mut other = fixture(200);
        other.name = CaseName::try_from("other".to_owned()).unwrap();
        Record::check_drift(&Compare::default(), &baseline, &other, &mut drift);
        assert_eq!(drift.len(), 2);

        let mut markdown = Vec::new();
        drift.write_markdown(&mut markdown).unwrap();
        let markdown = String::from_utf8(markdown).unwrap();
        assert!(markdown.contains("differently from the committed fixtures"));
        assert!(markdown.contains("response.status: expected 200, got 500"));
        assert!(markdown.contains("No committed fixture exists"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn records_fixtures_and_exports_from_a_live_endpoint() {
        let echo = EchoServer::start().await.unwrap();
        let dir =
            std::env::temp_dir().join(format!("apigw-parity-record-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(dir.join("cases")).unwrap();
        std::fs::create_dir_all(dir.join("downloads")).unwrap();
        std::fs::write(
            dir.join("cases/c.yaml"),
            "cases:
  - name: echo-case
    api: rest
    path: /p/q
    query: {a: '1'}
    headers: {x-secret-header: '{{env:PATH}}'}
    compare:
      headers: [content-type]
      body: ignore
      echo: {headers: [x-secret-header]}
",
        )
        .unwrap();
        std::fs::write(
            dir.join("downloads/rest.openapi.json"),
            r#"{"paths":{"/x":{"get":{"x-amazon-apigateway-integration":{"uri":"arn:aws:lambda:us-east-1:123456789012:function:f"}}}}}"#,
        )
        .unwrap();
        let base = format!("http://{}", echo.authority());
        let endpoint = serde_json::json!({"base_url": base});
        let outputs = serde_json::json!({"stage": "ref", "rest": endpoint, "rest_policy": endpoint, "http": endpoint});
        let mut record = record(None);
        record.outputs = serde_json::from_value(outputs).unwrap();
        record.cases = CaseSet::load(&dir.join("cases")).unwrap();
        record.fixtures = FixtureStore::new(dir.join("out/fixtures"));
        record.exports = ExportStore::new(dir.join("out/exports"));
        record.export_input = Some(ExportInput::new(dir.join("downloads")));
        let stale = FixtureStore::new(dir.join("baseline"));
        let mut old = fixture(500);
        old.name = CaseName::try_from("echo-case".to_owned()).unwrap();
        stale.save(&old).unwrap();
        record.baseline = Some(stale);

        let drift = record.run().await.unwrap();

        let recorded = record
            .fixtures
            .load(&CaseName::try_from("echo-case".to_owned()).unwrap())
            .unwrap();
        assert_eq!(recorded.source, FixtureSource::Recorded);
        assert_eq!(recorded.observation.response.status, 200);
        let echoed = recorded.observation.echo.unwrap();
        assert_eq!(echoed.path, "/p/q");
        assert_eq!(echoed.query, "a=1");
        assert_eq!(echoed.headers["x-secret-header"], "[redacted]");
        let export = record.exports.load(ApiName::Rest).unwrap();
        assert!(!export.openapi.to_string().contains("123456789012"));
        assert!(matches!(
            record.exports.load(ApiName::Http),
            Err(ParityError::MissingExport(_))
        ));
        assert_eq!(drift.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unset_secret_environment_variables_are_skipped() {
        assert_eq!(record(None).global_secrets(), Vec::<String>::new());
    }
}
