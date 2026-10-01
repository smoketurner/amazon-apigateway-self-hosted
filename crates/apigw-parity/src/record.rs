//! Record: sends every case to the deployed reference APIs, stores normalized
//! fixtures and the redacted exports, and reports drift from a baseline.

use std::io::Write;
use std::time::Duration;

use crate::case::{ApiName, CaseName, CaseSet, Compare, Expander, ProcessEnv, UnsetEnv};
use crate::client::Requester;
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
}

impl Record {
    /// Records every case and export.
    ///
    /// # Errors
    /// Fails when a request cannot be made, a case needs an unset environment
    /// variable, or a file cannot be written.
    pub(crate) async fn run(&self) -> Result<DriftReport> {
        let global_secrets = self.global_secrets();
        let requester = Requester::new()?;
        let expander = Expander::new(ProcessEnv, UnsetEnv::Fail);
        let mut drift = DriftReport::default();
        for (index, case) in self.cases.iter().enumerate() {
            if index > 0 {
                tokio::time::sleep(self.delay).await;
            }
            let request = case.request(&expander)?;
            let base_url = self.outputs.base_url(case.api)?;
            let raw = requester.send(&case.name, base_url, &request.spec).await?;
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
        for api in ApiName::ALL {
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
        }
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
        assert!(record(None).global_secrets().is_empty());
    }
}
