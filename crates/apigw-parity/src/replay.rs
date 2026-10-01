//! Replay: serves each recorded export with `apigw`, sends the same requests, and
//! diffs the responses against the fixtures.

use std::io::Write;
use std::path::PathBuf;

use crate::case::{ApiName, Case, CaseName, CaseSet, Expander, ProcessEnv, UnsetEnv};
use crate::compare::Mismatch;
use crate::echo::EchoServer;
use crate::error::{ParityError, Result};
use crate::export::ExportStore;
use crate::fixture::FixtureStore;
use crate::normalize::Normalizer;
use crate::process::ApigwProcess;

/// How one case came out.
#[derive(Debug)]
pub(crate) enum Outcome {
    Pass,
    Fail(Vec<Mismatch>),
    /// Differs from its fixture, as its `known_gap` says it should.
    KnownGap {
        issue: String,
    },
    /// Matches its fixture even though it is marked `known_gap`: the marker is stale.
    StaleGap {
        issue: String,
    },
    Error(String),
}

impl Outcome {
    pub(crate) fn is_failure(&self) -> bool {
        match self {
            Self::Fail(_) | Self::StaleGap { .. } | Self::Error(_) => true,
            Self::Pass | Self::KnownGap { .. } => false,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail(_) => "FAIL",
            Self::KnownGap { .. } => "GAP ",
            Self::StaleGap { .. } => "STALE",
            Self::Error(_) => "ERROR",
        }
    }

    /// Classifies a comparison of `case` against its fixture.
    fn from_diff(case: &Case, mismatches: Vec<Mismatch>) -> Self {
        match (case.known_gap.as_ref(), mismatches.is_empty()) {
            (None, true) => Self::Pass,
            (None, false) => Self::Fail(mismatches),
            (Some(issue), true) => Self::StaleGap {
                issue: issue.clone(),
            },
            (Some(issue), false) => Self::KnownGap {
                issue: issue.clone(),
            },
        }
    }

    /// Classifies an error while running `case`. A case that is a known gap may
    /// legitimately fail to produce what its fixture describes.
    fn from_error(case: &Case, error: &ParityError) -> Self {
        match (case.known_gap.as_ref(), error) {
            (Some(issue), ParityError::NotAnEcho { .. }) => Self::KnownGap {
                issue: issue.clone(),
            },
            (Some(_) | None, _) => Self::Error(error.to_string()),
        }
    }
}

#[derive(Debug)]
pub(crate) struct CaseResult {
    name: CaseName,
    outcome: Outcome,
}

/// The outcomes of a replay run.
#[derive(Debug, Default)]
pub(crate) struct ReplayReport {
    results: Vec<CaseResult>,
}

impl ReplayReport {
    pub(crate) fn failures(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.outcome.is_failure())
            .count()
    }

    /// Writes one line per case plus details for failures.
    ///
    /// # Errors
    /// Fails when `out` cannot be written.
    pub(crate) fn write(&self, out: &mut impl Write) -> std::io::Result<()> {
        for result in &self.results {
            let label = result.outcome.label();
            match &result.outcome {
                Outcome::Pass => writeln!(out, "{label} {}", result.name)?,
                Outcome::KnownGap { issue } => {
                    writeln!(out, "{label} {} (known gap {issue})", result.name)?;
                }
                Outcome::StaleGap { issue } => writeln!(
                    out,
                    "{label} {} matches its fixture, so known_gap {issue} should be removed",
                    result.name
                )?,
                Outcome::Fail(mismatches) => {
                    writeln!(out, "{label} {}", result.name)?;
                    for mismatch in mismatches {
                        writeln!(out, "       {mismatch}")?;
                    }
                }
                Outcome::Error(message) => writeln!(out, "{label} {}: {message}", result.name)?,
            }
        }
        let passed = self
            .results
            .iter()
            .filter(|r| matches!(r.outcome, Outcome::Pass))
            .count();
        let gaps = self
            .results
            .iter()
            .filter(|r| matches!(r.outcome, Outcome::KnownGap { .. }))
            .count();
        writeln!(
            out,
            "{} cases: {passed} passed, {gaps} known gaps, {} failed",
            self.results.len(),
            self.failures()
        )
    }
}

/// A replay run: which cases, fixtures, exports, and `apigw` binary to use.
#[derive(Debug)]
pub(crate) struct Replay {
    pub(crate) cases: CaseSet,
    pub(crate) fixtures: FixtureStore,
    pub(crate) exports: ExportStore,
    pub(crate) apigw: PathBuf,
}

impl Replay {
    /// Replays every case.
    ///
    /// # Errors
    /// Fails when an export is missing or `apigw` cannot be started. Per-case
    /// problems are reported as [`Outcome::Error`] instead.
    pub(crate) async fn run(&self) -> Result<ReplayReport> {
        let echo = EchoServer::start().await?;
        let normalizer = Normalizer::default();
        let expander = Expander::new(ProcessEnv, UnsetEnv::Placeholder);
        let mut report = ReplayReport::default();
        for api in ApiName::ALL {
            let cases: Vec<&Case> = self.cases.for_api(api).collect();
            if cases.is_empty() {
                continue;
            }
            let export = self.exports.load(api)?;
            let process = ApigwProcess::start(&self.apigw, api, &export, &echo.authority()).await?;
            let base_url = process.base_url(&export.stage);
            for case in cases {
                let outcome = self
                    .run_case(case, &base_url, &process, &normalizer, &expander)
                    .await;
                report.results.push(CaseResult {
                    name: case.name.clone(),
                    outcome: match outcome {
                        Ok(outcome) => outcome,
                        Err(error) => Outcome::from_error(case, &error),
                    },
                });
            }
        }
        Ok(report)
    }

    async fn run_case(
        &self,
        case: &Case,
        base_url: &str,
        process: &ApigwProcess,
        normalizer: &Normalizer,
        expander: &Expander<ProcessEnv>,
    ) -> Result<Outcome> {
        let fixture = self.fixtures.load(&case.name)?;
        let request = case.request(expander)?;
        let raw = process
            .requester()
            .send(&case.name, base_url, &request.spec)
            .await?;
        let actual = normalizer.observe(case, &raw)?;
        let mismatches = case.compare.diff(&fixture.observation, &actual);
        Ok(Outcome::from_diff(case, mismatches))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    fn case(known_gap: Option<&str>) -> Case {
        let mut case: Case = serde_saphyr::from_str("name: c\napi: rest\npath: /x\n").unwrap();
        case.known_gap = known_gap.map(str::to_owned);
        case
    }

    fn mismatch() -> Vec<Mismatch> {
        let a = crate::fixture::Observation {
            response: crate::fixture::Observed {
                status: 200,
                ..Default::default()
            },
            echo: None,
        };
        let mut b = a.clone();
        b.response.status = 500;
        crate::case::Compare::default().diff(&a, &b)
    }

    #[test]
    fn outcomes_follow_known_gap_markers() {
        assert!(matches!(
            Outcome::from_diff(&case(None), vec![]),
            Outcome::Pass
        ));
        assert!(Outcome::from_diff(&case(None), mismatch()).is_failure());
        let gap = Outcome::from_diff(&case(Some("#9")), mismatch());
        assert!(matches!(gap, Outcome::KnownGap { .. }) && !gap.is_failure());
        let stale = Outcome::from_diff(&case(Some("#9")), vec![]);
        assert!(matches!(stale, Outcome::StaleGap { .. }) && stale.is_failure());
    }

    #[test]
    fn only_a_missing_echo_is_forgiven_for_known_gaps() {
        let not_echo = ParityError::NotAnEcho {
            case: case(None).name,
            reason: "x".to_owned(),
        };
        assert!(matches!(
            Outcome::from_error(&case(Some("#9")), &not_echo),
            Outcome::KnownGap { .. }
        ));
        assert!(Outcome::from_error(&case(None), &not_echo).is_failure());
        let missing = ParityError::MissingFixture(case(None).name);
        assert!(Outcome::from_error(&case(Some("#9")), &missing).is_failure());
    }

    #[test]
    fn report_lists_every_case_and_counts_failures() {
        let report = ReplayReport {
            results: vec![
                CaseResult {
                    name: case(None).name,
                    outcome: Outcome::Pass,
                },
                CaseResult {
                    name: case(None).name,
                    outcome: Outcome::Fail(mismatch()),
                },
                CaseResult {
                    name: case(None).name,
                    outcome: Outcome::KnownGap {
                        issue: "#9".to_owned(),
                    },
                },
            ],
        };
        let mut out = Vec::new();
        report.write(&mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("PASS c"));
        assert!(text.contains("response.status: expected 200, got 500"));
        assert!(text.contains("known gap #9"));
        assert!(text.ends_with("3 cases: 1 passed, 1 known gaps, 1 failed\n"));
        assert_eq!(report.failures(), 1);
    }
}
