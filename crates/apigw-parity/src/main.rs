//! Dev tool that measures `apigw` against real Amazon API Gateway: `record` captures
//! the reference APIs' behavior as fixtures, `replay` checks `apigw` against them.

mod case;
mod client;
mod compare;
mod echo;
mod error;
mod export;
mod fixture;
mod normalize;
mod outputs;
mod process;
mod record;
mod replay;

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::case::CaseSet;
use crate::export::{ExportInput, ExportStore};
use crate::fixture::FixtureStore;
use crate::outputs::RunnerOutputs;
use crate::record::Record;
use crate::replay::Replay;

const APIGW_BINARY: &str = "apigw";

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Send every case to the deployed reference APIs and store fixtures.
    Record(RecordArgs),
    /// Serve the recorded exports with apigw and diff its responses against the fixtures.
    Replay(ReplayArgs),
}

#[derive(Debug, Args)]
struct RecordArgs {
    /// `terraform output -json parity_runner` for the deployed stack.
    #[arg(long, default_value = "parity/outputs.json")]
    outputs: PathBuf,
    /// Directory of case YAML files.
    #[arg(long, default_value = "parity/cases")]
    cases: PathBuf,
    /// Directory that receives `fixtures/` and `exports/`.
    #[arg(long, default_value = "parity")]
    out: PathBuf,
    /// Directory with downloaded `<api>.openapi.json` (and optional `<api>.stage.json`)
    /// files; without it, exports are not recorded.
    #[arg(long)]
    export_dir: Option<PathBuf>,
    /// A parity directory whose `fixtures/` the recording is compared against.
    #[arg(long, requires = "drift_report")]
    baseline: Option<PathBuf>,
    /// Where to write a Markdown drift report; created only when drift is found.
    #[arg(long, requires = "baseline")]
    drift_report: Option<PathBuf>,
    /// Environment variable whose value must never appear in fixtures (repeatable).
    #[arg(long = "secret-env", value_name = "NAME")]
    secret_env: Vec<String>,
    /// Pause between requests, to stay under API Gateway throttles.
    #[arg(long, default_value_t = 250)]
    delay_ms: u64,
}

#[derive(Debug, Args)]
struct ReplayArgs {
    /// Directory of case YAML files.
    #[arg(long, default_value = "parity/cases")]
    cases: PathBuf,
    /// Directory holding `fixtures/` and `exports/`.
    #[arg(long, default_value = "parity")]
    dir: PathBuf,
    /// The apigw binary; defaults to the one next to this executable.
    #[arg(long)]
    apigw: Option<PathBuf>,
}

impl RecordArgs {
    async fn run(self) -> anyhow::Result<()> {
        let record = Record {
            outputs: RunnerOutputs::load(&self.outputs).context("reading Terraform outputs")?,
            cases: CaseSet::load(&self.cases).context("loading cases")?,
            fixtures: FixtureStore::new(self.out.join("fixtures")),
            exports: ExportStore::new(self.out.join("exports")),
            export_input: self.export_dir.map(ExportInput::new),
            baseline: self
                .baseline
                .map(|dir| FixtureStore::new(dir.join("fixtures"))),
            secret_env: self.secret_env,
            delay: Duration::from_millis(self.delay_ms),
        };
        let drift = record.run().await.context("recording")?;
        if let Some(path) = self.drift_report
            && !drift.is_empty()
        {
            let mut file = std::fs::File::create(&path)
                .with_context(|| format!("creating {}", path.display()))?;
            drift
                .write_markdown(&mut file)
                .context("writing the drift report")?;
            tracing::warn!(cases = drift.len(), report = %path.display(), "recorded behavior drifted from the baseline");
        }
        Ok(())
    }
}

impl ReplayArgs {
    async fn run(self) -> anyhow::Result<()> {
        let apigw = match self.apigw {
            Some(path) => path,
            None => std::env::current_exe()
                .context("locating this executable")?
                .with_file_name(APIGW_BINARY),
        };
        let replay = Replay {
            cases: CaseSet::load(&self.cases).context("loading cases")?,
            fixtures: FixtureStore::new(self.dir.join("fixtures")),
            exports: ExportStore::new(self.dir.join("exports")),
            apigw,
        };
        let report = replay.run().await.context("replaying")?;
        report
            .write(&mut std::io::stdout().lock())
            .context("writing the report")?;
        match report.failures() {
            0 => Ok(()),
            failures => Err(error::ParityError::Mismatches(failures).into()),
        }
    }
}

fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("default crypto provider already installed"))?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        match cli.command {
            Command::Record(args) => args.run().await,
            Command::Replay(args) => args.run().await,
        }
    })?;
    std::io::stdout().flush().context("flushing stdout")
}
