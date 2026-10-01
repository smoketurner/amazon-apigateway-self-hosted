//! Runs the `apigw` binary as a subprocess serving a recorded export, with the
//! echo-backed integrations re-pointed at the in-process echo server.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};

use crate::case::ApiName;
use crate::client::Requester;
use crate::echo::LAMBDA_INVOKE_PATH;
use crate::error::{ParityError, Result};
use crate::export::ExportRecord;
use crate::fixture::write_json;

/// The stage variable the reference APIs use for the echo backend's host.
pub(crate) const ECHO_VARIABLE: &str = "echo_host";
const READY_POLL: Duration = Duration::from_millis(100);
const READY_ATTEMPTS: u32 = 300;
const LOG_TAIL_LINES: usize = 20;

/// A temporary directory removed when dropped.
#[derive(Debug)]
pub(crate) struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    pub(crate) fn create() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("apigw-parity-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&path).map_err(|e| ParityError::io(&path, e))?;
        Ok(Self { path })
    }

    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_dir_all(&self.path) {
            tracing::warn!(path = %self.path.display(), %err, "could not remove scratch directory");
        }
    }
}

/// A running `apigw` serving one API's export.
#[derive(Debug)]
pub(crate) struct ApigwProcess {
    child: Child,
    base_url: String,
    requester: Requester,
    scratch: ScratchDir,
}

impl ApigwProcess {
    /// Starts `binary` on loopback ports serving `export`, with echo-backed
    /// integrations re-pointed at `echo_authority`, and waits until it is healthy.
    ///
    /// # Errors
    /// Fails when the binary cannot be started, exits early, or does not become
    /// healthy in time; the error carries the tail of its log.
    pub(crate) async fn start(
        binary: &Path,
        api: ApiName,
        export: &ExportRecord,
        echo_authority: &str,
    ) -> Result<Self> {
        let scratch = ScratchDir::create()?;
        let certified = rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
        ])
        .map_err(|e| ParityError::Start {
            what: "certificate",
            reason: e.to_string(),
        })?;
        let cert_pem = certified.cert.pem();
        write_file(&scratch.join("tls.crt"), cert_pem.as_bytes())?;
        write_file(
            &scratch.join("tls.key"),
            certified.signing_key.serialize_pem().as_bytes(),
        )?;
        write_json(&scratch.join("export.json"), &export.openapi)?;
        let overrides = export.echo_overrides(ECHO_VARIABLE);
        if !overrides.is_empty() {
            write_json(&scratch.join("overrides.json"), &overrides)?;
        }

        let listen = free_port()?;
        let admin = free_port()?;
        let log = std::fs::File::create(scratch.join("apigw.log"))
            .map_err(|e| ParityError::io(scratch.join("apigw.log"), e))?;
        let log_err = log
            .try_clone()
            .map_err(|e| ParityError::io(scratch.join("apigw.log"), e))?;

        let mut command = Command::new(binary);
        command
            .arg("--openapi-file")
            .arg(scratch.join("export.json"))
            .args(["--api-type", api.api_type()])
            .args(["--stage", &export.stage])
            .arg("--base-path")
            .arg(format!("/{}", export.stage))
            .arg("--tls-cert")
            .arg(scratch.join("tls.crt"))
            .arg("--tls-key")
            .arg(scratch.join("tls.key"))
            .args(["--listen", &format!("127.0.0.1:{listen}")])
            .args(["--admin-listen", &format!("127.0.0.1:{admin}")])
            .args(["--refresh-seconds", "0", "--log-format", "text"])
            .args(["--integration-credentials", "gateway"]);
        for (name, value) in &export.stage_variables {
            if name != ECHO_VARIABLE {
                command
                    .arg("--stage-variable")
                    .arg(format!("{name}={value}"));
            }
        }
        command
            .arg("--stage-variable")
            .arg(format!("{ECHO_VARIABLE}={echo_authority}"));
        for function in export.lambda_functions() {
            command.arg("--lambda-endpoint").arg(format!(
                "{function}=http://{echo_authority}{LAMBDA_INVOKE_PATH}"
            ));
        }
        if !overrides.is_empty() {
            command
                .arg("--integration-overrides")
                .arg(scratch.join("overrides.json"));
        }
        command
            .env("AWS_REGION", "us-east-1")
            .env("AWS_ACCESS_KEY_ID", "parity")
            .env("AWS_SECRET_ACCESS_KEY", "parity")
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .kill_on_drop(true);
        let child = command.spawn().map_err(|e| ParityError::Start {
            what: "apigw",
            reason: format!("{}: {e}", binary.display()),
        })?;

        let requester = Requester::trusting(cert_pem.as_bytes())?;
        let mut process = Self {
            child,
            base_url: format!("https://127.0.0.1:{listen}"),
            requester,
            scratch,
        };
        process.wait_until_healthy(admin).await?;
        Ok(process)
    }

    /// The URL requests go to, including the stage prefix.
    pub(crate) fn base_url(&self, stage: &str) -> String {
        format!("{}/{stage}", self.base_url)
    }

    pub(crate) fn requester(&self) -> &Requester {
        &self.requester
    }

    async fn wait_until_healthy(&mut self, admin_port: u16) -> Result<()> {
        let url = format!("https://127.0.0.1:{admin_port}/healthz");
        for _ in 0..READY_ATTEMPTS {
            if let Some(status) = self.child.try_wait().map_err(|e| ParityError::Start {
                what: "apigw",
                reason: e.to_string(),
            })? {
                return Err(ParityError::Start {
                    what: "apigw",
                    reason: format!("exited with {status}: {}", self.log_tail()),
                });
            }
            if self.requester.probe(&url).await {
                return Ok(());
            }
            tokio::time::sleep(READY_POLL).await;
        }
        Err(ParityError::NotReady {
            seconds: READY_POLL
                .as_secs()
                .saturating_mul(u64::from(READY_ATTEMPTS)),
        })
    }

    fn log_tail(&self) -> String {
        let text = std::fs::read_to_string(self.scratch.join("apigw.log")).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(LOG_TAIL_LINES);
        lines.get(start..).unwrap_or_default().join("\n")
    }
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).map_err(|e| ParityError::io(path, e))
}

/// An unused loopback port. Another process could claim it before apigw binds, which
/// shows up as a startup failure, not as a wrong result.
fn free_port() -> Result<u16> {
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| ParityError::Start {
            what: "listener",
            reason: e.to_string(),
        })?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| ParityError::Start {
            what: "listener",
            reason: e.to_string(),
        })
}
