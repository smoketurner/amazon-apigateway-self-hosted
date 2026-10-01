//! A self-hosted Amazon API Gateway: downloads an existing REST or HTTP API's
//! definition and serves its routes from a single binary.

mod app;
mod aws;
mod config;
mod gateway;
mod identity;
mod integration;
mod lambda;
mod listener;
mod model;
mod pipeline;
mod proxy;
mod route;
mod router;
mod source;

use clap::Parser as _;
use tracing_subscriber::EnvFilter;

use crate::config::{Config, LogFormat};

fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("default crypto provider already installed"))?;

    let config = Config::parse();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match config.log_format {
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
        LogFormat::Text => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(app::run(config))
}
