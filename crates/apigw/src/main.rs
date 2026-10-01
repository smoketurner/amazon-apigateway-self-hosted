//! A self-hosted Amazon API Gateway: downloads an existing REST or HTTP API's
//! definition and serves its routes from a single binary.

mod app;
mod authz;
mod aws;
mod canary;
mod config;
mod cors;
mod entropy;
mod gateway;
mod gateway_response;
mod http_routes;
mod identity;
mod integration;
mod lambda;
mod listener;
mod mapping;
mod model;
mod observability;
mod pipeline;
mod proxy;
mod route;
mod router;
mod source;
mod state;
mod throttle;

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
