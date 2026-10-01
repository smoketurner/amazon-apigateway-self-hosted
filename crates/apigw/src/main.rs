//! A self-hosted Amazon API Gateway: downloads an existing REST or HTTP API's
//! definition and serves its routes from a single binary.

mod app;
mod authz;
mod aws;
mod backoff;
mod cache;
mod canary;
mod client_cert;
mod config;
mod cors;
mod digest;
mod domain;
mod entropy;
mod gateway;
mod gateway_response;
mod header_case;
mod header_policy;
mod http_routes;
mod identity;
mod integration;
mod integration_tls;
mod lambda;
mod lambda_response;
mod limits;
mod listener;
mod mapped;
mod mapping;
mod model;
mod observability;
mod payload;
mod pipeline;
mod proxy;
mod route;
mod router;
mod source;
mod state;
mod throttle;
mod usage;
mod validation;
mod vpc_link;

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
