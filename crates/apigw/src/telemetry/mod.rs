//! OpenTelemetry and Prometheus: the gateway's own metrics, request spans, and
//! their exporters.
//!
//! Metrics always reach the Prometheus registry served at `/metrics` on the
//! admin listener. With `--otel`, metrics and spans are also exported over
//! OTLP (or spans written to standard output), configured with the standard
//! `OTEL_*` environment variables.

mod metrics;
mod resource;
mod span;
mod stdout;

use std::time::Duration;

use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithTonicConfig as _;
use opentelemetry_sdk::metrics::{MeterProviderBuilder, PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;

pub(crate) use metrics::{
    ApiStage, GatewayMetrics, Outcome, RefreshOutcome, RequestLabels, RequestOutcome,
};
#[cfg(test)]
pub(crate) use span::tests as span_tests;
pub(crate) use span::{ChildSpan, RequestSpan, RequestTracer, ServerRequest, SpanTarget};

/// Where spans are exported, from `OTEL_TRACES_EXPORTER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TracesExporter {
    Otlp,
    /// One JSON object per span on standard output.
    Console,
    None,
}

/// Where metrics are exported besides Prometheus, from `OTEL_METRICS_EXPORTER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetricsExporter {
    Otlp,
    None,
}

/// The OTLP transport, from `OTEL_EXPORTER_OTLP_PROTOCOL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    HttpProtobuf,
    Grpc,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum SettingsError {
    #[error("{name}={value:?} is not supported; use {supported}")]
    Unsupported {
        name: &'static str,
        value: String,
        supported: &'static str,
    },
}

/// What `--otel` and the `OTEL_*` environment variables ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OtelSettings {
    pub(crate) enabled: bool,
    pub(crate) traces: TracesExporter,
    pub(crate) metrics: MetricsExporter,
    pub(crate) traces_protocol: Protocol,
    pub(crate) metrics_protocol: Protocol,
}

impl OtelSettings {
    pub(crate) fn disabled() -> Self {
        Self {
            enabled: false,
            traces: TracesExporter::None,
            metrics: MetricsExporter::None,
            traces_protocol: Protocol::HttpProtobuf,
            metrics_protocol: Protocol::HttpProtobuf,
        }
    }

    /// Reads the exporter and protocol variables through `env`. The endpoint,
    /// headers, timeout, sampler, and resource variables are read by the
    /// exporters and [`resource::Attributes`] themselves.
    ///
    /// # Errors
    ///
    /// When a variable names an exporter or protocol this gateway does not ship.
    pub(crate) fn from_env(
        enabled: bool,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, SettingsError> {
        if !enabled {
            return Ok(Self::disabled());
        }
        let traces = match env("OTEL_TRACES_EXPORTER").as_deref().map(str::trim) {
            None | Some("" | "otlp") => TracesExporter::Otlp,
            Some("console") => TracesExporter::Console,
            Some("none") => TracesExporter::None,
            Some(other) => {
                return Err(SettingsError::Unsupported {
                    name: "OTEL_TRACES_EXPORTER",
                    value: other.to_owned(),
                    supported: "otlp, console, or none",
                });
            }
        };
        let metrics = match env("OTEL_METRICS_EXPORTER").as_deref().map(str::trim) {
            None | Some("" | "otlp") => MetricsExporter::Otlp,
            Some("none") => MetricsExporter::None,
            Some(other) => {
                return Err(SettingsError::Unsupported {
                    name: "OTEL_METRICS_EXPORTER",
                    value: other.to_owned(),
                    supported: "otlp or none (Prometheus is always served on /metrics)",
                });
            }
        };
        let protocol = |name: &'static str| -> Result<Option<Protocol>, SettingsError> {
            match env(name).as_deref().map(str::trim) {
                None | Some("") => Ok(None),
                Some("http/protobuf") => Ok(Some(Protocol::HttpProtobuf)),
                Some("grpc") => Ok(Some(Protocol::Grpc)),
                Some(other) => Err(SettingsError::Unsupported {
                    name,
                    value: other.to_owned(),
                    supported: "http/protobuf or grpc",
                }),
            }
        };
        let general = protocol("OTEL_EXPORTER_OTLP_PROTOCOL")?.unwrap_or(Protocol::HttpProtobuf);
        Ok(Self {
            enabled,
            traces,
            metrics,
            traces_protocol: protocol("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")?.unwrap_or(general),
            metrics_protocol: protocol("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL")?.unwrap_or(general),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum TelemetryError {
    #[error("failed to set up the Prometheus registry: {0}")]
    Prometheus(String),
    #[error("failed to set up the OTLP exporter: {0}")]
    Otlp(#[from] opentelemetry_otlp::ExporterBuildError),
}

/// The Prometheus registry `/metrics` renders. Cheap to clone.
#[derive(Debug, Clone, Default)]
pub(crate) struct PrometheusRegistry(prometheus::Registry);

impl PrometheusRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// A meter provider builder whose metrics this registry serves.
    ///
    /// # Errors
    ///
    /// When the exporter cannot be registered.
    pub(crate) fn meter_provider_builder(&self) -> Result<MeterProviderBuilder, TelemetryError> {
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(self.0.clone())
            .without_target_info()
            .scope_info_enabled(false)
            .build()
            .map_err(|err| TelemetryError::Prometheus(err.to_string()))?;
        Ok(SdkMeterProvider::builder().with_reader(exporter))
    }

    /// Every metric in the Prometheus text exposition format.
    pub(crate) fn render(&self) -> String {
        let families = self.0.gather();
        prometheus::TextEncoder::new()
            .encode_to_string(&families)
            .unwrap_or_else(|err| {
                tracing::warn!(%err, "failed to render metrics");
                String::new()
            })
    }
}

/// The process's telemetry pipelines.
#[derive(Debug)]
pub(crate) struct Telemetry {
    registry: PrometheusRegistry,
    meter_provider: SdkMeterProvider,
    tracer_provider: Option<SdkTracerProvider>,
    metrics: GatewayMetrics,
}

impl Telemetry {
    const SCOPE: &'static str = "apigw";
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

    /// Builds the pipelines `settings` ask for. Must be called inside a Tokio
    /// runtime: the gRPC exporter connects through it.
    ///
    /// # Errors
    ///
    /// When an exporter cannot be built from its configuration.
    pub(crate) fn start(
        settings: &OtelSettings,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, TelemetryError> {
        let resource = resource::Attributes::from_env(&env).resource();
        let registry = PrometheusRegistry::new();
        let mut meters = registry
            .meter_provider_builder()?
            .with_resource(resource.clone());
        if settings.enabled && settings.metrics == MetricsExporter::Otlp {
            let exporter = match settings.metrics_protocol {
                Protocol::HttpProtobuf => opentelemetry_otlp::MetricExporter::builder()
                    .with_http()
                    .build()?,
                Protocol::Grpc => opentelemetry_otlp::MetricExporter::builder()
                    .with_tonic()
                    .with_tls_config(Self::grpc_tls())
                    .build()?,
            };
            meters = meters.with_reader(PeriodicReader::builder(exporter).build());
        }
        let meter_provider = meters.build();
        let metrics = GatewayMetrics::new(&meter_provider.meter(Self::SCOPE));
        let tracer_provider = if settings.enabled {
            let builder = SdkTracerProvider::builder().with_resource(resource);
            match settings.traces {
                TracesExporter::Otlp => {
                    let exporter = match settings.traces_protocol {
                        Protocol::HttpProtobuf => opentelemetry_otlp::SpanExporter::builder()
                            .with_http()
                            .build()?,
                        Protocol::Grpc => opentelemetry_otlp::SpanExporter::builder()
                            .with_tonic()
                            .with_tls_config(Self::grpc_tls())
                            .build()?,
                    };
                    Some(builder.with_batch_exporter(exporter).build())
                }
                TracesExporter::Console => Some(
                    builder
                        .with_batch_exporter(stdout::JsonLines::stdout())
                        .build(),
                ),
                TracesExporter::None => None,
            }
        } else {
            None
        };
        if settings.enabled {
            tracing::info!(
                traces = ?settings.traces,
                metrics = ?settings.metrics,
                "OpenTelemetry export enabled"
            );
        }
        Ok(Self {
            registry,
            meter_provider,
            tracer_provider,
            metrics,
        })
    }

    /// TLS for `https://` gRPC endpoints, verified against the system roots.
    /// Plain `http://` endpoints ignore it.
    fn grpc_tls() -> opentelemetry_otlp::tonic_types::transport::ClientTlsConfig {
        opentelemetry_otlp::tonic_types::transport::ClientTlsConfig::new().with_native_roots()
    }

    pub(crate) fn metrics(&self) -> GatewayMetrics {
        self.metrics.clone()
    }

    pub(crate) fn registry(&self) -> PrometheusRegistry {
        self.registry.clone()
    }

    /// The tracer request spans are started with, when spans are exported.
    pub(crate) fn tracer(&self) -> Option<RequestTracer> {
        self.tracer_provider
            .as_ref()
            .map(|provider| RequestTracer::new(provider.tracer(Self::SCOPE)))
    }

    /// Exports what is buffered and stops the exporters.
    pub(crate) fn shutdown(&self) {
        if let Some(ref provider) = self.tracer_provider
            && let Err(err) = provider.shutdown_with_timeout(Self::SHUTDOWN_TIMEOUT)
        {
            tracing::warn!(%err, "failed to flush spans at shutdown");
        }
        if let Err(err) = self
            .meter_provider
            .shutdown_with_timeout(Self::SHUTDOWN_TIMEOUT)
        {
            tracing::warn!(%err, "failed to flush metrics at shutdown");
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn settings(vars: &[(&str, &str)]) -> Result<OtelSettings, SettingsError> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        OtelSettings::from_env(true, |name| vars.get(name).cloned())
    }

    #[test]
    fn otlp_over_http_protobuf_is_the_default() {
        let parsed = settings(&[]).unwrap();
        assert_eq!(parsed.traces, TracesExporter::Otlp);
        assert_eq!(parsed.metrics, MetricsExporter::Otlp);
        assert_eq!(parsed.traces_protocol, Protocol::HttpProtobuf);
        assert_eq!(parsed.metrics_protocol, Protocol::HttpProtobuf);
    }

    #[test]
    fn exporters_and_protocols_come_from_the_standard_variables() {
        let parsed = settings(&[
            ("OTEL_TRACES_EXPORTER", "console"),
            ("OTEL_METRICS_EXPORTER", "none"),
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
            ("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "http/protobuf"),
        ])
        .unwrap();
        assert_eq!(parsed.traces, TracesExporter::Console);
        assert_eq!(parsed.metrics, MetricsExporter::None);
        assert_eq!(parsed.traces_protocol, Protocol::Grpc);
        assert_eq!(parsed.metrics_protocol, Protocol::HttpProtobuf);
        assert_eq!(
            settings(&[("OTEL_TRACES_EXPORTER", "none")])
                .unwrap()
                .traces,
            TracesExporter::None
        );
    }

    #[test]
    fn unsupported_exporters_and_protocols_are_rejected() {
        for (name, value) in [
            ("OTEL_TRACES_EXPORTER", "zipkin"),
            ("OTEL_METRICS_EXPORTER", "prometheus"),
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json"),
            ("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "udp"),
        ] {
            let err = settings(&[(name, value)]).unwrap_err();
            assert!(err.to_string().contains(name), "{err}");
        }
    }

    #[test]
    fn without_the_flag_nothing_is_exported_whatever_the_environment_says() {
        let parsed = OtelSettings::from_env(false, |_| Some("bogus".to_owned())).unwrap();
        assert_eq!(parsed, OtelSettings::disabled());
    }

    #[test]
    fn disabled_telemetry_still_serves_prometheus_and_starts_no_tracer() {
        let telemetry = Telemetry::start(&OtelSettings::disabled(), |_| None).unwrap();
        assert!(telemetry.tracer().is_none());
        telemetry.metrics().tls_reload(Outcome::Success);
        assert!(
            telemetry
                .registry()
                .render()
                .contains(r#"apigw_tls_reloads_total{outcome="success"} 1"#)
        );
        telemetry.shutdown();
    }

    #[tokio::test]
    async fn console_spans_start_a_tracer() {
        let settings = OtelSettings {
            metrics: MetricsExporter::None,
            traces: TracesExporter::Console,
            ..settings(&[]).unwrap()
        };
        let telemetry = Telemetry::start(&settings, |_| None).unwrap();
        assert!(telemetry.tracer().is_some());
        telemetry.shutdown();
    }
}
