//! CloudWatch observability: access logs, metrics, and execution logs.
//!
//! [`Observability`] is the process-wide delivery service: it owns one bounded
//! queue and worker per destination and the per-minute metrics aggregator.
//! Each loaded stage gets a [`StageObserver`] that decides what to record for
//! its requests and hands it to those queues.

mod destination;
mod exec;
mod format;
mod metrics;
mod observer;
mod queue;
mod sampling;
#[cfg(test)]
#[expect(clippy::panic, reason = "a test helper that fails loudly on timeout")]
pub(crate) mod testing;
mod trace;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use aws_sdk_cloudwatchlogs::config::Region;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

pub(crate) use destination::{LogGroup, StreamName};
pub(crate) use metrics::MetricsNamespace;
pub(crate) use observer::{ExecutionRecord, IntegrationTiming, StageObserver};
pub(crate) use trace::{Trace, TraceId};

use crate::canary::Release;
use crate::telemetry::{GatewayMetrics, RequestTracer};
use destination::Destination;
use metrics::MetricsAggregator;
use queue::{CloudWatchShipper, FirehoseShipper, LogQueue, Shipper, Worker, XRayShipper};
use sampling::{RulePoller, Sampler};

/// Where one kind of log goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Delivery {
    /// The destination the stage names (CloudWatch Logs or Firehose); standard
    /// output when the stage names none or the destination is not an ARN this
    /// gateway can write to.
    Aws,
    /// Standard output, one event per line, without calling AWS.
    Stdout,
    /// Nowhere.
    Off,
}

/// Where stage tracing sends X-Ray segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum TraceDelivery {
    /// Send segments for stages with tracing enabled to X-Ray, and propagate
    /// `X-Amzn-Trace-Id` and `traceparent` to integrations.
    Aws,
    /// Write segment documents to standard output, one per line, and
    /// propagate trace headers as `aws` does.
    Stdout,
    /// Neither send segments nor touch trace headers.
    Off,
}

/// Where embedded metric format events go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MetricsDestination {
    /// A CloudWatch Logs log group, which extracts the metrics.
    LogGroup(LogGroup),
    /// Standard output, for the CloudWatch agent or Fluent Bit to forward.
    Stdout,
}

/// Where metrics are published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MetricsSettings {
    pub(crate) destination: MetricsDestination,
    pub(crate) namespace: MetricsNamespace,
}

/// What the process delivers, and how.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub(crate) access_logs: Delivery,
    pub(crate) execution_logs: Delivery,
    /// Embedded metric format events, when published.
    pub(crate) metrics: Option<MetricsSettings>,
    pub(crate) tracing: TraceDelivery,
    /// Percentage of requests sampled once the first request of each second
    /// has been, for requests whose caller made no sampling decision and
    /// no X-Ray sampling rule applies.
    pub(crate) sampling_percent: u8,
    /// Read X-Ray's sampling rules and reservoir quotas (with `tracing: Aws`).
    pub(crate) sampling_rules: bool,
    /// Trace requests the caller sampled on stages without tracing enabled.
    pub(crate) passive: bool,
    pub(crate) stream: StreamName,
}

/// The process's OpenTelemetry instruments, which every stage records into.
#[derive(Debug, Clone)]
pub(crate) struct Instrumentation {
    pub(crate) metrics: GatewayMetrics,
    /// Starts request spans, when spans are exported.
    pub(crate) tracer: Option<RequestTracer>,
}

impl Instrumentation {
    /// Metrics into the process-wide instruments and no spans.
    #[cfg(test)]
    pub(crate) fn metrics_only() -> Self {
        Self {
            metrics: GatewayMetrics::global().clone(),
            tracer: None,
        }
    }
}

/// Delivery queues and workers shared by every loaded stage.
pub(crate) struct Observability {
    sdk_config: aws_config::SdkConfig,
    settings: Settings,
    instrumentation: Instrumentation,
    queues: Mutex<HashMap<Destination, LogQueue>>,
    workers: Mutex<JoinSet<()>>,
    aggregator: Option<Arc<MetricsAggregator>>,
    sampler: Arc<Sampler>,
    aggregator_task: Mutex<Option<JoinHandle<()>>>,
    publishing: CancellationToken,
    closed: CancellationToken,
    poller_started: AtomicBool,
}

impl Observability {
    /// Starts delivery. Must be called inside a Tokio runtime: workers and the
    /// metrics publisher run as tasks.
    pub(crate) fn start(
        sdk_config: aws_config::SdkConfig,
        settings: Settings,
        instrumentation: Instrumentation,
    ) -> Arc<Self> {
        let aggregator = settings
            .metrics
            .as_ref()
            .map(|m| Arc::new(MetricsAggregator::new(m.namespace.clone())));
        let sampler = Arc::new(Sampler::new(settings.sampling_percent));
        let observability = Arc::new(Self {
            sdk_config,
            settings,
            instrumentation,
            sampler,
            queues: Mutex::new(HashMap::new()),
            workers: Mutex::new(JoinSet::new()),
            aggregator,
            aggregator_task: Mutex::new(None),
            publishing: CancellationToken::new(),
            closed: CancellationToken::new(),
            poller_started: AtomicBool::new(false),
        });
        observability.start_metrics_publisher();
        observability
    }

    /// An instance that delivers nothing, for APIs built without a process
    /// to deliver from.
    #[cfg(test)]
    pub(crate) fn off() -> Arc<Self> {
        Self::off_with(Instrumentation::metrics_only())
    }

    /// As [`Self::off`], recording metrics and spans into `instrumentation`.
    #[cfg(test)]
    pub(crate) fn off_with(instrumentation: Instrumentation) -> Arc<Self> {
        Arc::new(Self {
            sdk_config: aws_config::SdkConfig::builder()
                .behavior_version(aws_config::BehaviorVersion::latest())
                .build(),
            settings: Settings {
                access_logs: Delivery::Off,
                execution_logs: Delivery::Off,
                metrics: None,
                tracing: TraceDelivery::Off,
                sampling_percent: 0,
                sampling_rules: false,
                passive: false,
                stream: StreamName::for_pod(
                    Some("test"),
                    None,
                    jiff::Timestamp::UNIX_EPOCH,
                    uuid::Uuid::nil(),
                ),
            },
            instrumentation,
            queues: Mutex::new(HashMap::new()),
            workers: Mutex::new(JoinSet::new()),
            sampler: Arc::new(Sampler::new(0)),
            aggregator: None,
            aggregator_task: Mutex::new(None),
            publishing: CancellationToken::new(),
            closed: CancellationToken::new(),
            poller_started: AtomicBool::new(false),
        })
    }

    fn start_metrics_publisher(self: &Arc<Self>) {
        let (Some(aggregator), Some(metrics)) =
            (self.aggregator.clone(), self.settings.metrics.clone())
        else {
            return;
        };
        let queue = self.queue(match metrics.destination {
            MetricsDestination::LogGroup(group) => Destination::CloudWatch {
                region: None,
                group,
                create_group: false,
            },
            MetricsDestination::Stdout => Destination::Stdout,
        });
        let publishing = self.publishing.clone();
        let task = tokio::spawn(async move { aggregator.run(queue, publishing).await });
        *self
            .aggregator_task
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(task);
    }

    pub(crate) fn instrumentation(&self) -> &Instrumentation {
        &self.instrumentation
    }

    /// Polls X-Ray for sampling rules while segments go to X-Ray, from the
    /// first time a stage with tracing enabled is loaded.
    fn start_rule_poller(&self) {
        if self.settings.tracing != TraceDelivery::Aws
            || !self.settings.sampling_rules
            || self.poller_started.swap(true, Ordering::Relaxed)
        {
            return;
        }
        let poller = RulePoller::new(
            aws_sdk_xray::Client::new(&self.sdk_config),
            Arc::clone(&self.sampler),
        );
        let publishing = self.publishing.clone();
        self.workers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .spawn(poller.run(publishing));
    }

    /// Whether stages without tracing continue traces their callers sampled.
    pub(crate) fn passive_tracing(&self) -> bool {
        self.settings.passive && self.settings.tracing != TraceDelivery::Off
    }

    /// `arn:{partition}:apigateway:{region}::/restapis/{api_id}/stages/{stage}`,
    /// the resource X-Ray sampling rules match.
    pub(crate) fn stage_arn(&self, api_id: &str, stage: &str) -> String {
        let region = self.sdk_config.region().map_or("", Region::as_ref);
        let partition = if region.starts_with("cn-") {
            "aws-cn"
        } else if region.starts_with("us-gov-") {
            "aws-us-gov"
        } else {
            "aws"
        };
        format!("arn:{partition}:apigateway:{region}::/restapis/{api_id}/stages/{stage}")
    }

    /// The aggregator requests record metrics into, when metrics are on.
    pub(crate) fn metrics(&self) -> Option<Arc<MetricsAggregator>> {
        self.aggregator.clone()
    }

    /// Where a stage's access log lines go, given the destination ARN in its
    /// access log settings: the destination, and for canary requests also its
    /// canary variant. Empty when access logs are off.
    pub(crate) fn access_log_queues(
        &self,
        destination_arn: Option<&str>,
        release: Option<Release>,
    ) -> Vec<LogQueue> {
        let destination = match self.settings.access_logs {
            Delivery::Off => return Vec::new(),
            Delivery::Stdout => Destination::Stdout,
            Delivery::Aws => match destination_arn.map(str::parse::<Destination>) {
                Some(Ok(destination)) => destination,
                Some(Err(err)) => {
                    tracing::warn!(%err, "writing access logs to stdout instead");
                    Destination::Stdout
                }
                None => Destination::Stdout,
            },
        };
        self.with_canary(destination, release)
    }

    /// Where a stage's execution logs go, as for [`Self::access_log_queues`].
    pub(crate) fn execution_queues(
        &self,
        api_id: &str,
        stage: &str,
        release: Option<Release>,
    ) -> Vec<LogQueue> {
        let destination = match self.settings.execution_logs {
            Delivery::Off => return Vec::new(),
            Delivery::Stdout => Destination::Stdout,
            Delivery::Aws => Destination::CloudWatch {
                region: None,
                group: LogGroup::execution_logs(api_id, stage),
                create_group: true,
            },
        };
        self.with_canary(destination, release)
    }

    fn with_canary(&self, destination: Destination, release: Option<Release>) -> Vec<LogQueue> {
        let canary = (release == Some(Release::Canary))
            .then(|| destination.canary())
            .flatten();
        let mut queues = vec![self.queue(destination)];
        queues.extend(canary.map(|destination| self.queue(destination)));
        queues
    }

    /// Where trace segments go, when tracing is on.
    pub(crate) fn trace_queue(&self) -> Option<LogQueue> {
        match self.settings.tracing {
            TraceDelivery::Off => None,
            TraceDelivery::Aws => Some(self.queue(Destination::XRay { region: None })),
            TraceDelivery::Stdout => Some(self.queue(Destination::Stdout)),
        }
    }

    /// The sampler of stages with tracing enabled.
    pub(crate) fn sampler(&self) -> Arc<Sampler> {
        self.start_rule_poller();
        Arc::clone(&self.sampler)
    }

    /// The queue for `destination`, starting its worker on first use.
    fn queue(&self, destination: Destination) -> LogQueue {
        let mut queues = self.queues.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(queue) = queues.get(&destination) {
            return queue.clone();
        }
        let (queue, worker) = Worker::new(self.shipper(&destination), self.closed.clone());
        self.workers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .spawn(worker.run());
        queues.insert(destination, queue.clone());
        queue
    }

    fn shipper(&self, destination: &Destination) -> Shipper {
        match *destination {
            Destination::CloudWatch {
                ref region,
                ref group,
                create_group,
            } => {
                let mut config = aws_sdk_cloudwatchlogs::config::Builder::from(&self.sdk_config);
                if let Some(region) = region {
                    config = config.region(Region::new(region.clone()));
                }
                Shipper::CloudWatch(CloudWatchShipper::new(
                    aws_sdk_cloudwatchlogs::Client::from_conf(config.build()),
                    group.clone(),
                    self.settings.stream.as_str().to_owned(),
                    create_group,
                ))
            }
            Destination::Firehose {
                ref region,
                ref stream,
            } => {
                let mut config = aws_sdk_firehose::config::Builder::from(&self.sdk_config);
                if let Some(region) = region {
                    config = config.region(Region::new(region.clone()));
                }
                Shipper::Firehose(FirehoseShipper::new(
                    aws_sdk_firehose::Client::from_conf(config.build()),
                    stream.clone(),
                ))
            }
            Destination::XRay { ref region } => {
                let mut config = aws_sdk_xray::config::Builder::from(&self.sdk_config);
                if let Some(region) = region {
                    config = config.region(Region::new(region.clone()));
                }
                Shipper::XRay(XRayShipper::new(aws_sdk_xray::Client::from_conf(
                    config.build(),
                )))
            }
            Destination::Stdout => Shipper::Stdout,
        }
    }

    /// Publishes the last partial minute of metrics and flushes every queue.
    /// Call after the listeners have drained so no request is still recording.
    pub(crate) async fn close(&self) {
        self.publishing.cancel();
        let task = self
            .aggregator_task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(task) = task
            && let Err(err) = task.await
        {
            tracing::error!(%err, "the metrics publisher failed");
        }
        self.closed.cancel();
        let mut workers =
            std::mem::take(&mut *self.workers.lock().unwrap_or_else(PoisonError::into_inner));
        while let Some(result) = workers.join_next().await {
            if let Err(err) = result {
                tracing::error!(%err, "a log delivery worker failed");
            }
        }
    }
}
