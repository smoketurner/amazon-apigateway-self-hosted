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
#[cfg(test)]
#[expect(clippy::panic, reason = "a test helper that fails loudly on timeout")]
mod testing;
mod trace;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use aws_sdk_cloudwatchlogs::config::Region;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

pub(crate) use destination::{LogGroup, StreamName};
pub(crate) use metrics::MetricsNamespace;
pub(crate) use observer::{IntegrationTiming, StageObserver};
pub(crate) use trace::Trace;

use destination::Destination;
use metrics::MetricsAggregator;
use queue::{CloudWatchShipper, FirehoseShipper, LogQueue, Shipper, Worker, XRayShipper};
use trace::Sampler;

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

/// Whether stage tracing sends segments to X-Ray.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum TraceDelivery {
    /// Send segments for stages with tracing enabled to X-Ray, and propagate
    /// `X-Amzn-Trace-Id` and `traceparent` to integrations.
    Aws,
    /// Neither send segments nor touch trace headers.
    Off,
}

/// Where metrics are published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MetricsSettings {
    pub(crate) group: LogGroup,
    pub(crate) namespace: MetricsNamespace,
}

/// What the process delivers, and how.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub(crate) access_logs: Delivery,
    pub(crate) execution_logs: Delivery,
    /// Metrics are published only when a log group is configured for them.
    pub(crate) metrics: Option<MetricsSettings>,
    pub(crate) tracing: TraceDelivery,
    /// Percentage of requests sampled once the first request of each second
    /// has been, for requests whose caller made no sampling decision.
    pub(crate) sampling_percent: u8,
    pub(crate) stream: StreamName,
}

/// Delivery queues and workers shared by every loaded stage.
pub(crate) struct Observability {
    sdk_config: aws_config::SdkConfig,
    settings: Settings,
    queues: Mutex<HashMap<Destination, LogQueue>>,
    workers: Mutex<JoinSet<()>>,
    aggregator: Option<Arc<MetricsAggregator>>,
    sampler: Arc<Sampler>,
    aggregator_task: Mutex<Option<JoinHandle<()>>>,
    publishing: CancellationToken,
    closed: CancellationToken,
}

impl Observability {
    /// Starts delivery. Must be called inside a Tokio runtime: workers and the
    /// metrics publisher run as tasks.
    pub(crate) fn start(sdk_config: aws_config::SdkConfig, settings: Settings) -> Arc<Self> {
        let aggregator = settings
            .metrics
            .as_ref()
            .map(|m| Arc::new(MetricsAggregator::new(m.namespace.clone())));
        let sampler = Arc::new(Sampler::new(settings.sampling_percent));
        let observability = Arc::new(Self {
            sdk_config,
            settings,
            sampler,
            queues: Mutex::new(HashMap::new()),
            workers: Mutex::new(JoinSet::new()),
            aggregator,
            aggregator_task: Mutex::new(None),
            publishing: CancellationToken::new(),
            closed: CancellationToken::new(),
        });
        observability.start_metrics_publisher();
        observability
    }

    /// An instance that delivers nothing, for APIs built without a process
    /// to deliver from.
    #[cfg(test)]
    pub(crate) fn off() -> Arc<Self> {
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
                stream: StreamName::for_pod(
                    Some("test"),
                    None,
                    jiff::Timestamp::UNIX_EPOCH,
                    uuid::Uuid::nil(),
                ),
            },
            queues: Mutex::new(HashMap::new()),
            workers: Mutex::new(JoinSet::new()),
            sampler: Arc::new(Sampler::new(0)),
            aggregator: None,
            aggregator_task: Mutex::new(None),
            publishing: CancellationToken::new(),
            closed: CancellationToken::new(),
        })
    }

    fn start_metrics_publisher(self: &Arc<Self>) {
        let (Some(aggregator), Some(metrics)) =
            (self.aggregator.clone(), self.settings.metrics.clone())
        else {
            return;
        };
        let queue = self.queue(Destination::CloudWatch {
            region: None,
            group: metrics.group,
            create_group: false,
        });
        let publishing = self.publishing.clone();
        let task = tokio::spawn(async move { aggregator.run(queue, publishing).await });
        *self
            .aggregator_task
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(task);
    }

    /// The aggregator requests record metrics into, when metrics are on.
    pub(crate) fn metrics(&self) -> Option<Arc<MetricsAggregator>> {
        self.aggregator.clone()
    }

    /// Where a stage's access log lines go, given the destination ARN in its
    /// access log settings.
    pub(crate) fn access_log_queue(&self, destination_arn: Option<&str>) -> Option<LogQueue> {
        match self.settings.access_logs {
            Delivery::Off => None,
            Delivery::Stdout => Some(self.queue(Destination::Stdout)),
            Delivery::Aws => {
                let destination = match destination_arn.map(str::parse::<Destination>) {
                    Some(Ok(destination)) => destination,
                    Some(Err(err)) => {
                        tracing::warn!(%err, "writing access logs to stdout instead");
                        Destination::Stdout
                    }
                    None => Destination::Stdout,
                };
                Some(self.queue(destination))
            }
        }
    }

    /// Where a stage's execution logs go.
    pub(crate) fn execution_queue(&self, api_id: &str, stage: &str) -> Option<LogQueue> {
        match self.settings.execution_logs {
            Delivery::Off => None,
            Delivery::Stdout => Some(self.queue(Destination::Stdout)),
            Delivery::Aws => Some(self.queue(Destination::CloudWatch {
                region: None,
                group: LogGroup::execution_logs(api_id, stage),
                create_group: true,
            })),
        }
    }

    /// Where trace segments go, when tracing is on.
    pub(crate) fn trace_queue(&self) -> Option<LogQueue> {
        match self.settings.tracing {
            TraceDelivery::Off => None,
            TraceDelivery::Aws => Some(self.queue(Destination::XRay { region: None })),
        }
    }

    pub(crate) fn sampler(&self) -> Arc<Sampler> {
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
