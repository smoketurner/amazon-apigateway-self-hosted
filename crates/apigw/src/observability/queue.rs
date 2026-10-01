//! Bounded, batched delivery of log events.
//!
//! Requests never wait for delivery: [`LogQueue::push`] hands an event to a
//! bounded channel and returns. One worker per destination drains the channel
//! into batches that respect the destination's limits, and flushes them every
//! few seconds, when a batch is full, and once more at shutdown. When the
//! channel is full the newest event is dropped and counted, so a slow or
//! unreachable destination costs log events, never request latency or memory.
//! A batch the destination rejects is written to standard output instead.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aws_sdk_cloudwatchlogs::operation::create_log_group::CreateLogGroupError;
use aws_sdk_cloudwatchlogs::operation::create_log_stream::CreateLogStreamError;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::destination::LogGroup;

/// Events buffered per destination before new ones are dropped.
pub(crate) const QUEUE_CAPACITY: usize = 10_000;

/// How long a partial batch waits before it is sent.
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// How long the final flush at shutdown may take.
const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound for a single AWS call.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// One log line and when it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogEvent {
    pub(crate) timestamp_ms: i64,
    pub(crate) message: String,
}

impl LogEvent {
    /// An event stamped with the current time.
    pub(crate) fn now(message: String) -> Self {
        Self {
            timestamp_ms: jiff::Timestamp::now().as_millisecond(),
            message,
        }
    }
}

/// The sending side of a destination's queue. Cheap to clone.
#[derive(Debug, Clone)]
pub(crate) struct LogQueue {
    sender: mpsc::Sender<LogEvent>,
    dropped: Arc<AtomicU64>,
}

impl LogQueue {
    fn channel(capacity: usize) -> (Self, mpsc::Receiver<LogEvent>, Arc<AtomicU64>) {
        let (sender, receiver) = mpsc::channel(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        (
            Self {
                sender,
                dropped: Arc::clone(&dropped),
            },
            receiver,
            dropped,
        )
    }

    /// Queues `event` without waiting. A full queue drops it and counts the loss.
    pub(crate) fn push(&self, event: LogEvent) {
        if self.sender.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Events dropped since the worker last reported.
    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// How much one call to a destination may carry.
#[derive(Debug, Clone, Copy)]
struct BatchLimits {
    max_events: usize,
    max_bytes: usize,
    /// Bytes each event counts for beyond its message.
    event_overhead: usize,
    max_event_bytes: usize,
}

/// Events collected for one call.
#[derive(Debug, Default)]
struct Batch {
    events: Vec<LogEvent>,
    bytes: usize,
}

impl Batch {
    /// Adds `event`, or hands it back when the batch has no room for it.
    fn push(&mut self, event: LogEvent, limits: BatchLimits) -> Result<(), LogEvent> {
        let size = event.message.len().saturating_add(limits.event_overhead);
        let fits = self.events.len() < limits.max_events
            && self.bytes.saturating_add(size) <= limits.max_bytes;
        if !fits && !self.events.is_empty() {
            return Err(event);
        }
        self.bytes = self.bytes.saturating_add(size);
        self.events.push(event);
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The events in timestamp order, as CloudWatch Logs requires; requests
    /// finish out of order, so arrival order is not timestamp order.
    fn take_sorted(&mut self) -> Vec<LogEvent> {
        self.bytes = 0;
        let mut events = std::mem::take(&mut self.events);
        events.sort_by_key(|event| event.timestamp_ms);
        events
    }
}

#[derive(Debug, thiserror::Error)]
enum ShipError {
    #[error("{0}")]
    Aws(String),
    #[error("timed out after {0:?}")]
    Timeout(Duration),
    #[error("event is not representable: {0}")]
    Build(String),
}

impl ShipError {
    fn aws<E, R>(error: aws_sdk_cloudwatchlogs::error::SdkError<E, R>) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
        R: std::fmt::Debug,
    {
        Self::Aws(aws_sdk_cloudwatchlogs::error::DisplayErrorContext(error).to_string())
    }
}

async fn within_timeout<T>(
    call: impl Future<Output = Result<T, ShipError>>,
) -> Result<T, ShipError> {
    tokio::time::timeout(CALL_TIMEOUT, call)
        .await
        .map_err(|_| ShipError::Timeout(CALL_TIMEOUT))?
}

/// Writes events to one CloudWatch Logs stream.
#[derive(Debug)]
pub(crate) struct CloudWatchShipper {
    client: aws_sdk_cloudwatchlogs::Client,
    group: LogGroup,
    stream: String,
    create_group: bool,
}

impl CloudWatchShipper {
    pub(crate) fn new(
        client: aws_sdk_cloudwatchlogs::Client,
        group: LogGroup,
        stream: String,
        create_group: bool,
    ) -> Self {
        Self {
            client,
            group,
            stream,
            create_group,
        }
    }

    const LIMITS: BatchLimits = BatchLimits {
        max_events: 10_000,
        max_bytes: 1_048_576,
        event_overhead: 26,
        // Below the 1 MB the API documents, so older limits in other
        // partitions cannot reject an event.
        max_event_bytes: 262_144 - 26,
    };

    /// Creates the log stream (and, for execution logs, the group). An existing
    /// one is fine; any other failure is logged and delivery is tried anyway.
    async fn prepare(&self) {
        if self.create_group {
            let result = within_timeout(async {
                match self
                    .client
                    .create_log_group()
                    .log_group_name(self.group.as_str())
                    .send()
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(err)
                        if err.as_service_error().is_some_and(
                            CreateLogGroupError::is_resource_already_exists_exception,
                        ) =>
                    {
                        Ok(())
                    }
                    Err(err) => Err(ShipError::aws(err)),
                }
            })
            .await;
            if let Err(err) = result {
                tracing::warn!(group = %self.group, %err, "failed to create the log group");
            }
        }
        let result = within_timeout(async {
            match self
                .client
                .create_log_stream()
                .log_group_name(self.group.as_str())
                .log_stream_name(&self.stream)
                .send()
                .await
            {
                Ok(_) => Ok(()),
                Err(err)
                    if err.as_service_error().is_some_and(
                        CreateLogStreamError::is_resource_already_exists_exception,
                    ) =>
                {
                    Ok(())
                }
                Err(err) => Err(ShipError::aws(err)),
            }
        })
        .await;
        if let Err(err) = result {
            tracing::warn!(group = %self.group, stream = self.stream, %err, "failed to create the log stream");
        }
    }

    async fn put(&self, events: &[LogEvent]) -> Result<(), ShipError> {
        let mut input = Vec::with_capacity(events.len());
        for event in events {
            input.push(
                aws_sdk_cloudwatchlogs::types::InputLogEvent::builder()
                    .timestamp(event.timestamp_ms)
                    .message(&event.message)
                    .build()
                    .map_err(|err| ShipError::Build(err.to_string()))?,
            );
        }
        let output = within_timeout(async {
            self.client
                .put_log_events()
                .log_group_name(self.group.as_str())
                .log_stream_name(&self.stream)
                .set_log_events(Some(input))
                .send()
                .await
                .map_err(ShipError::aws)
        })
        .await?;
        if output.rejected_log_events_info().is_some() {
            tracing::warn!(
                group = %self.group,
                info = ?output.rejected_log_events_info(),
                "CloudWatch Logs rejected some events (too old or too new)"
            );
        }
        Ok(())
    }

    /// Sends `events`; when the stream is missing (deleted, or never created
    /// because of a permissions problem that has since been fixed) creates it
    /// and tries once more.
    async fn ship(&self, events: Vec<LogEvent>) -> Vec<LogEvent> {
        let mut result = self.put(&events).await;
        if result
            .as_ref()
            .is_err_and(|err| err.to_string().contains("ResourceNotFoundException"))
        {
            self.prepare().await;
            result = self.put(&events).await;
        }
        match result {
            Ok(()) => Vec::new(),
            Err(err) => {
                tracing::warn!(group = %self.group, stream = self.stream, %err, count = events.len(), "failed to write log events");
                events
            }
        }
    }
}

/// Writes events to a Firehose delivery stream.
#[derive(Debug)]
pub(crate) struct FirehoseShipper {
    client: aws_sdk_firehose::Client,
    stream: String,
}

impl FirehoseShipper {
    pub(crate) fn new(client: aws_sdk_firehose::Client, stream: String) -> Self {
        Self { client, stream }
    }

    const LIMITS: BatchLimits = BatchLimits {
        max_events: 500,
        max_bytes: 4 * 1024 * 1024,
        event_overhead: 1,
        max_event_bytes: 1_000 * 1024 - 1,
    };

    /// Sends `events` as newline-terminated records and returns the ones
    /// Firehose did not accept.
    async fn ship(&self, events: Vec<LogEvent>) -> Vec<LogEvent> {
        let mut records = Vec::with_capacity(events.len());
        for event in &events {
            let mut data = event.message.clone().into_bytes();
            data.push(b'\n');
            match aws_sdk_firehose::types::Record::builder()
                .data(aws_sdk_firehose::primitives::Blob::new(data))
                .build()
            {
                Ok(record) => records.push(record),
                Err(err) => {
                    tracing::error!(%err, "failed to build a Firehose record");
                    return events;
                }
            }
        }
        let sent = within_timeout(async {
            self.client
                .put_record_batch()
                .delivery_stream_name(&self.stream)
                .set_records(Some(records))
                .send()
                .await
                .map_err(|err| {
                    ShipError::Aws(aws_sdk_firehose::error::DisplayErrorContext(err).to_string())
                })
        })
        .await;
        match sent {
            Err(err) => {
                tracing::warn!(stream = self.stream, %err, count = events.len(), "failed to write Firehose records");
                events
            }
            Ok(output) if output.failed_put_count() == 0 => Vec::new(),
            Ok(output) => {
                let failed: Vec<LogEvent> = events
                    .into_iter()
                    .zip(output.request_responses())
                    .filter(|(_, response)| response.error_code().is_some())
                    .map(|(event, _)| event)
                    .collect();
                tracing::warn!(
                    stream = self.stream,
                    count = failed.len(),
                    "Firehose rejected some records"
                );
                failed
            }
        }
    }
}

/// Where a worker sends its batches.
#[derive(Debug)]
pub(crate) enum Shipper {
    CloudWatch(CloudWatchShipper),
    Firehose(FirehoseShipper),
    Stdout,
}

impl Shipper {
    const STDOUT_LIMITS: BatchLimits = BatchLimits {
        max_events: 10_000,
        max_bytes: 1_048_576,
        event_overhead: 1,
        max_event_bytes: 262_144,
    };

    fn limits(&self) -> BatchLimits {
        match self {
            Self::CloudWatch(_) => CloudWatchShipper::LIMITS,
            Self::Firehose(_) => FirehoseShipper::LIMITS,
            Self::Stdout => Self::STDOUT_LIMITS,
        }
    }

    async fn prepare(&self) {
        if let Self::CloudWatch(shipper) = self {
            shipper.prepare().await;
        }
    }

    /// Delivers `events` and returns the ones that could not be delivered.
    async fn ship(&self, events: Vec<LogEvent>) -> Vec<LogEvent> {
        match self {
            Self::CloudWatch(shipper) => shipper.ship(events).await,
            Self::Firehose(shipper) => shipper.ship(events).await,
            Self::Stdout => Self::write_stdout(events).await,
        }
    }

    async fn write_stdout(events: Vec<LogEvent>) -> Vec<LogEvent> {
        let mut text = String::new();
        for event in &events {
            text.push_str(&event.message);
            text.push('\n');
        }
        let mut stdout = tokio::io::stdout();
        let written = async {
            stdout.write_all(text.as_bytes()).await?;
            stdout.flush().await
        }
        .await;
        match written {
            Ok(()) => Vec::new(),
            Err(err) => {
                tracing::error!(%err, count = events.len(), "failed to write log events to stdout");
                events
            }
        }
    }
}

/// Drains one destination's queue into its shipper.
pub(crate) struct Worker {
    receiver: mpsc::Receiver<LogEvent>,
    shipper: Shipper,
    dropped: Arc<AtomicU64>,
    flush_interval: Duration,
    closed: CancellationToken,
}

impl Worker {
    /// A queue and the worker that drains it. The worker stops, after a final
    /// flush, when `closed` is cancelled.
    pub(crate) fn new(shipper: Shipper, closed: CancellationToken) -> (LogQueue, Self) {
        Self::with_options(shipper, closed, QUEUE_CAPACITY, FLUSH_INTERVAL)
    }

    fn with_options(
        shipper: Shipper,
        closed: CancellationToken,
        capacity: usize,
        flush_interval: Duration,
    ) -> (LogQueue, Self) {
        let (queue, receiver, dropped) = LogQueue::channel(capacity);
        (
            queue,
            Self {
                receiver,
                shipper,
                dropped,
                flush_interval,
                closed,
            },
        )
    }

    pub(crate) async fn run(mut self) {
        self.shipper.prepare().await;
        let limits = self.shipper.limits();
        let mut batch = Batch::default();
        let mut ticker = tokio::time::interval(self.flush_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = self.closed.cancelled() => break,
                received = self.receiver.recv() => {
                    let Some(event) = received else { break };
                    self.accept(&mut batch, event, limits).await;
                }
                _ = ticker.tick() => {
                    self.report_drops();
                    self.flush(&mut batch).await;
                }
            }
        }
        self.receiver.close();
        while let Ok(event) = self.receiver.try_recv() {
            self.accept(&mut batch, event, limits).await;
        }
        self.report_drops();
        if tokio::time::timeout(SHUTDOWN_FLUSH_TIMEOUT, self.flush(&mut batch))
            .await
            .is_err()
        {
            tracing::warn!("timed out flushing log events at shutdown");
        }
    }

    async fn accept(&self, batch: &mut Batch, mut event: LogEvent, limits: BatchLimits) {
        if event.message.len() > limits.max_event_bytes {
            let end = event.message.floor_char_boundary(limits.max_event_bytes);
            event.message.truncate(end);
        }
        if let Err(event) = batch.push(event, limits) {
            self.flush(batch).await;
            if batch.push(event, limits).is_err() {
                tracing::error!("an empty batch rejected a log event");
            }
        }
    }

    fn report_drops(&self) {
        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            tracing::warn!(dropped, "log queue was full; events were dropped");
        }
    }

    async fn flush(&self, batch: &mut Batch) {
        if batch.is_empty() {
            return;
        }
        let failed = self.shipper.ship(batch.take_sorted()).await;
        if !failed.is_empty() && !matches!(self.shipper, Shipper::Stdout) {
            Shipper::write_stdout(failed).await;
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(
    clippy::indexing_slicing,
    reason = "tests index JSON bodies they built"
)]
mod tests {
    use base64::Engine as _;

    use super::*;
    use crate::observability::testing::{MockAws, Reply};

    fn event(timestamp_ms: i64, message: &str) -> LogEvent {
        LogEvent {
            timestamp_ms,
            message: message.to_owned(),
        }
    }

    const SMALL: BatchLimits = BatchLimits {
        max_events: 3,
        max_bytes: 20,
        event_overhead: 1,
        max_event_bytes: 10,
    };

    #[test]
    fn batches_stop_at_the_event_and_byte_limits() {
        let mut batch = Batch::default();
        assert!(batch.push(event(1, "aaaa"), SMALL).is_ok());
        assert!(batch.push(event(2, "bbbb"), SMALL).is_ok());
        assert!(batch.push(event(3, "cccc"), SMALL).is_ok());
        assert_eq!(batch.push(event(4, "d"), SMALL).unwrap_err().message, "d");

        let mut batch = Batch::default();
        batch.push(event(1, "aaaaaaaaaa"), SMALL).unwrap();
        assert!(batch.push(event(2, "bbbbbbbbb"), SMALL).is_err());
    }

    #[test]
    fn an_empty_batch_always_takes_one_event() {
        let mut batch = Batch::default();
        assert!(batch.push(event(1, &"x".repeat(100)), SMALL).is_ok());
        assert_eq!(batch.events.len(), 1);
    }

    #[test]
    fn batches_are_sent_in_timestamp_order() {
        let mut batch = Batch::default();
        batch.push(event(30, "c"), SMALL).unwrap();
        batch.push(event(10, "a"), SMALL).unwrap();
        batch.push(event(10, "b"), SMALL).unwrap();
        let sorted: Vec<_> = batch.take_sorted().into_iter().map(|e| e.message).collect();
        assert_eq!(sorted, ["a", "b", "c"]);
        assert!(batch.is_empty());
        assert_eq!(batch.bytes, 0);
    }

    #[test]
    fn a_full_queue_drops_and_counts_instead_of_blocking() {
        let (queue, _receiver, _) = LogQueue::channel(2);
        for i in 0..5 {
            queue.push(event(i, "x"));
        }
        assert_eq!(queue.dropped(), 3);
    }

    fn cloudwatch(aws: &MockAws, create_group: bool) -> Shipper {
        Shipper::CloudWatch(CloudWatchShipper::new(
            aws.cloudwatch_logs(),
            LogGroup::new("group"),
            "stream".to_owned(),
            create_group,
        ))
    }

    #[tokio::test]
    async fn the_worker_creates_the_stream_and_ships_batches_in_order() {
        let aws = MockAws::start().await;
        let closed = CancellationToken::new();
        let (queue, worker) = Worker::with_options(
            cloudwatch(&aws, false),
            closed.clone(),
            100,
            Duration::from_millis(50),
        );
        let task = tokio::spawn(worker.run());
        queue.push(event(20, "second"));
        queue.push(event(10, "first"));
        aws.wait_for("Logs_20140328.PutLogEvents", 1).await;
        closed.cancel();
        task.await.unwrap();

        let calls = aws.calls();
        assert_eq!(calls[0].target, "Logs_20140328.CreateLogStream");
        assert_eq!(calls[0].body["logGroupName"], "group");
        assert_eq!(calls[0].body["logStreamName"], "stream");
        let put = calls
            .iter()
            .find(|c| c.target == "Logs_20140328.PutLogEvents")
            .unwrap();
        let messages: Vec<&str> = put.body["logEvents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["message"].as_str().unwrap())
            .collect();
        assert_eq!(messages, ["first", "second"]);
    }

    #[tokio::test]
    async fn execution_log_groups_are_created_and_existing_ones_tolerated() {
        let aws = MockAws::start().await;
        aws.reply(
            "Logs_20140328.CreateLogGroup",
            Reply::error("ResourceAlreadyExistsException"),
        );
        let closed = CancellationToken::new();
        let (queue, worker) = Worker::with_options(
            cloudwatch(&aws, true),
            closed.clone(),
            100,
            Duration::from_secs(60),
        );
        let task = tokio::spawn(worker.run());
        queue.push(event(1, "line"));
        closed.cancel();
        task.await.unwrap();
        let targets: Vec<String> = aws.calls().into_iter().map(|c| c.target).collect();
        assert_eq!(
            targets,
            [
                "Logs_20140328.CreateLogGroup",
                "Logs_20140328.CreateLogStream",
                "Logs_20140328.PutLogEvents"
            ]
        );
    }

    #[tokio::test]
    async fn shutdown_flushes_events_still_queued() {
        let aws = MockAws::start().await;
        let closed = CancellationToken::new();
        let (queue, worker) = Worker::with_options(
            cloudwatch(&aws, false),
            closed.clone(),
            100,
            Duration::from_secs(3600),
        );
        for i in 0..7 {
            queue.push(event(i, &format!("line {i}")));
        }
        closed.cancel();
        worker.run().await;
        let put = aws
            .calls()
            .into_iter()
            .find(|c| c.target == "Logs_20140328.PutLogEvents")
            .unwrap();
        assert_eq!(put.body["logEvents"].as_array().unwrap().len(), 7);
    }

    #[tokio::test]
    async fn a_stream_deleted_underneath_is_recreated_once() {
        let aws = MockAws::start().await;
        aws.reply_once(
            "Logs_20140328.PutLogEvents",
            Reply::error("ResourceNotFoundException"),
        );
        let shipper = cloudwatch(&aws, false);
        let failed = shipper.ship(vec![event(1, "a")]).await;
        assert!(failed.is_empty());
        let targets: Vec<String> = aws.calls().into_iter().map(|c| c.target).collect();
        assert_eq!(
            targets,
            [
                "Logs_20140328.PutLogEvents",
                "Logs_20140328.CreateLogStream",
                "Logs_20140328.PutLogEvents"
            ]
        );
    }

    #[tokio::test]
    async fn rejected_batches_are_handed_back_for_the_stdout_fallback() {
        let aws = MockAws::start().await;
        aws.reply(
            "Logs_20140328.PutLogEvents",
            Reply::error("InvalidParameterException"),
        );
        let failed = cloudwatch(&aws, false)
            .ship(vec![event(1, "a"), event(2, "b")])
            .await;
        assert_eq!(failed.len(), 2);
    }

    #[tokio::test]
    async fn oversized_events_are_truncated_on_a_character_boundary() {
        let aws = MockAws::start().await;
        let closed = CancellationToken::new();
        let (queue, worker) = Worker::with_options(
            cloudwatch(&aws, false),
            closed.clone(),
            10,
            Duration::from_secs(3600),
        );
        queue.push(event(1, &"\u{e9}".repeat(200_000)));
        closed.cancel();
        worker.run().await;
        let put = aws
            .calls()
            .into_iter()
            .find(|c| c.target == "Logs_20140328.PutLogEvents")
            .unwrap();
        let message = put.body["logEvents"][0]["message"].as_str().unwrap();
        assert!(message.len() <= CloudWatchShipper::LIMITS.max_event_bytes);
        assert!(message.chars().all(|c| c == '\u{e9}'));
    }

    #[tokio::test]
    async fn firehose_records_are_newline_terminated_and_failures_returned() {
        let aws = MockAws::start().await;
        aws.reply(
            "Firehose_20150804.PutRecordBatch",
            Reply::json(
                r#"{"FailedPutCount":1,"RequestResponses":[{"RecordId":"1"},{"ErrorCode":"ServiceUnavailableException","ErrorMessage":"x"}]}"#,
            ),
        );
        let shipper = Shipper::Firehose(FirehoseShipper::new(
            aws.firehose(),
            "amazon-apigateway-logs".to_owned(),
        ));
        let failed = shipper.ship(vec![event(1, "ok"), event(2, "bad")]).await;
        assert_eq!(failed, vec![event(2, "bad")]);
        let call = &aws.calls()[0];
        assert_eq!(call.body["DeliveryStreamName"], "amazon-apigateway-logs");
        let data = call.body["Records"][0]["Data"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(data)
            .unwrap();
        assert_eq!(decoded, b"ok\n");
        assert_eq!(call.body["Records"].as_array().unwrap().len(), 2);
    }
}
