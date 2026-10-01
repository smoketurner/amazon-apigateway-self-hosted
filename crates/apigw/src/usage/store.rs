//! The current keys and usage plans of the stage, refreshed in the background.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::UsageData;
use super::plan::UsageChecker;
use super::source::{ControlPlane, UsageReader};
use crate::backoff::Backoff;

/// How long data stays usable when it cannot be refreshed. A key disabled in
/// API Gateway keeps working until the next successful read, so an outage must
/// not extend that indefinitely: past this age every key is refused.
const MAX_STALENESS: Duration = Duration::from_hours(1);

#[derive(Debug)]
struct Held {
    data: Arc<UsageData>,
    read_at: Instant,
}

/// What the gateway currently knows about the stage's API keys.
#[derive(Debug)]
pub(crate) struct UsageStore {
    held: RwLock<Option<Held>>,
    checker: UsageChecker,
    max_staleness: Duration,
}

impl UsageStore {
    pub(crate) fn new(checker: UsageChecker) -> Self {
        Self {
            held: RwLock::new(None),
            checker,
            max_staleness: MAX_STALENESS,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_max_staleness(mut self, max_staleness: Duration) -> Self {
        self.max_staleness = max_staleness;
        self
    }

    pub(crate) fn checker(&self) -> &UsageChecker {
        &self.checker
    }

    /// The data, unless none has been read yet or it is too old to trust.
    pub(crate) fn current(&self) -> Option<Arc<UsageData>> {
        let held = self.held.read().unwrap_or_else(PoisonError::into_inner);
        held.as_ref()
            .filter(|held| held.read_at.elapsed() < self.max_staleness)
            .map(|held| Arc::clone(&held.data))
    }

    /// Makes `data` current.
    pub(crate) fn replace(&self, data: UsageData) {
        *self.held.write().unwrap_or_else(PoisonError::into_inner) = Some(Held {
            data: Arc::new(data),
            read_at: Instant::now(),
        });
    }

    /// Reads once and makes the result current.
    ///
    /// # Errors
    ///
    /// When the read fails; the data held before is kept.
    pub(crate) async fn refresh<S: ControlPlane>(
        &self,
        reader: &UsageReader<S>,
    ) -> Result<(), super::source::UsageError> {
        let data = reader.read().await?;
        tracing::info!(
            keys = data.key_count(),
            plans = data.plan_count(),
            "read API keys and usage plans"
        );
        self.replace(data);
        Ok(())
    }

    /// Refreshes every `interval` (backing off after failures) until `shutdown`.
    pub(crate) async fn keep_fresh<S: ControlPlane>(
        &self,
        reader: &UsageReader<S>,
        interval: Duration,
        shutdown: &CancellationToken,
    ) {
        let mut backoff = Backoff::default();
        loop {
            let wait = backoff.delay(interval);
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(wait) => {}
            }
            match self.refresh(reader).await {
                Ok(()) => backoff.reset(),
                Err(error) => {
                    backoff.record_failure();
                    tracing::warn!(%error, "could not refresh API keys and usage plans; keeping the last read");
                }
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use std::future::Future;
    use std::num::NonZeroU32;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::super::source::{Pacing, Page, PlanRecord, RawKey, StageRecord, UsageError};
    use super::super::{KeyId, KeyValue, PlanId};
    use super::*;

    /// One plan and one key, which can be made to fail.
    struct Flaky {
        failing: AtomicBool,
        reads: AtomicUsize,
        value: &'static str,
    }

    impl Flaky {
        fn new(value: &'static str) -> Self {
            Self {
                failing: AtomicBool::new(false),
                reads: AtomicUsize::new(0),
                value,
            }
        }

        fn check(&self) -> Result<(), UsageError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.failing.load(Ordering::SeqCst) {
                Err(UsageError::Aws("down".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    impl ControlPlane for &Flaky {
        fn usage_plans(
            &self,
            _: Option<&str>,
        ) -> impl Future<Output = Result<Page<PlanRecord>, UsageError>> + Send {
            std::future::ready(self.check().map(|()| Page {
                items: vec![PlanRecord {
                    id: PlanId("plan".to_owned()),
                    stages: vec![StageRecord {
                        api_id: "abc".to_owned(),
                        stage: "prod".to_owned(),
                        methods: std::collections::BTreeMap::new(),
                    }],
                    throttle: None,
                    quota: None,
                }],
                next: None,
            }))
        }

        fn api_keys(
            &self,
            _: Option<&str>,
        ) -> impl Future<Output = Result<Page<RawKey>, UsageError>> + Send {
            std::future::ready(self.check().map(|()| Page {
                items: vec![RawKey {
                    id: KeyId("key".to_owned()),
                    enabled: true,
                    value: KeyValue::new(self.value.to_owned()),
                }],
                next: None,
            }))
        }

        fn plan_keys(
            &self,
            _: &PlanId,
            _: Option<&str>,
        ) -> impl Future<Output = Result<Page<KeyId>, UsageError>> + Send {
            std::future::ready(self.check().map(|()| Page {
                items: vec![KeyId("key".to_owned())],
                next: None,
            }))
        }
    }

    fn store() -> UsageStore {
        UsageStore::new(UsageChecker::new("abc", "prod", NonZeroU32::MIN))
    }

    fn reader(source: &Flaky) -> UsageReader<&Flaky> {
        UsageReader::new(source, "abc", "prod", Pacing::of(Duration::ZERO))
    }

    #[tokio::test]
    async fn nothing_is_current_before_the_first_read() {
        assert!(store().current().is_none());
    }

    #[tokio::test]
    async fn a_refresh_makes_the_data_current() {
        let (store, source) = (store(), Flaky::new("v1"));
        store.refresh(&reader(&source)).await.unwrap();
        assert!(store.current().unwrap().lookup("v1").is_some());
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_what_was_read_before() {
        let (store, source) = (store(), Flaky::new("v1"));
        store.refresh(&reader(&source)).await.unwrap();
        source.failing.store(true, Ordering::SeqCst);
        assert!(store.refresh(&reader(&source)).await.is_err());
        assert!(store.current().unwrap().lookup("v1").is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn data_expires_when_it_cannot_be_refreshed() {
        let (store, source) = (store(), Flaky::new("v1"));
        store.refresh(&reader(&source)).await.unwrap();
        tokio::time::advance(MAX_STALENESS.saturating_sub(Duration::from_secs(1))).await;
        assert!(store.current().is_some());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            store.current().is_none(),
            "an hour without a read: every key is refused"
        );
        store.refresh(&reader(&source)).await.unwrap();
        assert!(store.current().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn the_keeper_reads_every_interval_and_backs_off_after_failures() {
        let store = Arc::new(store());
        let source = Arc::new(Flaky::new("v1"));
        let shutdown = CancellationToken::new();
        let task = {
            let (store, source, shutdown) =
                (Arc::clone(&store), Arc::clone(&source), shutdown.clone());
            tokio::spawn(async move {
                let reader = UsageReader::new(&*source, "abc", "prod", Pacing::of(Duration::ZERO));
                store
                    .keep_fresh(&reader, Duration::from_secs(60), &shutdown)
                    .await;
            })
        };
        // Three calls per read (plans, members, keys).
        let reads = |n: usize| source.reads.load(Ordering::SeqCst) == n.saturating_mul(3);
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(reads(0), "the first read waits one interval");
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert!(reads(1));
        assert!(store.current().unwrap().lookup("v1").is_some());
        source.failing.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(150)).await;
        let failures = source.reads.load(Ordering::SeqCst);
        assert!(failures > 3, "a failing read was attempted");
        assert!(
            store.current().unwrap().lookup("v1").is_some(),
            "the last read is kept meanwhile"
        );
        source.failing.store(false, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert!(
            source.reads.load(Ordering::SeqCst) >= failures.saturating_add(3),
            "recovered"
        );
        shutdown.cancel();
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn the_keeper_stops_when_asked() {
        let (store, source) = (store(), Flaky::new("v1"));
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        store
            .keep_fresh(&reader(&source), Duration::from_secs(60), &shutdown)
            .await;
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    }
}
