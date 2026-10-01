//! The URL and script tests run anywhere. The tests against a server start a
//! container with Docker and are ignored by default: run them with
//! `cargo test -p apigw valkey -- --ignored`. `APIGW_TEST_VALKEY_IMAGE`
//! selects the image (default `valkey/valkey:8`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, SanType};

use super::*;
use crate::state::quota::QuotaPeriod;

fn url(raw: &str) -> ValkeyUrl {
    raw.parse().unwrap()
}

#[test]
fn credentials_never_appear_in_the_displayed_url() {
    for raw in [
        "rediss://user:hunter2@cache.example.com:6380/0",
        "rediss://:hunter2@cache.example.com:6380/0",
        "redis://default:hunter2@cache.example.com",
    ] {
        let parsed = url(raw);
        for shown in [parsed.to_string(), format!("{parsed:?}")] {
            assert!(!shown.contains("hunter2"), "{shown}");
            assert!(shown.contains("cache.example.com"), "{shown}");
        }
    }
    assert_eq!(
        url("rediss://u:p@h:1/2?x=y").to_string(),
        "rediss://h:1/2?x=y"
    );
    assert_eq!(url("redis://h").to_string(), "redis://h");
}

#[test]
fn only_redis_urls_with_a_host_are_accepted() {
    for raw in [
        "",
        "http://cache:6379",
        "cache:6379",
        "redis://",
        "rediss://user:pass@",
        "rediss:///0",
    ] {
        assert!(raw.parse::<ValkeyUrl>().is_err(), "{raw:?}");
    }
    let error = "http://x".parse::<ValkeyUrl>().unwrap_err().to_string();
    assert!(!error.contains("http://x"));
}

#[test]
fn only_the_redis_scheme_is_plaintext() {
    assert!(url("redis://h").is_plaintext());
    assert!(!url("rediss://h").is_plaintext());
}

#[test]
fn bucket_lifetime_covers_a_refill_and_is_bounded() {
    let ttl = |rate, burst| Valkey::bucket_ttl(BucketLimits::new(rate, burst).unwrap());
    assert_eq!(ttl(10.0, 100.0), Duration::from_secs(10 + 60));
    assert_eq!(ttl(0.0, 5.0), MAX_BUCKET_TTL);
    assert_eq!(ttl(0.000_001, 5.0), MAX_BUCKET_TTL);
}

#[test]
fn keys_are_namespaced_so_the_server_can_be_shared() {
    assert_eq!(Valkey::name(&StateKey::new("t", &["x"])), "apigw:t:x");
}

#[test]
fn durations_are_sent_as_at_least_one_millisecond() {
    assert_eq!(Valkey::millis(Duration::ZERO), 1);
    assert_eq!(Valkey::millis(Duration::from_secs(2)), 2000);
}

struct Container {
    name: String,
    port: u16,
    dir: Option<PathBuf>,
}

impl Container {
    fn docker(args: &[&str]) -> Output {
        Command::new("docker").args(args).output().unwrap()
    }

    fn image() -> String {
        std::env::var("APIGW_TEST_VALKEY_IMAGE").unwrap_or_else(|_| "valkey/valkey:8".to_owned())
    }

    fn start(extra: &[&str], mounts: Option<&Path>) -> Self {
        let name = format!("apigw-valkey-{}", uuid::Uuid::now_v7());
        let image = Self::image();
        let mount = mounts.map(|dir| format!("{}:/certs:ro", dir.display()));
        let mut args = vec![
            "run",
            "-d",
            "--rm",
            "--name",
            &name,
            "-p",
            "127.0.0.1::6379",
        ];
        if let Some(mount) = &mount {
            args.extend(["-v", mount]);
        }
        args.push(&image);
        args.push(if image.contains("valkey") {
            "valkey-server"
        } else {
            "redis-server"
        });
        args.extend(extra);
        let started = Self::docker(&args);
        assert!(
            started.status.success(),
            "docker run failed: {}",
            String::from_utf8_lossy(&started.stderr)
        );
        let published = Self::docker(&["port", &name, "6379/tcp"]);
        let text = String::from_utf8(published.stdout).unwrap();
        let port = text
            .lines()
            .next()
            .and_then(|line| line.rsplit(':').next())
            .and_then(|port| port.trim().parse().ok())
            .unwrap();
        Self {
            name,
            port,
            dir: mounts.map(Path::to_path_buf),
        }
    }

    fn plain() -> Self {
        Self::start(&[], None)
    }

    fn url(&self, scheme: &str) -> ValkeyUrl {
        url(&format!("{scheme}://127.0.0.1:{}", self.port))
    }

    async fn connect(&self, scheme: &str, ca: Option<&[u8]>) -> Result<Valkey, ValkeyError> {
        let url = self.url(scheme);
        let mut last = None;
        for _ in 0..50 {
            match Valkey::connect(&url, ca).await {
                Ok(valkey) => return Ok(valkey),
                Err(error) => last = Some(error),
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(last.unwrap())
    }

    fn stop(&self) {
        Self::docker(&["stop", "-t", "0", &self.name]);
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        Self::docker(&["rm", "-f", &self.name]);
        if let Some(dir) = &self.dir {
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}

fn key(name: &str) -> StateKey {
    StateKey::new("t", &[name])
}

fn limits(rate: f64, burst: f64) -> BucketLimits {
    BucketLimits::new(rate, burst).unwrap()
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_bucket_admits_its_burst_then_throttles() {
    let container = Container::plain();
    let valkey = container.connect("redis", None).await.unwrap();
    let key = key("burst");
    for _ in 0..3 {
        assert_eq!(
            valkey.take_token(&key, limits(0.0, 3.0)).await.unwrap(),
            Admission::Admitted
        );
    }
    assert_eq!(
        valkey.take_token(&key, limits(0.0, 3.0)).await.unwrap(),
        Admission::Throttled
    );
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_bucket_refills_at_its_rate() {
    let container = Container::plain();
    let valkey = container.connect("redis", None).await.unwrap();
    let key = key("refill");
    let limits = limits(20.0, 1.0);
    assert_eq!(
        valkey.take_token(&key, limits).await.unwrap(),
        Admission::Admitted
    );
    assert_eq!(
        valkey.take_token(&key, limits).await.unwrap(),
        Admission::Throttled
    );
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(
        valkey.take_token(&key, limits).await.unwrap(),
        Admission::Admitted
    );
    assert_eq!(
        valkey.take_token(&key, limits).await.unwrap(),
        Admission::Throttled
    );
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_bucket_with_no_burst_admits_nothing() {
    let container = Container::plain();
    let valkey = container.connect("redis", None).await.unwrap();
    assert_eq!(
        valkey
            .take_token(&key("zero"), limits(5.0, 0.0))
            .await
            .unwrap(),
        Admission::Throttled
    );
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn replicas_share_one_bucket() {
    let container = Container::plain();
    let first = container.connect("redis", None).await.unwrap();
    let second = container.connect("redis", None).await.unwrap();
    let key = key("shared");
    let limits = limits(0.0, 2.0);
    assert_eq!(
        first.take_token(&key, limits).await.unwrap(),
        Admission::Admitted
    );
    assert_eq!(
        second.take_token(&key, limits).await.unwrap(),
        Admission::Admitted
    );
    assert_eq!(
        first.take_token(&key, limits).await.unwrap(),
        Admission::Throttled
    );
    assert_eq!(
        second.take_token(&key, limits).await.unwrap(),
        Admission::Throttled
    );
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn concurrent_requests_never_exceed_the_burst() {
    let container = Container::plain();
    let valkey = std::sync::Arc::new(container.connect("redis", None).await.unwrap());
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..40 {
        let valkey = std::sync::Arc::clone(&valkey);
        tasks.spawn(async move {
            valkey
                .take_token(&key("race"), limits(0.0, 10.0))
                .await
                .unwrap()
        });
    }
    let mut admitted = 0_u32;
    while let Some(result) = tasks.join_next().await {
        if result.unwrap() == Admission::Admitted {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 10);
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_quota_counts_down_then_refuses_until_the_window_ends() {
    let container = Container::plain();
    let valkey = container.connect("redis", None).await.unwrap();
    let quota = QuotaLimit {
        limit: 2,
        period: QuotaPeriod::Day,
    };
    let now: Timestamp = "2030-05-06T10:00:00Z".parse().unwrap();
    let key = key("quota");
    assert_eq!(
        valkey.consume_quota(&key, quota, now).await.unwrap(),
        QuotaDecision::Allowed { remaining: 1 }
    );
    assert_eq!(
        valkey.consume_quota(&key, quota, now).await.unwrap(),
        QuotaDecision::Allowed { remaining: 0 }
    );
    let resets_at: Timestamp = "2030-05-07T00:00:00Z".parse().unwrap();
    assert_eq!(
        valkey.consume_quota(&key, quota, now).await.unwrap(),
        QuotaDecision::Exceeded { resets_at }
    );
    let tomorrow: Timestamp = "2030-05-07T00:00:01Z".parse().unwrap();
    assert_eq!(
        valkey.consume_quota(&key, quota, tomorrow).await.unwrap(),
        QuotaDecision::Allowed { remaining: 1 }
    );
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn quotas_are_counted_per_key() {
    let container = Container::plain();
    let valkey = container.connect("redis", None).await.unwrap();
    let quota = QuotaLimit {
        limit: 1,
        period: QuotaPeriod::Month,
    };
    let now: Timestamp = "2030-05-06T10:00:00Z".parse().unwrap();
    for name in ["a", "b"] {
        assert_eq!(
            valkey.consume_quota(&key(name), quota, now).await.unwrap(),
            QuotaDecision::Allowed { remaining: 0 }
        );
    }
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn cached_values_expire_and_can_be_dropped() {
    let container = Container::plain();
    let valkey = container.connect("redis", None).await.unwrap();
    let key = key("cache");
    assert_eq!(valkey.cache_get(&key).await.unwrap(), None);
    let value = Bytes::from_static(b"{\"principal\":\"u\"}");
    assert_eq!(
        valkey
            .cache_put(&key, &value, Duration::from_secs(60))
            .await
            .unwrap(),
        CacheStore::Stored
    );
    assert_eq!(valkey.cache_get(&key).await.unwrap(), Some(value.clone()));
    valkey.cache_invalidate(&key).await.unwrap();
    assert_eq!(valkey.cache_get(&key).await.unwrap(), None);

    valkey
        .cache_put(&key, &value, Duration::from_millis(100))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(valkey.cache_get(&key).await.unwrap(), None);
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn oversized_and_zero_ttl_values_are_not_cached() {
    let container = Container::plain();
    let valkey = container.connect("redis", None).await.unwrap();
    let key = key("big");
    let big = Bytes::from(vec![0_u8; MAX_CACHED_BYTES + 1]);
    assert_eq!(
        valkey
            .cache_put(&key, &big, Duration::from_secs(60))
            .await
            .unwrap(),
        CacheStore::Rejected
    );
    let small = Bytes::from_static(b"x");
    assert_eq!(
        valkey
            .cache_put(&key, &small, Duration::ZERO)
            .await
            .unwrap(),
        CacheStore::Rejected
    );
    assert_eq!(valkey.cache_get(&key).await.unwrap(), None);
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_stopped_server_answers_unavailable_within_the_timeout() {
    let container = Container::plain();
    let valkey = container.connect("redis", None).await.unwrap();
    container.stop();
    let started = std::time::Instant::now();
    let result = valkey.take_token(&key("down"), limits(1.0, 1.0)).await;
    assert!(
        matches!(result, Err(StateError::Unavailable(_))),
        "{result:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(matches!(
        valkey.cache_get(&key("down")).await,
        Err(StateError::Unavailable(_))
    ));
}

#[tokio::test]
async fn an_unreachable_server_fails_the_connection() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let error = Valkey::connect(&url(&format!("redis://u:hunter2@127.0.0.1:{port}")), None)
        .await
        .unwrap_err();
    assert!(matches!(error, ValkeyError::Connect { .. }));
    assert!(!error.to_string().contains("hunter2"));
}

#[tokio::test]
async fn an_unusable_ca_certificate_is_refused() {
    let error = Valkey::connect(&url("rediss://127.0.0.1:1"), Some(b"not a certificate"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            ValkeyError::CaCertificate(_) | ValkeyError::Connect { .. }
        ),
        "{error:?}"
    );
}

struct Pki {
    dir: PathBuf,
    ca_pem: String,
}

fn pki() -> Pki {
    let dir = std::env::temp_dir().join(format!("apigw-valkey-pki-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
    leaf_params.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().unwrap())];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();
    for (name, contents) in [
        ("ca.crt", ca.pem()),
        ("server.crt", leaf.pem()),
        ("server.key", leaf_key.serialize_pem()),
    ] {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
    }
    Pki {
        ca_pem: ca.pem(),
        dir,
    }
}

fn tls_container(pki: &Pki) -> Container {
    Container::start(
        &[
            "--port",
            "0",
            "--tls-port",
            "6379",
            "--tls-cert-file",
            "/certs/server.crt",
            "--tls-key-file",
            "/certs/server.key",
            "--tls-ca-cert-file",
            "/certs/ca.crt",
            "--tls-auth-clients",
            "no",
        ],
        Some(&pki.dir),
    )
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn rediss_connects_when_the_ca_is_trusted() {
    let pki = pki();
    let container = tls_container(&pki);
    let valkey = container
        .connect("rediss", Some(pki.ca_pem.as_bytes()))
        .await
        .unwrap();
    assert_eq!(
        valkey
            .take_token(&key("tls"), limits(0.0, 1.0))
            .await
            .unwrap(),
        Admission::Admitted
    );
    assert_eq!(
        valkey
            .take_token(&key("tls"), limits(0.0, 1.0))
            .await
            .unwrap(),
        Admission::Throttled
    );
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn rediss_refuses_a_server_the_ca_does_not_vouch_for() {
    let pki = pki();
    let container = tls_container(&pki);
    container
        .connect("rediss", Some(pki.ca_pem.as_bytes()))
        .await
        .unwrap();
    let error = Valkey::connect(&container.url("rediss"), None)
        .await
        .unwrap_err();
    assert!(matches!(error, ValkeyError::Connect { .. }), "{error:?}");
}
