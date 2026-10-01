//! TLS connection accept loop. Every listener terminates TLS (rustls with
//! aws-lc-rs); there is no plaintext mode.
//!
//! `axum::serve` builds hyper's connection builder privately and never installs
//! a [`hyper::rt::Timer`], so hyper's HTTP/1 header read timeout silently
//! becomes "no timeout": a client that sends nothing, or dribbles a request head
//! one byte at a time, holds a connection open indefinitely. This module drives
//! hyper directly so the timer can be installed.
//!
//! Each accepted connection runs in its own task:
//!
//! ```text
//! accept → set_nodelay → connection cap → spawn → PROXY header (timeout)
//!   → TLS handshake (timeout) → hyper-util auto HTTP/1 or HTTP/2 (TokioTimer, idle limit)
//! ```
//!
//! The task is spawned before any per-connection I/O, so a client that stalls
//! its TLS handshake occupies only its own task and never blocks `accept`.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, PoisonError, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use proxy_header::io::ProxiedStream;
use proxy_header::{ParseConfig, Protocol};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

use crate::domain::DomainName;
use crate::header_case::{HeaderCaseQueue, HeaderCaseTap};
use crate::identity::TrustedProxies;

/// Time limits applied to every connection.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnLimits {
    /// From TCP accept to a complete PROXY protocol header, on a listener that
    /// requires one.
    pub(crate) proxy_header: Duration,
    /// From the end of the PROXY header (or TCP accept, without one) to a
    /// finished TLS handshake.
    pub(crate) handshake: Duration,
    /// hyper's HTTP/1 header read timeout, and the idle limit: a connection with
    /// no request in flight for this long is closed. The idle limit covers what
    /// hyper leaves unbounded: protocol detection before the first bytes arrive,
    /// and HTTP/2, which has no header timer.
    pub(crate) header_read: Duration,
    pub(crate) h2_keep_alive_interval: Duration,
    pub(crate) h2_keep_alive_timeout: Duration,
    /// After shutdown is signalled, how long in-flight connections get to finish.
    pub(crate) drain: Duration,
}

impl ConnLimits {
    /// `drain` covers API Gateway's longest default integration timeout (30s), so
    /// shutdown never cuts off a request that could still have completed.
    pub(crate) const DEFAULT: Self = Self {
        // The PROXY protocol spec (proxy-protocol.txt section 2) lets the
        // receiver time out a missing header, "at least 3 seconds to cover a TCP
        // retransmit".
        proxy_header: Duration::from_secs(5),
        handshake: Duration::from_secs(5),
        header_read: Duration::from_secs(10),
        h2_keep_alive_interval: Duration::from_secs(20),
        h2_keep_alive_timeout: Duration::from_secs(20),
        drain: Duration::from_secs(30),
    };
}

/// Server TLS for a listener. The certificate is read from PEM files and
/// swapped in place when those files change, so rotation (cert-manager, certbot,
/// a remounted secret) needs no restart.
#[derive(Clone)]
pub(crate) struct Tls {
    acceptor: TlsAcceptor,
    certs: Arc<CertSet>,
}

/// The PEM files of a custom domain's certificate.
#[derive(Debug, Clone)]
pub(crate) struct DomainCert {
    pub(crate) name: DomainName,
    pub(crate) cert: PathBuf,
    pub(crate) key: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum TlsError {
    #[error("failed to read certificate chain {path}: {source}")]
    Certificates {
        path: String,
        source: rustls::pki_types::pem::Error,
    },
    #[error("{0} contains no certificates")]
    NoCertificates(String),
    #[error("failed to read private key {path}: {source}")]
    PrivateKey {
        path: String,
        source: rustls::pki_types::pem::Error,
    },
    #[error("invalid TLS certificate or key: {0}")]
    Config(#[from] rustls::Error),
}

/// Identifies one version of the PEM files on disk. `metadata` follows
/// symlinks, so a Kubernetes secret's atomic symlink swap changes it too.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp(
    Option<(std::time::SystemTime, u64)>,
    Option<(std::time::SystemTime, u64)>,
);

impl FileStamp {
    fn read(cert_path: &Path, key_path: &Path) -> Self {
        let stamp = |path: &Path| {
            std::fs::metadata(path)
                .ok()
                .and_then(|m| m.modified().ok().map(|modified| (modified, m.len())))
        };
        Self(stamp(cert_path), stamp(key_path))
    }
}

#[derive(Debug)]
struct CertStore {
    cert_path: PathBuf,
    key_path: PathBuf,
    provider: Arc<rustls::crypto::CryptoProvider>,
    current: RwLock<(FileStamp, Arc<CertifiedKey>)>,
}

fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
    provider: &rustls::crypto::CryptoProvider,
) -> Result<CertifiedKey, TlsError> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|source| TlsError::Certificates {
            path: cert_path.display().to_string(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(cert_path.display().to_string()));
    }
    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|source| TlsError::PrivateKey {
        path: key_path.display().to_string(),
        source,
    })?;
    Ok(CertifiedKey::from_der(certs, key, provider)?)
}

impl CertStore {
    fn open(
        cert_path: &Path,
        key_path: &Path,
        provider: &Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, TlsError> {
        let stamp = FileStamp::read(cert_path, key_path);
        let key = load_certified_key(cert_path, key_path, provider)?;
        Ok(Self {
            cert_path: cert_path.to_owned(),
            key_path: key_path.to_owned(),
            provider: Arc::clone(provider),
            current: RwLock::new((stamp, Arc::new(key))),
        })
    }

    fn load(&self) -> Result<CertifiedKey, TlsError> {
        load_certified_key(&self.cert_path, &self.key_path, &self.provider)
    }

    fn current(&self) -> std::sync::RwLockReadGuard<'_, (FileStamp, Arc<CertifiedKey>)> {
        self.current.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn certified(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.current().1)
    }

    /// Reloads the certificate if its files changed. A file that fails to load
    /// leaves the previous certificate in place.
    fn reload_if_changed(&self) -> Result<bool, TlsError> {
        let stamp = FileStamp::read(&self.cert_path, &self.key_path);
        if self.current().0 == stamp {
            return Ok(false);
        }
        let key = self.load()?;
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = (stamp, Arc::new(key));
        Ok(true)
    }
}

/// The default certificate and one per custom domain, chosen by the client's
/// SNI. A client that sends no SNI, or one no domain matches, gets the default.
#[derive(Debug)]
struct CertSet {
    default: CertStore,
    domains: Vec<(DomainName, CertStore)>,
}

impl CertSet {
    fn stores(&self) -> impl Iterator<Item = &CertStore> {
        std::iter::once(&self.default).chain(self.domains.iter().map(|(_, store)| store))
    }

    /// An exact domain name wins over a wildcard that also matches.
    fn store_for(&self, server_name: &str) -> &CertStore {
        let exact = self
            .domains
            .iter()
            .find(|(name, _)| !name.as_str().starts_with("*.") && name.matches(server_name));
        exact
            .or_else(|| {
                self.domains
                    .iter()
                    .find(|(name, _)| name.matches(server_name))
            })
            .map_or(&self.default, |(_, store)| store)
    }
}

impl ResolvesServerCert for CertSet {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let store = client_hello
            .server_name()
            .map_or(&self.default, |name| self.store_for(name));
        Some(store.certified())
    }
}

impl Tls {
    /// Server TLS with aws-lc-rs from PEM files; HTTP/2 is offered via ALPN.
    #[cfg(test)]
    pub(crate) fn from_pem_files(cert_path: &Path, key_path: &Path) -> Result<Self, TlsError> {
        Self::with_domains(cert_path, key_path, &[])
    }

    /// As [`Tls::from_pem_files`], with a certificate per custom domain served
    /// to clients whose SNI names the domain.
    pub(crate) fn with_domains(
        cert_path: &Path,
        key_path: &Path,
        domains: &[DomainCert],
    ) -> Result<Self, TlsError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut stores = Vec::with_capacity(domains.len());
        for domain in domains {
            stores.push((
                domain.name.clone(),
                CertStore::open(&domain.cert, &domain.key, &provider)?,
            ));
        }
        let certs = Arc::new(CertSet {
            default: CertStore::open(cert_path, key_path, &provider)?,
            domains: stores,
        });
        let resolver: Arc<dyn ResolvesServerCert> = Arc::<CertSet>::clone(&certs);
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            certs,
        })
    }

    /// Reloads every certificate whose files changed. A file that fails to load
    /// leaves that certificate's previous version in place; the first failure is
    /// returned after every store has been tried.
    pub(crate) fn reload_if_changed(&self) -> Result<bool, TlsError> {
        let mut reloaded = false;
        let mut failure = None;
        for store in self.certs.stores() {
            match store.reload_if_changed() {
                Ok(true) => {
                    tracing::info!(cert = %store.cert_path.display(), "reloaded TLS certificate");
                    reloaded = true;
                }
                Ok(false) => {}
                Err(err) => {
                    failure.get_or_insert(err);
                }
            }
        }
        failure.map_or(Ok(reloaded), Err)
    }

    /// Polls the PEM files every `interval` until `shutdown` is cancelled.
    pub(crate) async fn watch(self, interval: Duration, shutdown: CancellationToken) {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = shutdown.cancelled() => return,
                _ = ticker.tick() => {}
            }
            match self.reload_if_changed() {
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!(%err, "TLS certificate changed but failed to load; keeping the previous one");
                }
            }
        }
    }
}

/// The stream the TLS handshake starts from: the accepted TCP stream, after any
/// PROXY protocol header. Bytes read past the header (the start of the TLS
/// `ClientHello`, when both arrive in one segment) are replayed on the first read.
type ClientStream = ProxiedStream<TcpStream>;

/// PROXY protocol v2 on one listener.
///
/// A TCP proxy that relays TLS without terminating it (Istio/Envoy
/// `PASSTHROUGH`, nginx `stream`, `HAProxy` `mode tcp`) opens its own connection
/// and cannot add `X-Forwarded-For` to ciphertext; it sends the client's address
/// in a PROXY header ahead of the relayed bytes instead.
///
/// The spec (<https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>)
/// shapes each rule here:
///
/// - section 2: the receiver "MUST not try to guess whether the protocol header
///   is present or not". On an enabled listener the header is required.
/// - section 2: "only trusted proxies are allowed to use this protocol". A
///   connection from outside `--trusted-proxies` is closed before anything is
///   read.
/// - section 2: the receiver "MUST NOT start processing the connection before
///   it receives a complete and valid PROXY protocol header". The header is read
///   in full, under [`ConnLimits::proxy_header`], before the TLS handshake.
///
/// Only v2 is accepted: the load balancers and gateways this is for send v2,
/// and turning v1 off keeps the text parser out of reach.
#[derive(Clone, Debug)]
pub(crate) struct ProxyProtocol {
    pub(crate) required_from: Option<TrustedProxies>,
}

#[derive(Debug, thiserror::Error)]
enum ProxyHeaderError {
    #[error("peer is outside --trusted-proxies")]
    Untrusted,
    #[error("header refused: {0}")]
    Invalid(#[from] io::Error),
    #[error("header timed out")]
    TimedOut,
}

/// v2 only, and no TLVs: nothing reads them.
const PROXY_PARSE: ParseConfig = ParseConfig {
    include_tlvs: false,
    allow_v1: false,
    allow_v2: true,
};

impl ProxyProtocol {
    /// The PROXY protocol is off: the TCP peer is the client.
    pub(crate) fn off() -> Self {
        Self {
            required_from: None,
        }
    }

    /// Require a PROXY header from peers `trusted` covers.
    pub(crate) fn required_from(trusted: TrustedProxies) -> Self {
        Self {
            required_from: Some(trusted),
        }
    }

    /// Reads the header from `tcp`, returning the stream after it and the
    /// client's address. Without the protocol the stream is untouched and the
    /// TCP peer is the client.
    ///
    /// A `LOCAL` header (the proxy's own health check) carries no address, and
    /// the spec says the receiver "must use the real connection endpoints"; the
    /// same holds for a `PROXY` command with an `UNSPEC` or `AF_UNIX` family.
    /// Both keep `tcp_peer`, which is the proxy. A UDP address cannot describe a
    /// TCP connection, so it is refused.
    async fn accept(
        &self,
        tcp: TcpStream,
        tcp_peer: SocketAddr,
        limit: Duration,
    ) -> Result<(ClientStream, SocketAddr), ProxyHeaderError> {
        let Some(ref trusted) = self.required_from else {
            return Ok((ProxiedStream::unproxied(tcp), tcp_peer));
        };
        if !trusted.contains(tcp_peer.ip()) {
            return Err(ProxyHeaderError::Untrusted);
        }
        let stream =
            tokio::time::timeout(limit, ProxiedStream::create_from_tokio(tcp, PROXY_PARSE))
                .await
                .map_err(|_| ProxyHeaderError::TimedOut)??;
        let client = match stream.proxy_header().proxied_address() {
            None => tcp_peer,
            Some(addr) if addr.protocol == Protocol::Stream => addr.source,
            Some(_) => {
                return Err(ProxyHeaderError::Invalid(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PROXY header describes a datagram connection",
                )));
            }
        };
        Ok((stream, client))
    }
}

/// Who may be a proxy in front of a listener, and what each connection must
/// send first.
#[derive(Clone, Debug)]
pub(crate) struct Edge {
    pub(crate) trusted: TrustedProxies,
    pub(crate) proxy_protocol: ProxyProtocol,
}

impl Edge {
    /// A listener with no proxy in front of it: the TCP peer is the client.
    pub(crate) fn direct() -> Self {
        Self {
            trusted: TrustedProxies::none(),
            proxy_protocol: ProxyProtocol::off(),
        }
    }
}

/// What every connection of one listener shares.
#[derive(Clone)]
struct ConnShared {
    tls: TlsAcceptor,
    app: Router,
    limits: ConnLimits,
    edge: Edge,
}

/// Serve `app` on `listener` until `shutdown` is cancelled, then give open
/// connections [`ConnLimits::drain`] to finish. At most `max_connections` are
/// served at once; further clients wait in the kernel backlog.
pub(crate) async fn serve(
    listener: TcpListener,
    tls: Tls,
    app: Router,
    limits: ConnLimits,
    max_connections: usize,
    edge: Edge,
    shutdown: CancellationToken,
) {
    let slots = Arc::new(Semaphore::new(max_connections));
    let shared = ConnShared {
        tls: tls.acceptor.clone(),
        app,
        limits,
        edge,
    };
    let mut conns = JoinSet::new();

    loop {
        let accepted = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            Some(_) = conns.join_next(), if !conns.is_empty() => continue,
            accepted = listener.accept() => accepted,
        };
        let (tcp, peer) = match accepted {
            Ok(conn) => conn,
            Err(err) => {
                handle_accept_error(err).await;
                continue;
            }
        };
        if let Err(err) = tcp.set_nodelay(true) {
            tracing::trace!("failed to set TCP_NODELAY on incoming connection: {err:#}");
        }
        let slot = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            slot = Arc::clone(&slots).acquire_owned() => slot,
        };
        // The semaphore is never closed, so this branch cannot drop a connection.
        let Ok(slot) = slot else { continue };
        conns.spawn(serve_connection(
            tcp,
            peer,
            slot,
            shared.clone(),
            shutdown.clone(),
        ));
    }

    drop(listener);
    let drained = tokio::time::timeout(limits.drain, async {
        while conns.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tracing::warn!(
            remaining = conns.len(),
            "connections still open after the {}s drain timeout; closing them",
            limits.drain.as_secs()
        );
        conns.shutdown().await;
    }
}

/// Mirror `axum::serve`: per-connection errors are the client's business;
/// anything else (for example `EMFILE`) backs off so the loop does not spin.
async fn handle_accept_error(err: io::Error) {
    if matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) {
        return;
    }
    tracing::error!("accept error: {err}");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

/// Largest HTTP/2 header list hyper accepts. hyper's default (16 KiB) is below
/// REST APIs' 20,480 byte header quota; requests between the quota and this
/// ceiling reach [`crate::limits`], which answers as API Gateway does.
const H2_MAX_HEADER_LIST_BYTES: u32 = 64 * 1024;

/// Drive one connection from handshake to close. `_slot` holds the connection's
/// place under the connection cap until it closes.
async fn serve_connection(
    tcp: TcpStream,
    tcp_peer: SocketAddr,
    _slot: OwnedSemaphorePermit,
    shared: ConnShared,
    shutdown: CancellationToken,
) {
    let ConnShared {
        tls,
        app,
        limits,
        edge,
    } = shared;
    let header = edge
        .proxy_protocol
        .accept(tcp, tcp_peer, limits.proxy_header);
    let (stream, peer) = tokio::select! {
        () = shutdown.cancelled() => return,
        header = header => match header {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::debug!(remote_addr = %tcp_peer, "PROXY protocol connection refused: {err}");
                return;
            }
        },
    };
    let handshake = tokio::time::timeout(limits.handshake, tls.accept(stream));
    let io = tokio::select! {
        () = shutdown.cancelled() => return,
        handshake = handshake => match handshake {
            Ok(Ok(io)) => io,
            Ok(Err(err)) => {
                tracing::debug!(remote_addr = %peer, "handshake failed: {err}");
                return;
            }
            Err(_) => {
                tracing::debug!(remote_addr = %peer, "handshake timed out");
                return;
            }
        },
    };

    let activity = Activity::default();
    let idle = activity.subscribe();
    let header_case = HeaderCaseQueue::default();
    let io = HeaderCaseTap::new(io, header_case.clone());
    let service =
        TowerToHyperService::new(tower::service_fn(move |req: hyper::Request<Incoming>| {
            let mut req = req.map(Body::new);
            let identity = edge.trusted.identify(peer, req.headers_mut());
            req.extensions_mut().insert(identity);
            if let Some(spelling) = header_case.pop() {
                req.extensions_mut().insert(spelling);
            }
            let in_flight = activity.begin();
            let response = app.clone().oneshot(req);
            async move {
                let response = response.await?;
                Ok::<_, Infallible>(response.map(|inner| TrackedBody {
                    inner,
                    _in_flight: in_flight,
                }))
            }
        }));

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(limits.h2_keep_alive_interval)
        .keep_alive_timeout(limits.h2_keep_alive_timeout)
        .max_header_list_size(H2_MAX_HEADER_LIST_BYTES);
    let conn = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    tokio::pin!(conn);
    let result = tokio::select! {
        result = conn.as_mut() => result,
        () = shutdown.cancelled() => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
        () = idle_for(idle, limits.header_read) => {
            tracing::debug!(remote_addr = %peer, "closing idle connection");
            // HTTP/2 graceful shutdown sends GOAWAY and then waits for the client
            // to acknowledge a PING, which a stalling client never does; give it
            // one more idle period, then drop.
            conn.as_mut().graceful_shutdown();
            tokio::time::timeout(limits.header_read, conn)
                .await
                .unwrap_or(Ok(()))
        }
    };
    if let Err(err) = result {
        tracing::trace!(remote_addr = %peer, "connection error: {err:#}");
    }
}

/// Count of requests in flight on one connection, from dispatch until the
/// response body has been sent.
#[derive(Clone, Default)]
struct Activity(Arc<watch::Sender<usize>>);

impl Activity {
    fn begin(&self) -> InFlight {
        self.0.send_modify(|n| *n = n.saturating_add(1));
        InFlight(Arc::clone(&self.0))
    }

    fn subscribe(&self) -> watch::Receiver<usize> {
        self.0.subscribe()
    }
}

struct InFlight(Arc<watch::Sender<usize>>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n = n.saturating_sub(1));
    }
}

/// Resolve once no request has been in flight for `idle`.
async fn idle_for(mut in_flight: watch::Receiver<usize>, idle: Duration) {
    loop {
        let busy = *in_flight.borrow_and_update() > 0;
        let changed = if busy {
            in_flight.changed().await
        } else {
            tokio::select! {
                () = tokio::time::sleep(idle) => return,
                changed = in_flight.changed() => changed,
            }
        };
        if changed.is_err() {
            // Every sender is gone, so the connection is finishing on its own.
            std::future::pending::<()>().await;
        }
    }
}

/// A response body that keeps its request counted as in flight until hyper has
/// finished sending it.
struct TrackedBody {
    inner: Body,
    _in_flight: InFlight,
}

impl HttpBody for TrackedBody {
    type Data = <Body as HttpBody>::Data;
    type Error = <Body as HttpBody>::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test helpers panic on broken setup")]
pub(crate) mod test_tls {
    //! A self-signed certificate for `localhost` and a client that trusts it.

    use std::sync::Arc;

    use std::path::PathBuf;

    use rustls::pki_types::{CertificateDer, ServerName};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::client::TlsStream;

    use super::Tls;

    pub(crate) struct TestCert {
        cert: CertificateDer<'static>,
        pub(crate) cert_pem: String,
        pub(crate) key_pem: String,
    }

    pub(crate) fn generate() -> TestCert {
        generate_for(&["localhost"])
    }

    /// A self-signed certificate valid for `names`.
    pub(crate) fn generate_for(names: &[&str]) -> TestCert {
        let certified = rcgen::generate_simple_self_signed(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        TestCert {
            cert: certified.cert.der().clone(),
            cert_pem: certified.cert.pem(),
            key_pem: certified.signing_key.serialize_pem(),
        }
    }

    impl TestCert {
        /// Writes the PEM files to a fresh directory and returns their paths.
        pub(crate) fn write(&self) -> (PathBuf, PathBuf) {
            let dir = std::env::temp_dir().join(format!("apigw-tls-{}", uuid::Uuid::now_v7()));
            std::fs::create_dir_all(&dir).unwrap();
            let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
            std::fs::write(&cert, &self.cert_pem).unwrap();
            std::fs::write(&key, &self.key_pem).unwrap();
            (cert, key)
        }

        pub(crate) fn server(&self) -> Tls {
            let (cert, key) = self.write();
            Tls::from_pem_files(&cert, &key).unwrap()
        }

        pub(crate) async fn connect(&self, addr: std::net::SocketAddr) -> TlsStream<TcpStream> {
            self.connect_after(addr, b"").await
        }

        /// Connects, writes `prefix` (a PROXY header) on the bare TCP stream, then
        /// starts the TLS handshake.
        pub(crate) async fn connect_after(
            &self,
            addr: std::net::SocketAddr,
            prefix: &[u8],
        ) -> TlsStream<TcpStream> {
            self.try_connect_after(addr, prefix).await.unwrap()
        }

        /// [`Self::connect_after`] that reports a refused handshake.
        pub(crate) async fn try_connect_after(
            &self,
            addr: std::net::SocketAddr,
            prefix: &[u8],
        ) -> std::io::Result<TlsStream<TcpStream>> {
            self.try_connect_as(addr, prefix, "localhost").await
        }

        /// [`Self::try_connect_after`] announcing `server_name` as the SNI.
        pub(crate) async fn try_connect_as(
            &self,
            addr: std::net::SocketAddr,
            prefix: &[u8],
            server_name: &str,
        ) -> std::io::Result<TlsStream<TcpStream>> {
            use tokio::io::AsyncWriteExt as _;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(self.cert.clone()).unwrap();
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let mut tcp = TcpStream::connect(addr).await.unwrap();
            tcp.write_all(prefix).await?;
            TlsConnector::from(Arc::new(config))
                .connect(ServerName::try_from(server_name.to_owned()).unwrap(), tcp)
                .await
        }

        /// Sends one HTTP/1.1 request and returns the raw response.
        pub(crate) async fn request(
            &self,
            addr: std::net::SocketAddr,
            head: &str,
            body: &[u8],
        ) -> String {
            self.request_after(addr, b"", head, body).await
        }

        /// [`Self::request`] after a PROXY header written ahead of the handshake.
        pub(crate) async fn request_after(
            &self,
            addr: std::net::SocketAddr,
            prefix: &[u8],
            head: &str,
            body: &[u8],
        ) -> String {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut stream = self.connect_after(addr, prefix).await;
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            let mut out = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                stream.read_to_end(&mut out),
            )
            .await
            .unwrap()
            .unwrap();
            String::from_utf8_lossy(&out).into_owned()
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good setup")]
mod tests {
    use axum::Extension;
    use axum::http::HeaderMap;
    use axum::routing::{any, get};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use crate::header_case::HeaderCase;
    use crate::identity::ClientIdentity;

    use super::test_tls::{TestCert, generate, generate_for};
    use super::*;

    const SHORT: ConnLimits = ConnLimits {
        proxy_header: Duration::from_millis(300),
        handshake: Duration::from_millis(300),
        header_read: Duration::from_millis(300),
        h2_keep_alive_interval: Duration::from_secs(20),
        h2_keep_alive_timeout: Duration::from_secs(20),
        drain: Duration::from_secs(5),
    };
    const BOUND: Duration = Duration::from_secs(10);
    const GET_PEER: &str = "GET /peer HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n";

    /// `/peer` answers with the request's source IP; `/forwarded` with the
    /// `X-Forwarded-For` and `X-Forwarded-Client-Cert` an integration would see.
    fn app() -> Router {
        Router::new()
            .route(
                "/peer",
                get(
                    |Extension(identity): Extension<ClientIdentity>| async move {
                        identity
                            .source_ip()
                            .ip()
                            .map_or_else(|| "unknown".to_owned(), |ip| ip.to_string())
                    },
                ),
            )
            .route(
                "/spelling",
                any(|request: axum::extract::Request| async move {
                    request
                        .extensions()
                        .get::<HeaderCase>()
                        .map_or("none", |case| case.spelling("x-mixed-case"))
                        .to_owned()
                }),
            )
            .route(
                "/forwarded",
                get(|headers: HeaderMap| async move {
                    let show = |name: &str| {
                        headers
                            .get(name)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("-")
                            .to_owned()
                    };
                    format!(
                        "{}|{}",
                        show("x-forwarded-for"),
                        show("x-forwarded-client-cert")
                    )
                }),
            )
    }

    async fn start(
        cert: &TestCert,
        max_connections: usize,
    ) -> (SocketAddr, CancellationToken, tokio::task::JoinHandle<()>) {
        start_with(cert, SHORT, max_connections, Edge::direct()).await
    }

    async fn start_with(
        cert: &TestCert,
        limits: ConnLimits,
        max_connections: usize,
        edge: Edge,
    ) -> (SocketAddr, CancellationToken, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(serve(
            listener,
            cert.server(),
            app(),
            limits,
            max_connections,
            edge,
            shutdown.clone(),
        ));
        (addr, shutdown, handle)
    }

    fn trusting(nets: &[&str], hops: u8) -> TrustedProxies {
        let nets: Vec<_> = nets.iter().map(|net| net.parse().unwrap()).collect();
        TrustedProxies::new(&nets, std::num::NonZeroU8::new(hops).unwrap())
    }

    fn proxied(nets: &[&str]) -> Edge {
        let trusted = trusting(nets, 1);
        Edge {
            proxy_protocol: ProxyProtocol::required_from(trusted.clone()),
            trusted,
        }
    }

    #[tokio::test]
    async fn serves_requests_over_tls_with_a_client_identity() {
        let cert = generate();
        let (addr, shutdown, handle) = start(&cert, 8).await;
        let response = cert.request(addr, GET_PEER, b"").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("127.0.0.1"), "{response}");
        shutdown.cancel();
        tokio::time::timeout(BOUND, handle).await.unwrap().unwrap();
    }

    /// Starts a listener whose default certificate is `default` and whose
    /// custom domains have the certificates given.
    async fn start_domains(
        default: &TestCert,
        domains: &[(&str, &TestCert)],
    ) -> (SocketAddr, CancellationToken) {
        let (cert, key) = default.write();
        let domains: Vec<DomainCert> = domains
            .iter()
            .map(|(name, domain)| {
                let (cert, key) = domain.write();
                DomainCert {
                    name: name.parse().unwrap(),
                    cert,
                    key,
                }
            })
            .collect();
        let tls = Tls::with_domains(&cert, &key, &domains).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        tokio::spawn(serve(
            listener,
            tls,
            app(),
            SHORT,
            8,
            Edge::direct(),
            shutdown.clone(),
        ));
        (addr, shutdown)
    }

    #[tokio::test]
    async fn each_domain_is_served_its_own_certificate_by_sni() {
        let default = generate_for(&["localhost", "unmapped.example.test"]);
        let api = generate_for(&["api.example.test"]);
        let wild = generate_for(&["a.wild.example.test"]);
        let exact = generate_for(&["b.wild.example.test"]);
        let (addr, shutdown) = start_domains(
            &default,
            &[
                ("api.example.test", &api),
                ("*.wild.example.test", &wild),
                ("b.wild.example.test", &exact),
            ],
        )
        .await;
        // Each client trusts only the certificate it expects, so a handshake
        // succeeds only when the server picked that certificate.
        assert!(
            api.try_connect_as(addr, b"", "api.example.test")
                .await
                .is_ok()
        );
        assert!(
            wild.try_connect_as(addr, b"", "a.wild.example.test")
                .await
                .is_ok()
        );
        assert!(
            exact
                .try_connect_as(addr, b"", "b.wild.example.test")
                .await
                .is_ok(),
            "an exact name wins over a wildcard"
        );
        assert!(
            default
                .try_connect_as(addr, b"", "unmapped.example.test")
                .await
                .is_ok(),
            "unknown names get the default certificate"
        );
        assert!(default.try_connect_as(addr, b"", "localhost").await.is_ok());
        assert!(
            default
                .try_connect_as(addr, b"", "api.example.test")
                .await
                .is_err(),
            "a mapped name does not get the default certificate"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn domain_certificates_reload_when_their_files_change() {
        let default = generate();
        let first = generate_for(&["api.example.test"]);
        let (cert_path, key_path) = first.write();
        let (default_cert, default_key) = default.write();
        let tls = Tls::with_domains(
            &default_cert,
            &default_key,
            &[DomainCert {
                name: "api.example.test".parse().unwrap(),
                cert: cert_path.clone(),
                key: key_path.clone(),
            }],
        )
        .unwrap();
        assert!(!tls.reload_if_changed().unwrap());
        let second = generate_for(&["api.example.test"]);
        std::fs::write(&cert_path, &second.cert_pem).unwrap();
        std::fs::write(&key_path, &second.key_pem).unwrap();
        assert!(tls.reload_if_changed().unwrap());
        assert!(!tls.reload_if_changed().unwrap());
    }

    #[tokio::test]
    async fn http1_requests_keep_the_clients_header_spelling_across_a_keep_alive_connection() {
        let cert = generate();
        let (addr, shutdown, handle) = start(&cert, 8).await;
        let requests = "POST /spelling HTTP/1.1\r\nhost: localhost\r\nX-Mixed-Case: x\r\ncontent-length: 5\r\n\r\nX: y!\
GET /spelling HTTP/1.1\r\nhost: localhost\r\nx-MIXED-case: x\r\nconnection: close\r\n\r\n";
        let response = cert.request(addr, requests, b"").await;
        let first = response.find("X-Mixed-Case").unwrap_or(usize::MAX);
        let second = response.find("x-MIXED-case").unwrap_or(usize::MAX);
        assert!(first < second, "{response}");
        shutdown.cancel();
        tokio::time::timeout(BOUND, handle).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_plaintext_http() {
        let cert = generate();
        let (addr, shutdown, _handle) = start(&cert, 8).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(GET_PEER.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let read = tokio::time::timeout(BOUND, stream.read_to_end(&mut buf))
            .await
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&buf).contains("HTTP/1.1 200"),
            "{read:?}"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn closes_connections_that_stall_the_handshake() {
        let cert = generate();
        let (addr, shutdown, _handle) = start(&cert, 8).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut buf = Vec::new();
        let read = tokio::time::timeout(BOUND, stream.read_to_end(&mut buf)).await;
        assert!(read.is_ok(), "stalled handshake was not disconnected");
        shutdown.cancel();
    }

    #[tokio::test]
    async fn closes_connections_that_never_finish_headers() {
        let cert = generate();
        let (addr, shutdown, _handle) = start(&cert, 8).await;
        let mut stream = cert.connect(addr).await;
        stream.write_all(b"GET /peer HTTP/1.1\r\n").await.unwrap();
        let mut buf = Vec::new();
        let read = tokio::time::timeout(BOUND, stream.read_to_end(&mut buf)).await;
        assert!(read.is_ok(), "slow client was not disconnected");
        shutdown.cancel();
    }

    #[tokio::test]
    async fn connection_cap_queues_extra_clients() {
        let cert = Arc::new(generate());
        let (addr, shutdown, _handle) = start(&cert, 1).await;
        let held = cert.connect(addr).await;
        let waiting = {
            let cert = Arc::clone(&cert);
            tokio::spawn(async move { cert.request(addr, GET_PEER, b"").await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !waiting.is_finished(),
            "second client was served while the cap was held"
        );
        drop(held);
        let response = tokio::time::timeout(BOUND, waiting).await.unwrap().unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        shutdown.cancel();
    }

    #[test]
    fn rejects_missing_empty_and_mismatched_pem_files() {
        let cert = generate();
        let (cert_path, key_path) = cert.write();
        let dir = cert_path.parent().unwrap();
        let missing = dir.join("missing.pem");
        assert!(matches!(
            Tls::from_pem_files(&missing, &key_path),
            Err(TlsError::Certificates { .. })
        ));
        assert!(matches!(
            Tls::from_pem_files(&cert_path, &missing),
            Err(TlsError::PrivateKey { .. })
        ));
        let empty = dir.join("empty.pem");
        std::fs::write(&empty, b"").unwrap();
        assert!(matches!(
            Tls::from_pem_files(&empty, &key_path),
            Err(TlsError::NoCertificates(_))
        ));
        let (_, other_key) = generate().write();
        assert!(matches!(
            Tls::from_pem_files(&cert_path, &other_key),
            Err(TlsError::Config(_))
        ));
    }

    #[tokio::test]
    async fn reloads_certificates_when_files_change() {
        let first = generate();
        let (cert_path, key_path) = first.write();
        let tls = Tls::from_pem_files(&cert_path, &key_path).unwrap();
        assert!(!tls.reload_if_changed().unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/peer", get(|| async { "ok" }));
        let shutdown = CancellationToken::new();
        tokio::spawn(serve(
            listener,
            tls.clone(),
            app,
            SHORT,
            8,
            Edge::direct(),
            shutdown.clone(),
        ));
        assert!(
            first
                .request(addr, GET_PEER, b"")
                .await
                .starts_with("HTTP/1.1 200")
        );

        // A broken write is ignored and the old certificate keeps serving.
        std::fs::write(&cert_path, b"garbage").unwrap();
        assert!(tls.reload_if_changed().is_err());
        assert!(
            first
                .request(addr, GET_PEER, b"")
                .await
                .starts_with("HTTP/1.1 200")
        );

        let second = generate();
        std::fs::write(&cert_path, &second.cert_pem).unwrap();
        std::fs::write(&key_path, &second.key_pem).unwrap();
        assert!(tls.reload_if_changed().unwrap());
        assert!(
            second
                .request(addr, GET_PEER, b"")
                .await
                .starts_with("HTTP/1.1 200")
        );
        shutdown.cancel();
    }

    const GET_FORWARDED: &str = "GET /forwarded HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\nx-forwarded-for: 203.0.113.9\r\nx-forwarded-client-cert: Hash=abc\r\n\r\n";
    const LOOPBACK: &[&str] = &["127.0.0.0/8"];

    fn get_peer_with_forwarded() -> String {
        GET_FORWARDED.replace("/forwarded", "/peer")
    }

    fn body(response: &str) -> &str {
        response.rsplit("\r\n\r\n").next().unwrap_or_default()
    }

    async fn serves(cert: &TestCert, edge: Edge, prefix: &[u8], request: &str) -> String {
        let (addr, shutdown, _handle) = start_with(cert, SHORT, 8, edge).await;
        let response = cert.request_after(addr, prefix, request, b"").await;
        shutdown.cancel();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        body(&response).to_owned()
    }

    fn trusting_loopback() -> Edge {
        Edge {
            trusted: trusting(LOOPBACK, 1),
            proxy_protocol: ProxyProtocol::off(),
        }
    }

    /// A PROXY v2 header for a TCP connection from `source`.
    fn proxy_v2(source: &str) -> Vec<u8> {
        let header = proxy_header::ProxyHeader::with_address(proxy_header::ProxiedAddress::stream(
            source.parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
        ));
        let mut buf = Vec::new();
        header.encode_v2(&mut buf).unwrap();
        buf
    }

    /// Whether the server closes a connection that starts with `prefix` before
    /// the TLS handshake completes.
    async fn handshake_refused(cert: &TestCert, addr: SocketAddr, prefix: &[u8]) -> bool {
        tokio::time::timeout(BOUND, cert.try_connect_after(addr, prefix))
            .await
            .unwrap()
            .is_err()
    }

    /// Sends `bytes` on a bare TCP stream and reports whether the server closed
    /// the connection without answering.
    async fn closed_without_reply(addr: SocketAddr, bytes: &[u8]) -> bool {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let _write = stream.write_all(bytes).await;
        let mut received = Vec::new();
        let read = tokio::time::timeout(BOUND, stream.read_to_end(&mut received))
            .await
            .unwrap();
        read.is_err() || received.is_empty()
    }

    #[tokio::test]
    async fn forwarded_headers_from_an_untrusted_peer_are_replaced() {
        let cert = generate();
        let edge = Edge {
            trusted: trusting(&["192.0.2.0/24"], 1),
            proxy_protocol: ProxyProtocol::off(),
        };
        assert_eq!(
            serves(&cert, edge.clone(), b"", GET_FORWARDED).await,
            "127.0.0.1|-"
        );
        assert_eq!(
            serves(&cert, edge, b"", &get_peer_with_forwarded()).await,
            "127.0.0.1"
        );
    }

    #[tokio::test]
    async fn forwarded_headers_from_a_trusted_peer_are_believed() {
        let cert = generate();
        assert_eq!(
            serves(&cert, trusting_loopback(), b"", GET_FORWARDED).await,
            "203.0.113.9, 127.0.0.1|Hash=abc"
        );
        assert_eq!(
            serves(&cert, trusting_loopback(), b"", &get_peer_with_forwarded()).await,
            "203.0.113.9"
        );
    }

    #[tokio::test]
    async fn trusted_peer_with_an_unreadable_forwarded_for_is_unknown() {
        let cert = generate();
        let request = get_peer_with_forwarded().replace("203.0.113.9", "unknown");
        assert_eq!(
            serves(&cert, trusting_loopback(), b"", &request).await,
            "unknown"
        );
    }

    /// The header's source address, not the proxy's, is the client. The
    /// handshake begins right behind the header, so any bytes read past it must be
    /// replayed to rustls.
    #[tokio::test]
    async fn proxy_header_source_becomes_the_client() {
        let cert = generate();
        let response = serves(
            &cert,
            proxied(LOOPBACK),
            &proxy_v2("203.0.113.9:40000"),
            GET_PEER,
        )
        .await;
        assert_eq!(response, "203.0.113.9");
    }

    /// The header's source is the connection's peer, so its `X-Forwarded-For` is
    /// believed only when that address is itself a trusted proxy.
    #[tokio::test]
    async fn proxy_header_source_decides_whether_forwarded_for_is_believed() {
        let cert = generate();
        let request = get_peer_with_forwarded().replace("203.0.113.9", "198.51.100.1");
        assert_eq!(
            serves(
                &cert,
                proxied(LOOPBACK),
                &proxy_v2("203.0.113.9:40000"),
                &request
            )
            .await,
            "203.0.113.9"
        );
        assert_eq!(
            serves(
                &cert,
                proxied(LOOPBACK),
                &proxy_v2("127.0.0.2:40000"),
                &request
            )
            .await,
            "198.51.100.1"
        );
    }

    /// proxy-protocol.txt section 2: only trusted proxies may use the protocol,
    /// so a well-formed header from anyone else is a client forging its address
    /// and is closed unanswered.
    #[tokio::test]
    async fn proxy_header_from_an_untrusted_peer_is_refused() {
        let cert = generate();
        let (addr, _shutdown, _handle) =
            start_with(&cert, SHORT, 8, proxied(&["192.0.2.0/24"])).await;
        assert!(handshake_refused(&cert, addr, &proxy_v2("203.0.113.9:40000")).await);
    }

    /// Section 2: the receiver "MUST not try to guess whether the protocol
    /// header is present or not", so a trusted peer without one is refused.
    #[tokio::test]
    async fn missing_proxy_header_is_refused() {
        let cert = generate();
        let (addr, _shutdown, _handle) = start_with(&cert, SHORT, 8, proxied(LOOPBACK)).await;
        assert!(handshake_refused(&cert, addr, b"").await);
    }

    #[tokio::test]
    async fn proxy_v1_header_is_refused() {
        let cert = generate();
        let (addr, _shutdown, _handle) = start_with(&cert, SHORT, 8, proxied(LOOPBACK)).await;
        assert!(
            handshake_refused(
                &cert,
                addr,
                b"PROXY TCP4 203.0.113.9 192.0.2.1 40000 443\r\n"
            )
            .await
        );
    }

    /// A UDP address cannot describe the TCP connection it arrived on.
    #[tokio::test]
    async fn proxy_header_for_a_datagram_is_refused() {
        let cert = generate();
        let (addr, _shutdown, _handle) = start_with(&cert, SHORT, 8, proxied(LOOPBACK)).await;
        let header =
            proxy_header::ProxyHeader::with_address(proxy_header::ProxiedAddress::datagram(
                "203.0.113.9:40000".parse().unwrap(),
                "192.0.2.1:443".parse().unwrap(),
            ));
        let mut buf = Vec::new();
        header.encode_v2(&mut buf).unwrap();
        assert!(handshake_refused(&cert, addr, &buf).await);
    }

    /// Section 2.2, LOCAL: the receiver "must use the real connection
    /// endpoints", so a proxy's own health check is served with the TCP peer as
    /// the client.
    #[tokio::test]
    async fn local_proxy_header_keeps_the_tcp_peer() {
        let cert = generate();
        let mut header = Vec::new();
        proxy_header::ProxyHeader::with_local()
            .encode_v2(&mut header)
            .unwrap();
        assert_eq!(
            serves(&cert, proxied(LOOPBACK), &header, GET_PEER).await,
            "127.0.0.1"
        );
    }

    /// A trusted peer that never finishes its header is closed by the header
    /// timeout; the other limits are far beyond the test's bound, so only it can
    /// close the connection.
    #[tokio::test]
    async fn stalled_proxy_header_is_closed() {
        let cert = generate();
        let limits = ConnLimits {
            proxy_header: Duration::from_millis(300),
            handshake: Duration::from_secs(3600),
            header_read: Duration::from_secs(3600),
            ..SHORT
        };
        let (addr, _shutdown, _handle) = start_with(&cert, limits, 8, proxied(LOOPBACK)).await;
        let header = proxy_v2("203.0.113.9:40000");
        assert!(closed_without_reply(addr, header.first_chunk::<10>().unwrap().as_slice()).await);
    }
}
