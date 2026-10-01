//! Who is calling: the client address and forwarded client certificate of a
//! request, established from the connection peer and, only when that peer is a
//! trusted proxy, from `X-Forwarded-For` and `X-Forwarded-Client-Cert`.
//!
//! Headers from a client are attacker-controlled. A peer outside
//! `--trusted-proxies` is the client, its `X-Forwarded-For` is replaced by its own
//! address, and its `X-Forwarded-Client-Cert` is removed so a forged certificate
//! never reaches an integration.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU8;
use std::str::FromStr;
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use ipnet::IpNet;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_CLIENT_CERT: HeaderName = HeaderName::from_static("x-forwarded-client-cert");

/// A trusted proxy as written on the command line: a CIDR block, or a single
/// address (a /32 or /128).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrustedProxy(IpNet);

#[derive(Debug, thiserror::Error)]
#[error("expected an IP address or CIDR block such as 10.0.0.0/8, got {0:?}")]
pub(crate) struct TrustedProxyError(String);

impl FromStr for TrustedProxy {
    type Err = TrustedProxyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        s.parse::<IpNet>()
            .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
            .map(|net| Self(net.trunc()))
            .map_err(|_| TrustedProxyError(s.to_owned()))
    }
}

/// The client address of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceIp {
    /// The address, with IPv4-mapped IPv6 addresses reduced to IPv4.
    Known(IpAddr),
    /// A trusted proxy forwarded the request but the client address could not
    /// be read from its `X-Forwarded-For`. Anything that depends on the client
    /// address, such as a resource policy's `aws:SourceIp`, must refuse.
    Unknown,
}

impl SourceIp {
    /// The address, or `None` when it could not be established.
    pub(crate) fn ip(self) -> Option<IpAddr> {
        match self {
            Self::Known(ip) => Some(ip),
            Self::Unknown => None,
        }
    }
}

/// One address of an `X-Forwarded-For` list. Proxies write a bare address, and
/// some add a port or brackets, so all of `203.0.113.7`, `203.0.113.7:4000`,
/// `2001:db8::1`, `[2001:db8::1]` and `[2001:db8::1]:4000` are read. Tokens such
/// as `unknown` are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ForwardedAddr(IpAddr);

#[derive(Debug, thiserror::Error)]
#[error("not an IP address: {0:?}")]
struct ForwardedAddrError(String);

impl FromStr for ForwardedAddr {
    type Err = ForwardedAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let token = s.trim();
        let parsed = token
            .parse::<IpAddr>()
            .ok()
            .or_else(|| token.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
            .or_else(|| {
                token
                    .strip_circumfix('[', ']')
                    .and_then(|inner| inner.parse().ok())
            });
        parsed
            .map(|ip: IpAddr| Self(ip.to_canonical()))
            .ok_or_else(|| ForwardedAddrError(token.to_owned()))
    }
}

/// The text of a possibly repeated header, joined the way HTTP says repeated
/// header lines combine.
enum HeaderLine {
    Absent,
    Text(String),
    /// Present, but not visible ASCII.
    Invalid,
}

impl HeaderLine {
    fn read(headers: &HeaderMap, name: &HeaderName) -> Self {
        let mut lines = headers.get_all(name).iter().peekable();
        if lines.peek().is_none() {
            return Self::Absent;
        }
        let mut joined = Vec::new();
        for line in lines {
            match line.to_str() {
                Ok(text) => joined.push(text),
                Err(_) => return Self::Invalid,
            }
        }
        Self::Text(joined.join(", "))
    }
}

/// Which peers are trusted proxies, and how many proxies sit between the
/// client and this gateway.
#[derive(Debug, Clone)]
pub(crate) struct TrustedProxies {
    nets: Arc<[IpNet]>,
    hops: NonZeroU8,
}

impl TrustedProxies {
    /// Trusts peers inside `proxies`. `hops` counts the proxies in front of the
    /// gateway including the one that connects to it: with one, the client is the
    /// last `X-Forwarded-For` entry; with two, the one before it.
    pub(crate) fn new(proxies: &[TrustedProxy], hops: NonZeroU8) -> Self {
        Self {
            nets: proxies.iter().map(|proxy| proxy.0).collect(),
            hops,
        }
    }

    /// Trusts no peer: every connection's peer is its client.
    pub(crate) fn none() -> Self {
        Self::new(&[], NonZeroU8::MIN)
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.nets.iter().any(|net| net.contains(&ip))
    }

    /// Establishes who sent a request that arrived from `peer` with `headers`,
    /// and rewrites the headers so that what an integration sees agrees with
    /// that: `X-Forwarded-For` ends with `peer`'s address, and
    /// `X-Forwarded-Client-Cert` is removed unless `peer` is trusted.
    pub(crate) fn identify(&self, peer: SocketAddr, headers: &mut HeaderMap) -> ClientIdentity {
        let peer_ip = peer.ip().to_canonical();
        let forwarded_for = HeaderLine::read(headers, &X_FORWARDED_FOR);
        let trusted = self.contains(peer_ip);

        let (source_ip, certificate, chain) = if trusted {
            let source_ip = match forwarded_for {
                HeaderLine::Absent => SourceIp::Known(peer_ip),
                HeaderLine::Invalid => SourceIp::Unknown,
                HeaderLine::Text(ref text) => self.client_in(text),
            };
            let chain = match forwarded_for {
                HeaderLine::Text(text) => format!("{text}, {peer_ip}"),
                HeaderLine::Absent | HeaderLine::Invalid => peer_ip.to_string(),
            };
            let certificate = ClientCertificate::read(headers);
            (source_ip, certificate, chain)
        } else {
            headers.remove(X_FORWARDED_CLIENT_CERT);
            (
                SourceIp::Known(peer_ip),
                ClientCertificate::Absent,
                peer_ip.to_string(),
            )
        };
        match HeaderValue::from_str(&chain) {
            Ok(value) => {
                headers.insert(X_FORWARDED_FOR, value);
            }
            Err(_) => {
                headers.remove(X_FORWARDED_FOR);
            }
        }
        ClientIdentity {
            source_ip,
            certificate,
        }
    }

    /// Walks `forwarded_for` from the right, past one entry per trusted hop.
    /// Entries to the left of the client are never read, so a client cannot
    /// break the lookup by writing junk in front of what the proxies appended.
    fn client_in(&self, forwarded_for: &str) -> SourceIp {
        let mut remaining = self.hops.get();
        for entry in forwarded_for.rsplit(',') {
            let Ok(ForwardedAddr(addr)) = entry.parse() else {
                return SourceIp::Unknown;
            };
            remaining = remaining.saturating_sub(1);
            if remaining == 0 || !self.contains(addr) {
                return SourceIp::Known(addr);
            }
        }
        SourceIp::Unknown
    }
}

/// Who a request came from, attached to the request's extensions by the
/// listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientIdentity {
    source_ip: SourceIp,
    certificate: ClientCertificate,
}

impl ClientIdentity {
    /// An identity whose client address could not be established.
    pub(crate) fn unknown() -> Self {
        Self {
            source_ip: SourceIp::Unknown,
            certificate: ClientCertificate::Absent,
        }
    }

    pub(crate) fn source_ip(&self) -> SourceIp {
        self.source_ip
    }

    /// The client certificate a trusted proxy reported.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the mTLS client-certificate work")
    )]
    pub(crate) fn certificate(&self) -> &ClientCertificate {
        &self.certificate
    }
}

/// The client certificate information in `X-Forwarded-Client-Cert`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientCertificate {
    /// No header, or the peer was not trusted to send one.
    Absent,
    Forwarded(ForwardedClientCert),
    /// A trusted peer sent a header that could not be parsed. Anything that
    /// authenticates with the certificate must refuse.
    Malformed,
}

impl ClientCertificate {
    fn read(headers: &HeaderMap) -> Self {
        match HeaderLine::read(headers, &X_FORWARDED_CLIENT_CERT) {
            HeaderLine::Absent => Self::Absent,
            HeaderLine::Invalid => Self::Malformed,
            HeaderLine::Text(text) => text.parse().map_or(Self::Malformed, Self::Forwarded),
        }
    }
}

/// A parsed `X-Forwarded-Client-Cert` header: one element per proxy that
/// appended to it, the last being the connection that reached the proxy
/// closest to this gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForwardedClientCert {
    elements: Vec<CertElement>,
}

impl ForwardedClientCert {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the mTLS client-certificate work")
    )]
    pub(crate) fn elements(&self) -> &[CertElement] {
        &self.elements
    }
}

/// One element of `X-Forwarded-Client-Cert`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CertElement {
    /// The proxy's own certificate URI (`By`).
    pub(crate) by: Option<String>,
    /// SHA-256 of the client certificate, hex encoded.
    pub(crate) hash: Option<String>,
    /// The client certificate in PEM form, decoded from its URL encoding.
    pub(crate) cert: Option<String>,
    pub(crate) subject: Option<String>,
    pub(crate) uris: Vec<String>,
    pub(crate) dns_names: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum CertParseError {
    #[error("header is empty")]
    Empty,
    #[error("expected KEY=VALUE, found {0:?}")]
    MissingValue(String),
    #[error("quoted value is not terminated")]
    UnterminatedQuote,
    #[error("unexpected {0:?} after a quoted value")]
    TrailingAfterQuote(char),
    #[error("{0} appears twice in one element")]
    Duplicate(&'static str),
    #[error("Cert is not valid percent-encoded UTF-8")]
    InvalidCert,
}

impl CertElement {
    fn set(&mut self, key: &str, value: String) -> Result<(), CertParseError> {
        fn once(
            slot: &mut Option<String>,
            name: &'static str,
            value: String,
        ) -> Result<(), CertParseError> {
            if slot.replace(value).is_some() {
                return Err(CertParseError::Duplicate(name));
            }
            Ok(())
        }
        match key.to_ascii_lowercase().as_str() {
            "by" => once(&mut self.by, "By", value),
            "hash" => once(&mut self.hash, "Hash", value),
            "subject" => once(&mut self.subject, "Subject", value),
            "cert" => once(
                &mut self.cert,
                "Cert",
                percent_decode(&value).ok_or(CertParseError::InvalidCert)?,
            ),
            "uri" => {
                self.uris.push(value);
                Ok(())
            }
            "dns" => {
                self.dns_names.push(value);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Strict percent-decoding: a malformed escape or non-UTF-8 result is `None`.
fn percent_decode(input: &str) -> Option<String> {
    let mut out = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = hex_digit(bytes.next()?)?;
            let low = hex_digit(bytes.next()?)?;
            out.push(high << 4 | low);
        } else {
            out.push(byte);
        }
    }
    String::from_utf8(out).ok()
}

fn hex_digit(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
}

/// Reads `KEY=VALUE` pairs and element boundaries from a header value.
struct Scanner<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
}

impl Scanner<'_> {
    fn skip_spaces(&mut self) {
        while self.chars.next_if(char::is_ascii_whitespace).is_some() {}
    }

    fn key(&mut self) -> Result<String, CertParseError> {
        let mut key = String::new();
        loop {
            match self.chars.next() {
                Some('=') => return Ok(key.trim().to_owned()),
                Some(';' | ',') | None => return Err(CertParseError::MissingValue(key)),
                Some(c) => key.push(c),
            }
        }
    }

    /// A value is either `"..."` with `\"` and `\\` escapes, or the text up to
    /// the next `;` or `,`.
    fn value(&mut self) -> Result<String, CertParseError> {
        self.skip_spaces();
        let mut value = String::new();
        if self.chars.next_if_eq(&'"').is_some() {
            loop {
                match self.chars.next() {
                    None => return Err(CertParseError::UnterminatedQuote),
                    Some('"') => break,
                    Some('\\') => match self.chars.next() {
                        Some(escaped) => value.push(escaped),
                        None => return Err(CertParseError::UnterminatedQuote),
                    },
                    Some(c) => value.push(c),
                }
            }
            self.skip_spaces();
            return match self.chars.peek() {
                Some(&c) if c != ';' && c != ',' => Err(CertParseError::TrailingAfterQuote(c)),
                _ => Ok(value),
            };
        }
        while let Some(c) = self.chars.next_if(|c| *c != ';' && *c != ',') {
            value.push(c);
        }
        Ok(value.trim_end().to_owned())
    }
}

impl FromStr for ForwardedClientCert {
    type Err = CertParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim().is_empty() {
            return Err(CertParseError::Empty);
        }
        let mut scanner = Scanner {
            chars: s.chars().peekable(),
        };
        let mut elements = Vec::new();
        let mut current = CertElement::default();
        loop {
            let key = scanner.key()?;
            let value = scanner.value()?;
            current.set(&key, value)?;
            match scanner.chars.next() {
                Some(';') => {}
                Some(',') => elements.push(std::mem::take(&mut current)),
                _ => {
                    elements.push(current);
                    return Ok(Self { elements });
                }
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use proptest::prelude::*;

    use super::*;

    fn proxies(nets: &[&str], hops: u8) -> TrustedProxies {
        let nets: Vec<TrustedProxy> = nets.iter().map(|net| net.parse().unwrap()).collect();
        TrustedProxies::new(&nets, NonZeroU8::new(hops).unwrap())
    }

    fn peer(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 40_000)
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_static(name),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn header<'a>(map: &'a HeaderMap, name: &str) -> &'a str {
        map.get(name).unwrap().to_str().unwrap()
    }

    fn elements_of(certificate: &ClientCertificate) -> &[CertElement] {
        match certificate {
            ClientCertificate::Forwarded(cert) => cert.elements(),
            ClientCertificate::Absent | ClientCertificate::Malformed => &[],
        }
    }

    fn client(trust: &TrustedProxies, from: &str, forwarded_for: Option<&str>) -> SourceIp {
        let mut map = forwarded_for
            .map(|value| headers(&[("x-forwarded-for", value)]))
            .unwrap_or_default();
        trust.identify(peer(from), &mut map).source_ip()
    }

    fn known(ip: &str) -> SourceIp {
        SourceIp::Known(ip.parse().unwrap())
    }

    #[test]
    fn trusted_proxy_parses_cidrs_and_bare_addresses() {
        assert_eq!(
            "10.0.0.0/8".parse::<TrustedProxy>().unwrap().0,
            "10.0.0.0/8".parse::<IpNet>().unwrap()
        );
        assert_eq!(
            " 192.0.2.7 ".parse::<TrustedProxy>().unwrap().0,
            "192.0.2.7/32".parse::<IpNet>().unwrap()
        );
        assert_eq!(
            "2001:db8::1".parse::<TrustedProxy>().unwrap().0,
            "2001:db8::1/128".parse::<IpNet>().unwrap()
        );
        assert_eq!(
            "10.1.2.3/8".parse::<TrustedProxy>().unwrap().0,
            "10.0.0.0/8".parse::<IpNet>().unwrap()
        );
        for bad in ["", "10.0.0.0/33", "not-an-ip", "10.0.0.0/8/9"] {
            assert!(bad.parse::<TrustedProxy>().is_err(), "{bad}");
        }
    }

    #[test]
    fn untrusted_peer_is_the_client_and_forwarded_for_is_ignored() {
        let trust = proxies(&["10.0.0.0/8"], 1);
        assert_eq!(
            client(&trust, "198.51.100.5", Some("203.0.113.9")),
            known("198.51.100.5")
        );
        assert_eq!(
            client(&trust, "198.51.100.5", Some("not an address")),
            known("198.51.100.5")
        );
    }

    #[test]
    fn untrusted_peer_cannot_inject_a_forwarded_for_chain() {
        let trust = proxies(&["10.0.0.0/8"], 1);
        let mut map = headers(&[("x-forwarded-for", "10.1.1.1, 203.0.113.9")]);
        trust.identify(peer("198.51.100.5"), &mut map);
        assert_eq!(header(&map, "x-forwarded-for"), "198.51.100.5");
        assert_eq!(map.get_all("x-forwarded-for").iter().count(), 1);
    }

    #[test]
    fn no_trusted_proxies_trusts_nobody() {
        let trust = TrustedProxies::none();
        assert_eq!(
            client(&trust, "10.0.0.1", Some("203.0.113.9")),
            known("10.0.0.1")
        );
    }

    #[test]
    fn trusted_peer_without_forwarded_for_is_the_client() {
        let trust = proxies(&["10.0.0.0/8"], 1);
        assert_eq!(client(&trust, "10.0.0.1", None), known("10.0.0.1"));
    }

    #[test]
    fn one_hop_takes_the_last_entry() {
        let trust = proxies(&["10.0.0.0/8"], 1);
        assert_eq!(
            client(&trust, "10.0.0.1", Some("203.0.113.9")),
            known("203.0.113.9")
        );
        assert_eq!(
            client(&trust, "10.0.0.1", Some("198.51.100.1, 203.0.113.9")),
            known("203.0.113.9"),
            "an entry the client wrote in front of the proxy's is not the client"
        );
    }

    #[test]
    fn hops_count_trusted_proxies_from_the_right() {
        let trust = proxies(&["10.0.0.0/8"], 2);
        assert_eq!(
            client(&trust, "10.0.0.1", Some("203.0.113.9, 10.0.0.2")),
            known("203.0.113.9")
        );
        assert_eq!(
            client(
                &trust,
                "10.0.0.1",
                Some("192.0.2.200, 203.0.113.9, 10.0.0.2")
            ),
            known("203.0.113.9"),
            "the client's own prefix is never read"
        );
        let trust = proxies(&["10.0.0.0/8"], 3);
        assert_eq!(
            client(&trust, "10.0.0.1", Some("203.0.113.9, 10.0.0.3, 10.0.0.2")),
            known("203.0.113.9")
        );
    }

    #[test]
    fn walking_stops_at_the_first_untrusted_address() {
        let trust = proxies(&["10.0.0.0/8"], 3);
        assert_eq!(
            client(
                &trust,
                "10.0.0.1",
                Some("192.0.2.200, 203.0.113.9, 10.0.0.2")
            ),
            known("203.0.113.9"),
            "an untrusted hop is the client even when more hops were configured"
        );
    }

    #[test]
    fn too_few_entries_for_the_hops_is_unknown() {
        let trust = proxies(&["10.0.0.0/8"], 2);
        assert_eq!(
            client(&trust, "10.0.0.1", Some("10.0.0.2")),
            SourceIp::Unknown
        );
    }

    #[test]
    fn malformed_entries_make_the_source_unknown() {
        let trust = proxies(&["10.0.0.0/8"], 1);
        for bad in [
            "",
            " ",
            "unknown",
            "_hidden",
            "203.0.113.999",
            "1.2.3.4, ",
            ",",
            "1.2.3.4,,",
        ] {
            assert_eq!(
                client(&trust, "10.0.0.1", Some(bad)),
                SourceIp::Unknown,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn non_ascii_forwarded_for_from_a_trusted_peer_is_unknown() {
        let trust = proxies(&["10.0.0.0/8"], 1);
        let mut map = HeaderMap::new();
        map.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_bytes(b"203.0.113.9\xff").unwrap(),
        );
        let identity = trust.identify(peer("10.0.0.1"), &mut map);
        assert_eq!(identity.source_ip(), SourceIp::Unknown);
        assert_eq!(header(&map, "x-forwarded-for"), "10.0.0.1");
    }

    #[test]
    fn malformed_entry_left_of_the_client_is_not_read() {
        let trust = proxies(&["10.0.0.0/8"], 1);
        assert_eq!(
            client(&trust, "10.0.0.1", Some("garbage, 203.0.113.9")),
            known("203.0.113.9")
        );
    }

    #[test]
    fn repeated_forwarded_for_lines_combine_in_order() {
        let trust = proxies(&["10.0.0.0/8"], 2);
        let mut map = headers(&[
            ("x-forwarded-for", "203.0.113.9"),
            ("x-forwarded-for", "10.0.0.2"),
        ]);
        let identity = trust.identify(peer("10.0.0.1"), &mut map);
        assert_eq!(identity.source_ip(), known("203.0.113.9"));
        assert_eq!(
            header(&map, "x-forwarded-for"),
            "203.0.113.9, 10.0.0.2, 10.0.0.1"
        );
    }

    #[test]
    fn trusted_peer_is_appended_to_the_forwarded_chain() {
        let trust = proxies(&["10.0.0.0/8"], 1);
        let mut map = headers(&[("x-forwarded-for", "203.0.113.9")]);
        trust.identify(peer("10.0.0.1"), &mut map);
        assert_eq!(header(&map, "x-forwarded-for"), "203.0.113.9, 10.0.0.1");
    }

    #[test]
    fn ipv6_clients_and_proxies() {
        let trust = proxies(&["fd00::/8"], 1);
        assert_eq!(
            client(&trust, "fd00::1", Some("2001:db8::7")),
            known("2001:db8::7")
        );
        assert_eq!(
            client(&trust, "fd00::1", Some("[2001:db8::7]")),
            known("2001:db8::7")
        );
        assert_eq!(
            client(&trust, "fd00::1", Some("[2001:db8::7]:5000")),
            known("2001:db8::7")
        );
        assert_eq!(
            client(&trust, "2001:db8::bad", Some("2001:db8::7")),
            known("2001:db8::bad")
        );
    }

    #[test]
    fn forwarded_for_ports_are_dropped() {
        let trust = proxies(&["10.0.0.0/8"], 1);
        assert_eq!(
            client(&trust, "10.0.0.1", Some("203.0.113.9:51234")),
            known("203.0.113.9")
        );
    }

    #[test]
    fn ipv4_mapped_addresses_are_reduced_to_ipv4() {
        let trust = proxies(&["10.0.0.0/8"], 1);
        assert_eq!(
            client(&trust, "::ffff:10.0.0.1", Some("::ffff:203.0.113.9")),
            known("203.0.113.9"),
            "a mapped peer matches an IPv4 CIDR and a mapped client is reported as IPv4"
        );
        assert_eq!(
            client(&trust, "::ffff:198.51.100.5", Some("203.0.113.9")),
            known("198.51.100.5")
        );
        assert_eq!(
            SourceIp::Known(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))).ip(),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)))
        );
        assert_eq!(SourceIp::Unknown.ip(), None);
        assert_eq!(
            "::ffff:1.2.3.4".parse::<ForwardedAddr>().unwrap().0,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(
            "::1".parse::<ForwardedAddr>().unwrap().0,
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
    }

    const CERT_HEADER: &str = r#"By=spiffe://cluster.local/ns/a/sa/gw;Hash=abc123;Subject="CN=client,O=Acme";URI=spiffe://cluster.local/ns/b/sa/web;DNS=web.b.svc"#;

    #[test]
    fn forwarded_client_cert_is_parsed_from_a_trusted_peer() {
        let trust = proxies(&["10.0.0.0/8"], 1);
        let mut map = headers(&[("x-forwarded-client-cert", CERT_HEADER)]);
        let identity = trust.identify(peer("10.0.0.1"), &mut map);
        let elements = elements_of(identity.certificate());
        assert_eq!(elements.len(), 1, "{identity:?}");
        let element = elements.first().unwrap();
        assert_eq!(
            element.by.as_deref(),
            Some("spiffe://cluster.local/ns/a/sa/gw")
        );
        assert_eq!(element.hash.as_deref(), Some("abc123"));
        assert_eq!(element.subject.as_deref(), Some("CN=client,O=Acme"));
        assert_eq!(element.uris, ["spiffe://cluster.local/ns/b/sa/web"]);
        assert_eq!(element.dns_names, ["web.b.svc"]);
        assert_eq!(header(&map, "x-forwarded-client-cert"), CERT_HEADER);
    }

    #[test]
    fn forwarded_client_cert_from_an_untrusted_peer_is_stripped() {
        let trust = proxies(&["10.0.0.0/8"], 1);
        let mut map = headers(&[("x-forwarded-client-cert", CERT_HEADER)]);
        let identity = trust.identify(peer("198.51.100.5"), &mut map);
        assert_eq!(identity.certificate(), &ClientCertificate::Absent);
        assert!(map.get("x-forwarded-client-cert").is_none());

        let mut map = headers(&[("x-forwarded-client-cert", CERT_HEADER)]);
        let identity = TrustedProxies::none().identify(peer("10.0.0.1"), &mut map);
        assert_eq!(identity.certificate(), &ClientCertificate::Absent);
        assert!(map.get("x-forwarded-client-cert").is_none());
    }

    #[test]
    fn missing_and_malformed_certificate_headers() {
        let trust = proxies(&["10.0.0.0/8"], 1);
        let mut map = HeaderMap::new();
        assert_eq!(
            trust.identify(peer("10.0.0.1"), &mut map).certificate(),
            &ClientCertificate::Absent
        );
        let mut map = headers(&[("x-forwarded-client-cert", "Hash=\"unterminated")]);
        assert_eq!(
            trust.identify(peer("10.0.0.1"), &mut map).certificate(),
            &ClientCertificate::Malformed
        );
    }

    #[test]
    fn certificate_elements_split_on_commas_outside_quotes() {
        let cert: ForwardedClientCert = concat!(
            r#"By=spiffe://a;Hash=h1;Subject="CN=one, O=Acme; OU=x";URI=spiffe://one,"#,
            r"By=spiffe://b;Hash=h2;URI=spiffe://two;URI=spiffe://two-b;DNS=a.example;DNS=b.example"
        )
        .parse()
        .unwrap();
        assert_eq!(cert.elements().len(), 2, "{cert:?}");
        let first = cert.elements().first().unwrap();
        let second = cert.elements().get(1).unwrap();
        assert_eq!(first.subject.as_deref(), Some("CN=one, O=Acme; OU=x"));
        assert_eq!(first.uris, ["spiffe://one"]);
        assert_eq!(second.hash.as_deref(), Some("h2"));
        assert_eq!(second.uris, ["spiffe://two", "spiffe://two-b"]);
        assert_eq!(second.dns_names, ["a.example", "b.example"]);
    }

    #[test]
    fn certificate_quoted_values_unescape() {
        let cert: ForwardedClientCert = r#"Subject="CN=\"quoted\",O=back\\slash""#.parse().unwrap();
        assert_eq!(
            cert.elements().first().unwrap().subject.as_deref(),
            Some(r#"CN="quoted",O=back\slash"#)
        );
    }

    #[test]
    fn certificate_cert_field_is_url_decoded() {
        let cert: ForwardedClientCert =
            "Cert=\"-----BEGIN%20CERTIFICATE-----%0AMIIB%2Bw%3D%3D%0A-----END%20CERTIFICATE-----%0A\";Hash=h"
                .parse()
                .unwrap();
        assert_eq!(
            cert.elements().first().unwrap().cert.as_deref(),
            Some("-----BEGIN CERTIFICATE-----\nMIIB+w==\n-----END CERTIFICATE-----\n")
        );
    }

    #[test]
    fn certificate_keys_are_case_insensitive_and_unknown_keys_are_ignored() {
        let cert: ForwardedClientCert = "hash=h;uri=u;Chain=ignored;Extra=1".parse().unwrap();
        let element = &cert.elements().first().unwrap();
        assert_eq!(element.hash.as_deref(), Some("h"));
        assert_eq!(element.uris, ["u"]);
    }

    #[test]
    fn malformed_certificate_headers_are_rejected() {
        let cases = [
            ("", CertParseError::Empty),
            ("  ", CertParseError::Empty),
            ("Hash", CertParseError::MissingValue("Hash".to_owned())),
            (
                "Hash;URI=a",
                CertParseError::MissingValue("Hash".to_owned()),
            ),
            ("Hash=\"abc", CertParseError::UnterminatedQuote),
            ("Hash=\"abc\\", CertParseError::UnterminatedQuote),
            ("Hash=\"abc\"x", CertParseError::TrailingAfterQuote('x')),
            ("Hash=a;Hash=b", CertParseError::Duplicate("Hash")),
            ("Subject=a;subject=b", CertParseError::Duplicate("Subject")),
            ("Hash=a;", CertParseError::MissingValue(String::new())),
            ("Cert=%zz", CertParseError::InvalidCert),
            ("Cert=%ff", CertParseError::InvalidCert),
            ("Cert=%4", CertParseError::InvalidCert),
        ];
        for (input, expected) in cases {
            assert_eq!(
                input.parse::<ForwardedClientCert>(),
                Err(expected),
                "{input:?}"
            );
        }
    }

    proptest! {
        #[test]
        fn forwarded_for_parsing_never_panics(text in "[ -~]{0,80}", hops in 1u8..=4) {
            let trust = proxies(&["10.0.0.0/8"], hops);
            client(&trust, "10.0.0.1", Some(&text));
        }

        #[test]
        fn certificate_parsing_never_panics(text in "\\PC{0,120}") {
            drop(text.parse::<ForwardedClientCert>());
        }

        #[test]
        fn untrusted_peer_always_wins(
            peer_ip in any::<Ipv4Addr>().prop_filter("not in 10/8", |ip| ip.octets().first() != Some(&10)),
            forwarded in "[ -~]{0,60}",
        ) {
            let trust = proxies(&["10.0.0.0/8"], 1);
            let from = peer_ip.to_string();
            prop_assert_eq!(client(&trust, &from, Some(&forwarded)), SourceIp::Known(IpAddr::V4(peer_ip)));
        }

        #[test]
        fn trusted_peer_gets_the_hops_th_entry_from_the_right(
            junk in proptest::collection::vec("[ -~]{0,12}", 0..4),
            proxy_octets in proptest::collection::vec(any::<u16>(), 0..3),
            client_ip in any::<IpAddr>(),
        ) {
            let hops = u8::try_from(proxy_octets.len()).unwrap().saturating_add(1);
            let trust = proxies(&["10.0.0.0/8"], hops);
            let mut entries: Vec<String> = junk
                .into_iter()
                .map(|entry| entry.replace(',', ""))
                .collect();
            entries.push(client_ip.to_string());
            entries.extend(proxy_octets.iter().map(|n| format!("10.0.{}.{}", n >> 8, n & 0xff)));
            let forwarded = entries.join(", ");
            prop_assert_eq!(
                client(&trust, "10.0.0.1", Some(&forwarded)),
                SourceIp::Known(client_ip.to_canonical())
            );
        }

        #[test]
        fn forwarded_addresses_round_trip(ip in any::<IpAddr>(), port in any::<u16>()) {
            let canonical = ForwardedAddr(ip.to_canonical());
            prop_assert_eq!(ip.to_string().parse::<ForwardedAddr>().unwrap(), canonical);
            prop_assert_eq!(SocketAddr::new(ip, port).to_string().parse::<ForwardedAddr>().unwrap(), canonical);
        }
    }
}
