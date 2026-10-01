//! How REST APIs treat binary payloads and compressed payloads.
//!
//! Binary media types: a request body is binary when its `Content-Type` matches
//! one of the API's `binaryMediaTypes`, and a response is binary when the
//! client's first `Accept` media type matches one. A Lambda proxy event carries
//! a binary body base64-encoded, and a function's base64 response is decoded
//! only when the client accepts binary.
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-payload-encodings.html>
//!
//! Compression: with `minimumCompressionSize` set, responses at least that large
//! are compressed in the client's highest-priority coding when API Gateway
//! supports it (`gzip`, `deflate`, `identity`); request bodies in `gzip` or
//! `deflate` are always decompressed.
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-enable-compression.html>

use std::io::{self, Read as _, Write as _};
use std::str::FromStr;

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use flate2::Compression;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};

use crate::gateway::{GatewayError, MAX_BODY_BYTES};

/// A media type without its parameters, lower-cased: `image/png`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MediaType {
    main: String,
    sub: String,
}

impl FromStr for MediaType {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let essence = value.split(';').next().unwrap_or_default().trim();
        let (main, sub) = essence.split_once('/').ok_or(())?;
        if main.is_empty() || sub.is_empty() {
            return Err(());
        }
        Ok(Self {
            main: main.to_ascii_lowercase(),
            sub: sub.to_ascii_lowercase(),
        })
    }
}

/// One `binaryMediaTypes` entry: `image/png`, `image/*`, or `*/*`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MediaPattern {
    main: Option<String>,
    sub: Option<String>,
}

impl FromStr for MediaPattern {
    type Err = ();

    /// Exports may write the `/` as `~1`, as JSON Pointer does.
    fn from_str(entry: &str) -> Result<Self, Self::Err> {
        let entry = entry.trim().replace("~1", "/");
        if entry == "*" || entry == "*/*" {
            return Ok(Self {
                main: None,
                sub: None,
            });
        }
        let (main, sub) = entry.split_once('/').ok_or(())?;
        if main.is_empty() || sub.is_empty() || main == "*" {
            return Err(());
        }
        Ok(Self {
            main: Some(main.to_ascii_lowercase()),
            sub: (sub != "*").then(|| sub.to_ascii_lowercase()),
        })
    }
}

impl MediaPattern {
    fn matches(&self, media: &MediaType) -> bool {
        self.main.as_ref().is_none_or(|main| *main == media.main)
            && self.sub.as_ref().is_none_or(|sub| *sub == media.sub)
    }
}

/// An API's `binaryMediaTypes`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BinaryMediaTypes(Vec<MediaPattern>);

impl BinaryMediaTypes {
    pub(crate) fn new(entries: &[String]) -> Self {
        let mut patterns = Vec::with_capacity(entries.len());
        for entry in entries {
            if let Ok(pattern) = entry.parse() {
                patterns.push(pattern);
            } else {
                tracing::warn!(entry, "ignoring an invalid binary media type");
            }
        }
        Self(patterns)
    }

    fn matches(&self, media: &MediaType) -> bool {
        self.0.iter().any(|pattern| pattern.matches(media))
    }
}

/// How a response should be encoded for one client: API Gateway "uses the first
/// `Accept` header from clients to determine if a response should return binary
/// media".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResponseNegotiation<'a> {
    binary: &'a BinaryMediaTypes,
    accept: Option<MediaType>,
}

impl ResponseNegotiation<'_> {
    /// Whether the client gets binary. Without an `Accept` header the
    /// response's own `Content-Type` decides.
    pub(crate) fn wants_binary(&self, response_content_type: Option<&str>) -> bool {
        let media = self
            .accept
            .clone()
            .or_else(|| response_content_type.and_then(|content_type| content_type.parse().ok()));
        media.is_some_and(|media| self.binary.matches(&media))
    }
}

/// The content codings API Gateway supports besides `identity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentCoding {
    Gzip,
    Deflate,
}

/// Why a request body could not be decompressed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DecompressError {
    #[error("the body is not valid {0} data")]
    Invalid(&'static str),
    #[error("the decompressed body is larger than {MAX_BODY_BYTES} bytes")]
    TooLarge,
}

impl From<DecompressError> for GatewayError {
    fn from(error: DecompressError) -> Self {
        match error {
            DecompressError::Invalid(_) => Self::InvalidRequest,
            DecompressError::TooLarge => Self::RequestTooLarge,
        }
    }
}

impl ContentCoding {
    fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
        }
    }

    fn header_value(self) -> HeaderValue {
        HeaderValue::from_static(self.name())
    }

    fn compress(self, body: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Gzip => {
                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(body)?;
                encoder.finish()
            }
            Self::Deflate => {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(body)?;
                encoder.finish()
            }
        }
    }

    /// Reads a decoder to its end, stopping one byte past the payload limit so
    /// an oversized result is detected without being fully produced.
    fn read_limited(decoder: impl io::Read) -> io::Result<Vec<u8>> {
        let limit = u64::try_from(MAX_BODY_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut out = Vec::new();
        decoder.take(limit).read_to_end(&mut out)?;
        Ok(out)
    }

    /// Decompresses `body`, producing at most [`MAX_BODY_BYTES`]. `deflate` is
    /// zlib-wrapped per RFC 9110, but raw deflate streams are accepted too.
    fn decompress(self, body: &[u8]) -> Result<Vec<u8>, DecompressError> {
        let decoded = match self {
            Self::Gzip => Self::read_limited(GzDecoder::new(body)),
            Self::Deflate => Self::read_limited(ZlibDecoder::new(body))
                .or_else(|_| Self::read_limited(DeflateDecoder::new(body))),
        };
        let decoded = decoded.map_err(|_| DecompressError::Invalid(self.name()))?;
        if decoded.len() > MAX_BODY_BYTES {
            return Err(DecompressError::TooLarge);
        }
        Ok(decoded)
    }
}

impl FromStr for ContentCoding {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Ok(Self::Gzip),
            "deflate" => Ok(Self::Deflate),
            _ => Err(()),
        }
    }
}

/// One entry of an `Accept-Encoding` header: a coding and its weight in
/// thousandths (`q=0.5` is 500).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Preference {
    coding: String,
    weight: u16,
}

/// A parsed `Accept-Encoding` header (RFC 9110 section 12.5.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AcceptEncoding(Vec<Preference>);

impl AcceptEncoding {
    pub(crate) fn from_headers(headers: &HeaderMap) -> Self {
        headers
            .get_all(header::ACCEPT_ENCODING)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join(",")
            .parse()
            .unwrap_or_default()
    }

    /// The coding to compress with: the highest-weighted entry, the first of
    /// equals. API Gateway applies no compression when that entry is not one it
    /// supports, or is `identity`; `*` stands for any coding, and gzip is used.
    pub(crate) fn preferred(&self) -> Option<ContentCoding> {
        let mut best: Option<&Preference> = None;
        for preference in self.0.iter().filter(|p| p.weight > 0) {
            if best.is_none_or(|current| preference.weight > current.weight) {
                best = Some(preference);
            }
        }
        match best?.coding.as_str() {
            "*" => Some(ContentCoding::Gzip),
            coding => coding.parse().ok(),
        }
    }
}

impl FromStr for AcceptEncoding {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut preferences = Vec::new();
        for entry in value.split(',') {
            let mut parts = entry.split(';');
            let coding = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            if coding.is_empty() {
                continue;
            }
            let mut weight = 1000;
            for parameter in parts {
                let Some((name, quality)) = parameter.split_once('=') else {
                    continue;
                };
                if name.trim().eq_ignore_ascii_case("q") {
                    weight = Self::weight(quality.trim()).ok_or(())?;
                }
            }
            preferences.push(Preference { coding, weight });
        }
        Ok(Self(preferences))
    }
}

impl AcceptEncoding {
    /// A qpvalue (`0`, `1`, `0.5`, `1.000`) in thousandths.
    fn weight(quality: &str) -> Option<u16> {
        let (whole, fraction) = quality.split_once('.').unwrap_or((quality, ""));
        if fraction.len() > 3 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let thousandths: u16 = format!("{fraction:0<3}").parse().ok()?;
        match whole {
            "0" => Some(thousandths),
            "1" if thousandths == 0 => Some(1000),
            _ => None,
        }
    }
}

/// An API's payload settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PayloadSettings {
    binary: BinaryMediaTypes,
    minimum_compression: Option<usize>,
}

impl PayloadSettings {
    pub(crate) fn new(
        binary_media_types: &[String],
        minimum_compression_size: Option<u64>,
    ) -> Self {
        Self {
            binary: BinaryMediaTypes::new(binary_media_types),
            minimum_compression: minimum_compression_size
                .map(|size| usize::try_from(size).unwrap_or(usize::MAX)),
        }
    }

    /// Whether a request with these headers carries a binary body.
    pub(crate) fn request_is_binary(&self, headers: &HeaderMap) -> bool {
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|content_type| content_type.parse().ok())
            .is_some_and(|media| self.binary.matches(&media))
    }

    /// How to answer the client that sent `request`.
    pub(crate) fn negotiate(&self, request: &HeaderMap) -> ResponseNegotiation<'_> {
        let accept = request
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .and_then(|accept| accept.split(',').next())
            .and_then(|first| first.parse().ok());
        ResponseNegotiation {
            binary: &self.binary,
            accept,
        }
    }

    /// Decompresses a `gzip` or `deflate` request body and removes the headers
    /// that described the compressed form. Other codings pass through.
    ///
    /// # Errors
    ///
    /// Fails when the body is not valid in the coding it claims, or expands past
    /// the payload limit.
    pub(crate) fn decompress_request(
        headers: &mut HeaderMap,
        body: Bytes,
    ) -> Result<Bytes, DecompressError> {
        let Some(coding) = headers
            .get(header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<ContentCoding>().ok())
        else {
            return Ok(body);
        };
        let decoded = coding.decompress(&body)?;
        headers.remove(header::CONTENT_ENCODING);
        headers.remove(header::CONTENT_LENGTH);
        Ok(Bytes::from(decoded))
    }

    /// Compresses a buffered response for a client that accepts a coding, when
    /// compression is on and the body is at least `minimumCompressionSize`.
    /// Responses that already have a `Content-Encoding`, or no body, are left
    /// alone.
    ///
    /// # Errors
    ///
    /// Fails when the body exceeds the payload limit or cannot be compressed.
    pub(crate) async fn compress_response(
        &self,
        request: &HeaderMap,
        response: Response,
    ) -> Result<Response, GatewayError> {
        let Some(minimum) = self.minimum_compression else {
            return Ok(response);
        };
        let Some(coding) = AcceptEncoding::from_headers(request).preferred() else {
            return Ok(response);
        };
        let status = response.status();
        let bodyless = status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED
            || status.is_informational();
        if bodyless || response.headers().contains_key(header::CONTENT_ENCODING) {
            return Ok(response);
        }
        let (mut parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, MAX_BODY_BYTES)
            .await
            .map_err(|_| GatewayError::IntegrationFailure)?;
        if body.is_empty() || body.len() < minimum {
            return Ok(Response::from_parts(parts, Body::from(body)));
        }
        let compressed = tokio::task::spawn_blocking(move || coding.compress(&body))
            .await
            .map_err(|_| GatewayError::IntegrationFailure)?
            .map_err(|_| GatewayError::IntegrationFailure)?;
        parts
            .headers
            .insert(header::CONTENT_ENCODING, coding.header_value());
        parts.headers.remove(header::CONTENT_LENGTH);
        Ok(Response::from_parts(parts, Body::from(compressed)))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    fn types(entries: &[&str]) -> BinaryMediaTypes {
        BinaryMediaTypes::new(&entries.iter().map(|e| (*e).to_owned()).collect::<Vec<_>>())
    }

    fn media(value: &str) -> MediaType {
        value.parse().unwrap()
    }

    #[test]
    fn binary_media_types_match_exactly_by_type_and_by_wildcard() {
        let configured = types(&["image/png", "application/*", "MULTIPART/Form-Data"]);
        assert!(configured.matches(&media("image/png")));
        assert!(configured.matches(&media("IMAGE/PNG; charset=binary")));
        assert!(!configured.matches(&media("image/jpeg")));
        assert!(configured.matches(&media("application/octet-stream")));
        assert!(configured.matches(&media("application/pdf")));
        assert!(configured.matches(&media("multipart/form-data; boundary=x")));
        assert!(!configured.matches(&media("text/plain")));
        for any in ["*/*", "*"] {
            assert!(types(&[any]).matches(&media("text/plain")), "{any}");
        }
        assert!(types(&["image~1png"]).matches(&media("image/png")));
        assert!(!types(&[]).matches(&media("image/png")));
        assert!(!types(&["nonsense", "*/png", "/x"]).matches(&media("image/png")));
    }

    #[test]
    fn only_the_first_accept_media_type_decides() {
        let settings = PayloadSettings::new(&["image/webp".to_owned()], None);
        let request = |accept: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, HeaderValue::from_static(accept));
            headers
        };
        let browser = request("image/webp,image/*,*/*;q=0.8");
        assert!(settings.negotiate(&browser).wants_binary(None));
        let reordered = request("*/*;q=0.8,image/webp");
        assert!(!settings.negotiate(&reordered).wants_binary(None));
        let with_params = request("image/webp;q=0.9, text/html");
        assert!(settings.negotiate(&with_params).wants_binary(None));

        let everything = PayloadSettings::new(&["*/*".to_owned()], None);
        assert!(everything.negotiate(&reordered).wants_binary(None));
    }

    #[test]
    fn without_accept_the_response_content_type_decides() {
        let settings = PayloadSettings::new(&["image/*".to_owned()], None);
        let none = HeaderMap::new();
        let negotiation = settings.negotiate(&none);
        assert!(negotiation.wants_binary(Some("image/png")));
        assert!(!negotiation.wants_binary(Some("text/plain")));
        assert!(!negotiation.wants_binary(None));
        assert!(!negotiation.wants_binary(Some("garbage")));
    }

    #[test]
    fn request_bodies_are_binary_by_content_type() {
        let settings = PayloadSettings::new(&["application/octet-stream".to_owned()], None);
        let mut headers = HeaderMap::new();
        assert!(!settings.request_is_binary(&headers));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        assert!(settings.request_is_binary(&headers));
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(!settings.request_is_binary(&headers));
    }

    fn preferred(header: &str) -> Option<ContentCoding> {
        header.parse::<AcceptEncoding>().unwrap().preferred()
    }

    #[test]
    fn accept_encoding_forms_from_the_documentation() {
        assert_eq!(preferred("deflate,gzip"), Some(ContentCoding::Deflate));
        assert_eq!(preferred(""), None);
        assert_eq!(preferred("*"), Some(ContentCoding::Gzip));
        assert_eq!(
            preferred("deflate;q=0.5,gzip;q=1.0"),
            Some(ContentCoding::Gzip)
        );
        assert_eq!(
            preferred("gzip;q=1.0,identity;q=0.5,*;q=0"),
            Some(ContentCoding::Gzip)
        );
    }

    #[test]
    fn the_highest_priority_coding_must_be_one_api_gateway_supports() {
        assert_eq!(preferred("br,gzip;q=0.5"), None);
        assert_eq!(preferred("br;q=0.4,gzip;q=0.5"), Some(ContentCoding::Gzip));
        assert_eq!(preferred("identity,gzip;q=0.5"), None);
        assert_eq!(preferred("gzip;q=0"), None);
        assert_eq!(
            preferred("gzip;q=0,deflate;q=0.1"),
            Some(ContentCoding::Deflate)
        );
        assert_eq!(preferred("GZIP"), Some(ContentCoding::Gzip));
        assert_eq!(
            preferred("br;q=1,gzip;q=1"),
            None,
            "ties go to the first entry"
        );
        assert_eq!(
            preferred("gzip; Q=0.8, deflate;q=0.800"),
            Some(ContentCoding::Gzip)
        );
    }

    #[test]
    fn malformed_weights_ignore_the_whole_header() {
        for bad in [
            "gzip;q=2",
            "gzip;q=0.1234",
            "gzip;q=x",
            "gzip;q=-1",
            "gzip;q=1.5",
        ] {
            assert!(bad.parse::<AcceptEncoding>().is_err(), "{bad}");
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip;q=9"),
        );
        assert_eq!(AcceptEncoding::from_headers(&headers).preferred(), None);
    }

    #[test]
    fn several_accept_encoding_headers_are_combined() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("deflate;q=0.5"),
        );
        headers.append(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        assert_eq!(
            AcceptEncoding::from_headers(&headers).preferred(),
            Some(ContentCoding::Gzip)
        );
    }

    #[test]
    fn codings_round_trip() {
        let original = b"hello hello hello hello hello".repeat(20);
        for coding in [ContentCoding::Gzip, ContentCoding::Deflate] {
            let compressed = coding.compress(&original).unwrap();
            assert!(compressed.len() < original.len());
            assert_eq!(coding.decompress(&compressed).unwrap(), original);
        }
    }

    #[test]
    fn deflate_also_accepts_raw_streams() {
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"raw deflate").unwrap();
        let raw = encoder.finish().unwrap();
        assert_eq!(
            ContentCoding::Deflate.decompress(&raw).unwrap(),
            b"raw deflate"
        );
    }

    #[test]
    fn invalid_and_oversized_bodies_are_errors() {
        assert!(matches!(
            ContentCoding::Gzip.decompress(b"not gzip"),
            Err(DecompressError::Invalid("gzip"))
        ));
        assert!(matches!(
            ContentCoding::Deflate.decompress(b"\x00\x01 nope"),
            Err(DecompressError::Invalid("deflate"))
        ));
        let bomb = ContentCoding::Gzip
            .compress(&vec![0_u8; MAX_BODY_BYTES + 1])
            .unwrap();
        assert!(bomb.len() < 100_000);
        assert!(matches!(
            ContentCoding::Gzip.decompress(&bomb),
            Err(DecompressError::TooLarge)
        ));
        let at_limit = ContentCoding::Gzip
            .compress(&vec![0_u8; MAX_BODY_BYTES])
            .unwrap();
        assert_eq!(
            ContentCoding::Gzip.decompress(&at_limit).unwrap().len(),
            MAX_BODY_BYTES
        );
    }

    #[test]
    fn request_decompression_drops_the_encoding_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("30"));
        let body = ContentCoding::Gzip.compress(b"{\"a\":1}").unwrap();
        let decoded = PayloadSettings::decompress_request(&mut headers, Bytes::from(body)).unwrap();
        assert_eq!(&*decoded, b"{\"a\":1}");
        assert!(headers.is_empty());

        let mut other = HeaderMap::new();
        other.insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
        let body = Bytes::from_static(b"opaque");
        assert_eq!(
            PayloadSettings::decompress_request(&mut other, body.clone()).unwrap(),
            body
        );
        assert!(other.contains_key(header::CONTENT_ENCODING));
        let mut plain = HeaderMap::new();
        assert_eq!(
            PayloadSettings::decompress_request(&mut plain, body.clone()).unwrap(),
            body
        );
    }

    fn response(body: &'static [u8]) -> Response {
        let mut response = Response::new(Body::from(body));
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        response
    }

    fn accepting(coding: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static(coding));
        headers
    }

    async fn body_of(response: Response) -> Bytes {
        axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn responses_at_the_minimum_size_are_compressed_and_smaller_ones_are_not() {
        let settings = PayloadSettings::new(&[], Some(10));
        let at = settings
            .compress_response(&accepting("gzip"), response(b"0123456789"))
            .await
            .unwrap();
        assert_eq!(at.headers()[header::CONTENT_ENCODING], "gzip");
        assert!(at.headers().get(header::CONTENT_LENGTH).is_none());
        assert_eq!(
            ContentCoding::Gzip.decompress(&body_of(at).await).unwrap(),
            b"0123456789"
        );
        let below = settings
            .compress_response(&accepting("gzip"), response(b"012345678"))
            .await
            .unwrap();
        assert!(below.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(below.headers()[header::CONTENT_LENGTH], "9");
        assert_eq!(&*body_of(below).await, b"012345678");
    }

    #[tokio::test]
    async fn compression_needs_a_setting_a_supported_coding_and_a_body() {
        let body: &'static [u8] = b"0123456789";
        let off = PayloadSettings::new(&[], None);
        let out = off
            .compress_response(&accepting("gzip"), response(body))
            .await
            .unwrap();
        assert!(out.headers().get(header::CONTENT_ENCODING).is_none());

        let zero = PayloadSettings::new(&[], Some(0));
        for (accept, expected) in [
            ("deflate", Some("deflate")),
            ("br", None),
            ("identity", None),
            ("", None),
        ] {
            let out = zero
                .compress_response(&accepting(accept), response(body))
                .await
                .unwrap();
            assert_eq!(
                out.headers()
                    .get(header::CONTENT_ENCODING)
                    .map(|v| v.to_str().unwrap()),
                expected,
                "{accept:?}"
            );
        }
        let out = zero
            .compress_response(&HeaderMap::new(), response(body))
            .await
            .unwrap();
        assert!(out.headers().get(header::CONTENT_ENCODING).is_none());

        let empty = zero
            .compress_response(&accepting("gzip"), response(b""))
            .await
            .unwrap();
        assert!(empty.headers().get(header::CONTENT_ENCODING).is_none());

        let mut encoded = response(body);
        encoded
            .headers_mut()
            .insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
        let out = zero
            .compress_response(&accepting("gzip"), encoded)
            .await
            .unwrap();
        assert_eq!(out.headers()[header::CONTENT_ENCODING], "br");

        let mut no_content = response(body);
        *no_content.status_mut() = StatusCode::NO_CONTENT;
        let out = zero
            .compress_response(&accepting("gzip"), no_content)
            .await
            .unwrap();
        assert!(out.headers().get(header::CONTENT_ENCODING).is_none());
    }
}
