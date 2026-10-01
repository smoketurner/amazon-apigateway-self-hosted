//! Media types and payload conversion for non-proxy integrations: which
//! payloads are binary, and what `contentHandling` does to them.

use axum::body::Bytes;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::model::ContentHandling;

/// The media type API Gateway assumes for a request with no `Content-Type`.
pub(crate) const DEFAULT_MEDIA_TYPE: &str = "application/json";

/// A `Content-Type` reduced to its lowercase `type/subtype`, the key request and
/// response templates are matched by.
pub(crate) fn media_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// A payload that `contentHandling` could not convert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the payload is not valid Base64")]
pub(crate) struct NotBase64;

/// Which direction a payload is converted in: `CONVERT_TO_TEXT` Base64-encodes
/// a binary payload, `CONVERT_TO_BINARY` decodes a text payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Payload {
    Binary,
    Text,
}

impl ContentHandling {
    /// The payload after this conversion. A payload that is already in the
    /// target form passes through unchanged.
    pub(crate) fn convert(self, body: Bytes, payload: Payload) -> Result<Bytes, NotBase64> {
        match (self, payload) {
            (Self::ConvertToText, Payload::Binary) => Ok(Bytes::from(BASE64.encode(&body))),
            (Self::ConvertToBinary, Payload::Text) => {
                let text = String::from_utf8_lossy(&body);
                BASE64
                    .decode(text.trim())
                    .map(Bytes::from)
                    .map_err(|_| NotBase64)
            }
            (Self::ConvertToText, Payload::Text) | (Self::ConvertToBinary, Payload::Binary) => {
                Ok(body)
            }
        }
    }
}

/// Applies `handling`, when there is any, to `body`.
pub(crate) fn apply(
    handling: Option<ContentHandling>,
    body: Bytes,
    payload: Payload,
) -> Result<Bytes, NotBase64> {
    match handling {
        Some(handling) => handling.convert(body, payload),
        None => Ok(body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_types_are_lowercase_without_parameters() {
        assert_eq!(
            media_type(" Application/JSON ; charset=UTF-8"),
            "application/json"
        );
        assert_eq!(media_type("text/plain"), "text/plain");
        assert_eq!(media_type(""), "");
    }

    #[test]
    fn convert_to_text_encodes_binary_payloads_only() {
        let converted = ContentHandling::ConvertToText
            .convert(Bytes::from_static(&[0xff, 0x00, 0x7f]), Payload::Binary)
            .unwrap_or_default();
        assert_eq!(converted, Bytes::from_static(b"/wB/"));
        let text = Bytes::from_static(b"plain");
        assert_eq!(
            ContentHandling::ConvertToText.convert(text.clone(), Payload::Text),
            Ok(text)
        );
    }

    #[test]
    fn convert_to_binary_decodes_text_payloads_and_rejects_invalid_base64() {
        let decoded = ContentHandling::ConvertToBinary
            .convert(Bytes::from_static(b"/wB/\n"), Payload::Text)
            .unwrap_or_default();
        assert_eq!(decoded, Bytes::from_static(&[0xff, 0x00, 0x7f]));
        assert_eq!(
            ContentHandling::ConvertToBinary.convert(Bytes::from_static(b"!!"), Payload::Text),
            Err(NotBase64)
        );
        let binary = Bytes::from_static(&[1, 2]);
        assert_eq!(
            ContentHandling::ConvertToBinary.convert(binary.clone(), Payload::Binary),
            Ok(binary)
        );
    }

    #[test]
    fn no_content_handling_leaves_the_payload_alone() {
        let body = Bytes::from_static(b"x");
        assert_eq!(apply(None, body.clone(), Payload::Binary), Ok(body));
    }
}
