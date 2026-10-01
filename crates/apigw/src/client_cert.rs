//! The client certificate a request carries, as `$context.identity.clientCert`
//! and Lambda events report it.
//!
//! The certificate either completed this gateway's own mutual TLS handshake, or
//! was reported by a trusted proxy in `X-Forwarded-Client-Cert`. In both cases
//! it is described with API Gateway's field names and formats:
//! `subjectDN`/`issuerDN` as comma-separated attributes in certificate order
//! (`C=US,O=Acme,CN=client`), `serialNumber` as colon-separated hex bytes, and
//! validity dates as `May 28 12:30:02 2019 GMT`.
//!
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html>

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use serde_json::{Map, Value, json};
use x509_parser::prelude::{FromDer as _, X509Certificate, X509Name};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum CertError {
    #[error("not an X.509 certificate: {0}")]
    Der(String),
    #[error("not a PEM-encoded certificate")]
    Pem,
}

/// `notBefore` and `notAfter`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Validity {
    not_before: String,
    not_after: String,
}

/// What is known about a client certificate. A certificate forwarded without
/// its PEM carries only the fields the proxy reported.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClientCertDetails {
    pem: Option<String>,
    subject_dn: Option<String>,
    issuer_dn: Option<String>,
    serial_number: Option<String>,
    validity: Option<Validity>,
}

impl ClientCertDetails {
    /// Everything about the DER-encoded certificate `der`.
    pub(crate) fn from_der(der: &[u8]) -> Result<Self, CertError> {
        let (_, cert) =
            X509Certificate::from_der(der).map_err(|err| CertError::Der(err.to_string()))?;
        Ok(Self {
            pem: Some(Self::pem_of(der)),
            subject_dn: Some(Self::distinguished_name(cert.subject())),
            issuer_dn: Some(Self::distinguished_name(cert.issuer())),
            serial_number: Some(Self::serial(cert.raw_serial())),
            validity: Some(Validity {
                not_before: Self::date(cert.validity().not_before.timestamp()),
                not_after: Self::date(cert.validity().not_after.timestamp()),
            }),
        })
    }

    /// Everything about the first certificate in `pem`.
    pub(crate) fn from_pem(pem: &str) -> Result<Self, CertError> {
        let der = CertificateDer::from_pem_slice(pem.as_bytes()).map_err(|_| CertError::Pem)?;
        Self::from_der(der.as_ref())
    }

    /// A certificate known only by the subject a proxy reported.
    pub(crate) fn from_subject(subject: &str) -> Self {
        Self {
            subject_dn: Some(subject.to_owned()),
            ..Self::default()
        }
    }

    /// The `clientCert` object, with only the fields that are known.
    pub(crate) fn to_json(&self) -> Value {
        let mut fields = Map::new();
        if let Some(ref pem) = self.pem {
            fields.insert("clientCertPem".to_owned(), json!(pem));
        }
        if let Some(ref subject) = self.subject_dn {
            fields.insert("subjectDN".to_owned(), json!(subject));
        }
        if let Some(ref issuer) = self.issuer_dn {
            fields.insert("issuerDN".to_owned(), json!(issuer));
        }
        if let Some(ref serial) = self.serial_number {
            fields.insert("serialNumber".to_owned(), json!(serial));
        }
        if let Some(ref validity) = self.validity {
            fields.insert(
                "validity".to_owned(),
                json!({"notBefore": validity.not_before, "notAfter": validity.not_after}),
            );
        }
        Value::Object(fields)
    }

    fn pem_of(der: &[u8]) -> String {
        let encoded = BASE64.encode(der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(line));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }

    /// `C=US,O=Acme,CN=client`: attributes in certificate order, without spaces.
    fn distinguished_name(name: &X509Name<'_>) -> String {
        let attributes: Vec<String> = name
            .iter_rdn()
            .flat_map(x509_parser::prelude::RelativeDistinguishedName::iter)
            .map(|attribute| {
                let value = attribute.as_str().unwrap_or("?");
                format!("{}={value}", Self::attribute_name(attribute))
            })
            .collect();
        attributes.join(",")
    }

    fn attribute_name(attribute: &x509_parser::x509::AttributeTypeAndValue<'_>) -> String {
        x509_parser::objects::oid2abbrev(
            attribute.attr_type(),
            x509_parser::objects::oid_registry(),
        )
        .map_or_else(|_| attribute.attr_type().to_id_string(), str::to_owned)
    }

    /// `a1:b2:...`: the serial number's bytes in lowercase hex.
    fn serial(raw: &[u8]) -> String {
        let bytes: Vec<String> = raw.iter().map(|byte| format!("{byte:02x}")).collect();
        bytes.join(":")
    }

    /// OpenSSL's `May 28 12:30:02 2019 GMT`, with a space-padded day.
    fn date(epoch_seconds: i64) -> String {
        jiff::Timestamp::from_second(epoch_seconds).map_or_else(
            |_| "-".to_owned(),
            |at| at.strftime("%b %e %H:%M:%S %Y GMT").to_string(),
        )
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index JSON they built")]
pub(crate) mod tests {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    use super::*;

    /// A self-signed certificate with the given subject attributes.
    pub(crate) fn certificate(common_name: &str) -> (CertificateDer<'static>, String) {
        let mut params = CertificateParams::new(vec![]).unwrap();
        let mut name = DistinguishedName::new();
        name.push(DnType::CountryName, "US");
        name.push(DnType::OrganizationName, "Acme");
        name.push(DnType::CommonName, common_name);
        params.distinguished_name = name;
        params.not_before = rcgen::date_time_ymd(2024, 5, 28);
        params.not_after = rcgen::date_time_ymd(2034, 8, 5);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.der().clone(), cert.pem())
    }

    /// A certificate authority that issues client certificates.
    pub(crate) struct TestCa {
        pub(crate) pem: String,
        params: CertificateParams,
        key: KeyPair,
    }

    /// A client certificate and its private key.
    pub(crate) struct TestClient {
        pub(crate) chain: Vec<CertificateDer<'static>>,
        pub(crate) key: rustls::pki_types::PrivateKeyDer<'static>,
    }

    pub(crate) fn ca(common_name: &str) -> TestCa {
        let mut params = CertificateParams::new(vec![]).unwrap();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, common_name);
        params.distinguished_name = name;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        TestCa {
            pem: cert.pem(),
            params,
            key,
        }
    }

    impl TestCa {
        /// A client certificate for `common_name`, valid from `not_before` to
        /// `not_after` (years).
        pub(crate) fn issue(
            &self,
            common_name: &str,
            not_before: i32,
            not_after: i32,
        ) -> TestClient {
            let mut params = CertificateParams::new(vec![]).unwrap();
            let mut name = DistinguishedName::new();
            name.push(DnType::CountryName, "US");
            name.push(DnType::OrganizationName, "Acme");
            name.push(DnType::CommonName, common_name);
            params.distinguished_name = name;
            params.not_before = rcgen::date_time_ymd(not_before, 1, 1);
            params.not_after = rcgen::date_time_ymd(not_after, 1, 1);
            let key = KeyPair::generate().unwrap();
            let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
            let cert = params.signed_by(&key, &issuer).unwrap();
            TestClient {
                chain: vec![cert.der().clone()],
                key: rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            }
        }
    }

    #[test]
    fn certificates_are_described_with_api_gateways_fields_and_formats() {
        let (der, pem) = certificate("client one");
        let details = ClientCertDetails::from_der(der.as_ref()).unwrap();
        let json = details.to_json();
        assert_eq!(json["subjectDN"], "C=US,O=Acme,CN=client one");
        assert_eq!(json["issuerDN"], "C=US,O=Acme,CN=client one");
        assert_eq!(json["validity"]["notBefore"], "May 28 00:00:00 2024 GMT");
        assert_eq!(json["validity"]["notAfter"], "Aug  5 00:00:00 2034 GMT");
        let serial = json["serialNumber"].as_str().unwrap();
        assert!(
            serial
                .split(':')
                .all(|byte| byte.len() == 2 && byte.chars().all(|c| c.is_ascii_hexdigit())),
            "{serial}"
        );
        assert_eq!(serial, serial.to_lowercase());
        let regenerated = json["clientCertPem"].as_str().unwrap();
        assert!(regenerated.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(regenerated.ends_with("-----END CERTIFICATE-----\n"));
        assert_eq!(
            CertificateDer::from_pem_slice(regenerated.as_bytes()).unwrap(),
            der
        );
        assert_eq!(ClientCertDetails::from_pem(&pem).unwrap(), details);
    }

    #[test]
    fn certificates_known_only_by_subject_report_only_that() {
        let details = ClientCertDetails::from_subject("CN=proxy-reported");
        assert_eq!(details.to_json(), json!({"subjectDN": "CN=proxy-reported"}));
    }

    #[test]
    fn garbage_is_not_a_certificate() {
        assert!(matches!(
            ClientCertDetails::from_der(b"not a certificate"),
            Err(CertError::Der(_))
        ));
        assert_eq!(ClientCertDetails::from_pem("nope"), Err(CertError::Pem));
        assert_eq!(ClientCertDetails::from_pem(""), Err(CertError::Pem));
    }
}
