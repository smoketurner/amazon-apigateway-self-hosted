//! A custom domain's certificate exported from ACM (`--domain-cert-source acm`):
//! the certificate API Gateway serves for the domain, so clients see the same
//! one from either gateway.
//!
//! <https://docs.aws.amazon.com/acm/latest/userguide/acm-exportable-certificates.html>

use aws_sdk_acm::primitives::Blob;
use aws_sdk_acm::types::{CertificateExport, CertificateStatus, CertificateType};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use zeroize::Zeroizing;

use super::encrypted_key::{EncryptedKey, EncryptedKeyError};

#[derive(Debug, thiserror::Error)]
pub(crate) enum AcmError {
    #[error("ACM request for {arn} failed: {reason}")]
    Aws { arn: String, reason: String },
    #[error("certificate {arn} cannot be exported: {reason}")]
    NotExportable { arn: String, reason: &'static str },
    #[error("ACM returned no {what} for {arn}")]
    Missing { arn: String, what: &'static str },
    #[error("certificate {arn} could not be read: {source}")]
    Certificate {
        arn: String,
        source: rustls::pki_types::pem::Error,
    },
    #[error("private key of {arn}: {source}")]
    Key {
        arn: String,
        source: EncryptedKeyError,
    },
    #[error("no random passphrase could be generated")]
    Random,
    #[error("decrypting the private key of {arn} did not finish: {reason}")]
    Interrupted { arn: String, reason: String },
}

impl AcmError {
    fn aws(arn: &str, err: impl std::error::Error) -> Self {
        Self::Aws {
            arn: arn.to_owned(),
            reason: aws_sdk_acm::error::DisplayErrorContext(err).to_string(),
        }
    }

    fn missing(arn: &str, what: &'static str) -> Self {
        Self::Missing {
            arn: arn.to_owned(),
            what,
        }
    }
}

/// A certificate exported from ACM, with its key decrypted.
pub(crate) struct ExportedCertificate {
    /// The certificate followed by its chain.
    pub(crate) chain: Vec<CertificateDer<'static>>,
    pub(crate) key: PrivateKeyDer<'static>,
}

/// Reads and exports certificates from ACM.
#[derive(Clone)]
pub(crate) struct AcmCertificates {
    client: aws_sdk_acm::Client,
}

impl AcmCertificates {
    pub(crate) fn new(sdk_config: &aws_config::SdkConfig) -> Self {
        Self {
            client: aws_sdk_acm::Client::new(sdk_config),
        }
    }

    /// The configuration override that sends a request to the region the
    /// certificate is in: an edge-optimized domain's is always in us-east-1,
    /// whatever region the gateway is in.
    fn in_region_of(arn: &str) -> aws_sdk_acm::config::Builder {
        let builder = aws_sdk_acm::config::Builder::default();
        match arn.split(':').nth(3).filter(|region| !region.is_empty()) {
            Some(region) => builder.region(aws_sdk_acm::config::Region::new(region.to_owned())),
            None => builder,
        }
    }

    /// The serial number of the issued certificate `arn`, once it is known to
    /// be exportable. Cheap enough to ask on every refresh, unlike an export.
    ///
    /// # Errors
    ///
    /// When ACM cannot be reached, or the certificate is not issued or was not
    /// requested as exportable.
    pub(crate) async fn exportable_serial(&self, arn: &str) -> Result<String, AcmError> {
        let described = self
            .client
            .describe_certificate()
            .certificate_arn(arn)
            .customize()
            .config_override(Self::in_region_of(arn))
            .send()
            .await
            .map_err(|err| AcmError::aws(arn, err))?;
        let detail = described
            .certificate()
            .ok_or_else(|| AcmError::missing(arn, "certificate details"))?;
        let not_exportable = |reason| AcmError::NotExportable {
            arn: arn.to_owned(),
            reason,
        };
        // ACM exports what it issued with the Export option and what AWS
        // Private CA issued; never a certificate imported into it.
        let exportable = match detail.r#type() {
            Some(CertificateType::Imported) => {
                return Err(not_exportable(
                    "it was imported into ACM, which never exports imported certificates; serve its files with --domain-cert-dir",
                ));
            }
            Some(CertificateType::Private) => true,
            _ => {
                detail.options().and_then(|options| options.export())
                    == Some(&CertificateExport::Enabled)
            }
        };
        if !exportable {
            return Err(not_exportable(
                "it was not requested as exportable (ACM's Export option)",
            ));
        }
        if detail.status() != Some(&CertificateStatus::Issued) {
            return Err(not_exportable("it is not issued"));
        }
        detail
            .serial()
            .map(str::to_owned)
            .ok_or_else(|| AcmError::missing(arn, "serial number"))
    }

    /// Exports `arn` and decrypts its key. The passphrase is random, sent to
    /// ACM for this one export, and discarded afterwards: it only protects the
    /// key on its way from ACM.
    ///
    /// # Errors
    ///
    /// When the export fails or what it returns cannot be read.
    pub(crate) async fn export(&self, arn: &str) -> Result<ExportedCertificate, AcmError> {
        let passphrase = Passphrase::generate()?;
        let exported = self
            .client
            .export_certificate()
            .certificate_arn(arn)
            .passphrase(Blob::new(passphrase.0.to_vec()))
            .customize()
            .config_override(Self::in_region_of(arn))
            .send()
            .await
            .map_err(|err| AcmError::aws(arn, err))?;
        let certificate = exported
            .certificate()
            .ok_or_else(|| AcmError::missing(arn, "certificate"))?;
        let key = Zeroizing::new(
            exported
                .private_key()
                .ok_or_else(|| AcmError::missing(arn, "private key"))?
                .to_owned(),
        );
        // `CertificateChain` leaves out the certificate itself.
        let pem = format!(
            "{certificate}\n{}",
            exported.certificate_chain().unwrap_or_default()
        );
        let chain = CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| AcmError::Certificate {
                arn: arn.to_owned(),
                source,
            })?;
        // Up to MAX_ITERATIONS rounds of PBKDF2 take seconds, too long for an
        // async worker.
        let key = tokio::task::spawn_blocking(move || {
            EncryptedKey(key.as_str()).decrypt(passphrase.0.as_slice())
        })
        .await
        .map_err(|err| AcmError::Interrupted {
            arn: arn.to_owned(),
            reason: err.to_string(),
        })?
        .map_err(|source| AcmError::Key {
            arn: arn.to_owned(),
            source,
        })?;
        Ok(ExportedCertificate { chain, key })
    }
}

/// A one-time export passphrase: 32 letters and digits, inside ACM's limits
/// (4 to 128 ASCII characters, none of `#`, `$`, `%`).
struct Passphrase(Zeroizing<[u8; 32]>);

impl Passphrase {
    const ALPHABET: &'static [u8; 62] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    fn generate() -> Result<Self, AcmError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        aws_lc_rs::rand::fill(bytes.as_mut()).map_err(|_| AcmError::Random)?;
        for byte in bytes.iter_mut() {
            let index = usize::from(*byte)
                .checked_rem(Self::ALPHABET.len())
                .unwrap_or_default();
            *byte = Self::ALPHABET.get(index).copied().unwrap_or(b'A');
        }
        Ok(Self(bytes))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests against a local mock")]
pub(crate) mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use serde_json::json;

    use super::*;
    use crate::domain::encrypted_key::tests::{encrypt_for_test, encrypted_pem};
    use crate::observability::testing::{MockAws, Reply};

    const ARN: &str = "arn:aws:acm:us-east-1:123456789012:certificate/1";
    pub(crate) const DESCRIBE: &str = "CertificateManager.DescribeCertificate";
    pub(crate) const EXPORT: &str = "CertificateManager.ExportCertificate";

    /// A `DescribeCertificate` answer for a certificate ACM issued.
    pub(crate) fn described(serial: &str, status: &str, export: &str) -> Reply {
        described_as("AMAZON_ISSUED", serial, status, export)
    }

    pub(crate) fn described_as(kind: &str, serial: &str, status: &str, export: &str) -> Reply {
        Reply::json(
            &json!({"Certificate": {
                "CertificateArn": ARN, "Serial": serial, "Status": status,
                "Type": kind, "Options": {"Export": export}
            }})
            .to_string(),
        )
    }

    /// Answers exports with a certificate for `name` and its key, encrypted
    /// under the passphrase the gateway sends, as ACM does.
    pub(crate) fn answer_export(aws: &MockAws, name: &str) {
        answer_export_signed_by(aws, name, rcgen::KeyPair::generate().unwrap(), None);
    }

    /// Answers exports with a certificate for `name` and a key that is not its own.
    pub(crate) fn answer_export_with_another_key(aws: &MockAws, name: &str) {
        let other = rcgen::KeyPair::generate().unwrap();
        answer_export_signed_by(aws, name, rcgen::KeyPair::generate().unwrap(), Some(other));
    }

    fn answer_export_signed_by(
        aws: &MockAws,
        name: &str,
        key: rcgen::KeyPair,
        returned: Option<rcgen::KeyPair>,
    ) {
        let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let ca = rcgen::KeyPair::generate().unwrap();
        let ca_cert = rcgen::CertificateParams::new(vec!["ca.example".to_owned()])
            .unwrap()
            .self_signed(&ca)
            .unwrap();
        let key_der = returned.unwrap_or(key).serialize_der();
        aws.reply_with(EXPORT, move |request| {
            let passphrase = BASE64
                .decode(request["Passphrase"].as_str().unwrap())
                .unwrap();
            Reply::json(
                &json!({
                    "Certificate": cert.pem(),
                    "CertificateChain": ca_cert.pem(),
                    "PrivateKey": encrypt_for_test(&key_der, &passphrase),
                })
                .to_string(),
            )
        });
    }

    #[tokio::test]
    async fn requests_go_to_the_certificates_region() {
        let aws = MockAws::start().await;
        let acm = AcmCertificates::new(&aws.sdk_config());
        aws.reply(DESCRIBE, described("01", "ISSUED", "ENABLED"));
        acm.exportable_serial("arn:aws:acm:eu-west-1:1:certificate/x")
            .await
            .unwrap();
        acm.exportable_serial("not-an-arn").await.unwrap();
        let regions: Vec<_> = aws.calls().into_iter().map(|c| c.region).collect();
        assert_eq!(
            regions,
            [Some("eu-west-1".to_owned()), Some("us-east-1".to_owned())],
            "an ARN without a region keeps the gateway's"
        );
    }

    #[test]
    fn passphrases_are_random_and_within_acms_limits() {
        let first = Passphrase::generate().unwrap();
        let second = Passphrase::generate().unwrap();
        assert_ne!(*first.0, *second.0);
        assert!(first.0.iter().all(u8::is_ascii_alphanumeric));
    }

    #[tokio::test]
    async fn the_serial_is_read_only_from_an_issued_exportable_certificate() {
        let aws = MockAws::start().await;
        let acm = AcmCertificates::new(&aws.sdk_config());
        aws.reply_once(DESCRIBE, described("0a:01", "ISSUED", "ENABLED"));
        assert_eq!(acm.exportable_serial(ARN).await.unwrap(), "0a:01");
        aws.reply_once(DESCRIBE, described("0a:01", "ISSUED", "DISABLED"));
        assert!(matches!(
            acm.exportable_serial(ARN).await,
            Err(AcmError::NotExportable { .. })
        ));
        aws.reply_once(
            DESCRIBE,
            described("0a:01", "PENDING_VALIDATION", "ENABLED"),
        );
        assert!(matches!(
            acm.exportable_serial(ARN).await,
            Err(AcmError::NotExportable { .. })
        ));
        aws.reply_once(DESCRIBE, Reply::error("ResourceNotFoundException"));
        assert!(matches!(
            acm.exportable_serial(ARN).await,
            Err(AcmError::Aws { .. })
        ));
    }

    #[tokio::test]
    async fn imported_certificates_are_never_exportable_and_private_ca_ones_always_are() {
        let aws = MockAws::start().await;
        let acm = AcmCertificates::new(&aws.sdk_config());
        aws.reply_once(
            DESCRIBE,
            described_as("IMPORTED", "0a:01", "ISSUED", "ENABLED"),
        );
        let err = acm.exportable_serial(ARN).await.unwrap_err();
        assert!(err.to_string().contains("imported"), "{err}");
        assert!(err.to_string().contains("--domain-cert-dir"), "{err}");
        aws.reply_once(
            DESCRIBE,
            described_as("PRIVATE", "0a:02", "ISSUED", "DISABLED"),
        );
        assert_eq!(acm.exportable_serial(ARN).await.unwrap(), "0a:02");
        aws.reply_once(
            DESCRIBE,
            described_as("PRIVATE", "0a:02", "EXPIRED", "DISABLED"),
        );
        assert!(matches!(
            acm.exportable_serial(ARN).await,
            Err(AcmError::NotExportable { .. })
        ));
    }

    #[tokio::test]
    async fn an_export_yields_the_certificate_its_chain_and_a_usable_key() {
        let aws = MockAws::start().await;
        let acm = AcmCertificates::new(&aws.sdk_config());
        answer_export(&aws, "api.example.com");
        let exported = acm.export(ARN).await.unwrap();
        assert_eq!(exported.chain.len(), 2);
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        rustls::sign::CertifiedKey::from_der(exported.chain, exported.key, &provider).unwrap();
        let call = aws
            .calls()
            .into_iter()
            .find(|c| c.target == EXPORT)
            .unwrap();
        assert_eq!(call.body.get("CertificateArn").unwrap(), ARN);
    }

    #[tokio::test]
    async fn a_failed_or_unreadable_export_is_an_error() {
        let aws = MockAws::start().await;
        let acm = AcmCertificates::new(&aws.sdk_config());
        aws.reply_once(EXPORT, Reply::error("ResourceNotFoundException"));
        assert!(matches!(acm.export(ARN).await, Err(AcmError::Aws { .. })));
        aws.reply_once(EXPORT, Reply::json(r#"{"Certificate":"x"}"#));
        assert!(matches!(
            acm.export(ARN).await,
            Err(AcmError::Missing {
                what: "private key",
                ..
            })
        ));
        aws.reply_once(
            EXPORT,
            Reply::json(
                &json!({"Certificate": "x", "PrivateKey": encrypted_pem(b"\0\0\0")}).to_string(),
            ),
        );
        assert!(acm.export(ARN).await.is_err());
    }
}
