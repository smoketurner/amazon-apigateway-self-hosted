//! The certificate and private key a session is signed with, read from PEM files.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustls_pki_types::pem::{self, PemObject as _};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::prelude::{FromDer as _, X509Certificate};

use crate::key::SigningKey;

/// Why the certificate or private key could not be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// The certificate file could not be read as PEM.
    #[error("could not read the certificates in {}: {source}", path.display())]
    ReadCertificate {
        /// The certificate file.
        path: PathBuf,
        /// What went wrong.
        #[source]
        source: pem::Error,
    },
    /// The certificate file holds no `CERTIFICATE` block.
    #[error("{} holds no certificate", path.display())]
    NoCertificate {
        /// The certificate file.
        path: PathBuf,
    },
    /// The first certificate is not a valid X.509 certificate.
    #[error("the first certificate in {} is not a valid X.509 certificate", path.display())]
    ParseCertificate {
        /// The certificate file.
        path: PathBuf,
    },
    /// The private key file could not be read as PEM.
    #[error("could not read the private key in {}: {source}", path.display())]
    ReadKey {
        /// The private key file.
        path: PathBuf,
        /// What went wrong.
        #[source]
        source: pem::Error,
    },
    /// The key is not an RSA, P-256, P-384, or P-521 key.
    #[error("the private key in {} is not an RSA, P-256, P-384, or P-521 key", path.display())]
    UnsupportedKey {
        /// The private key file.
        path: PathBuf,
    },
    /// The key does not belong to the first certificate.
    #[error(
        "the private key in {} does not belong to the certificate in {}",
        key.display(),
        certificate.display()
    )]
    KeyMismatch {
        /// The certificate file.
        certificate: PathBuf,
        /// The private key file.
        key: PathBuf,
    },
}

/// A certificate, its intermediates, and its private key.
#[derive(Debug)]
pub(crate) struct Identity {
    /// The base64 DER of the end-entity certificate, the `X-Amz-X509` header.
    pub(crate) certificate: String,
    /// The base64 DER of each intermediate, comma-separated: the `X-Amz-X509-Chain` header.
    pub(crate) chain: Option<String>,
    /// The certificate's serial number in decimal, which stands in for an access key ID.
    pub(crate) serial: String,
    pub(crate) key: SigningKey,
}

impl Identity {
    /// Reads the certificate file (the end-entity certificate first, then any intermediates,
    /// as cert-manager writes `tls.crt`) and the private key file (PKCS#8, PKCS#1, or SEC1).
    pub(crate) fn load(certificate: &Path, private_key: &Path) -> Result<Self, IdentityError> {
        let certificates = CertificateDer::pem_file_iter(certificate)
            .and_then(Iterator::collect::<Result<Vec<_>, _>>)
            .map_err(|source| IdentityError::ReadCertificate {
                path: certificate.to_owned(),
                source,
            })?;
        let Some((leaf, intermediates)) = certificates.split_first() else {
            return Err(IdentityError::NoCertificate {
                path: certificate.to_owned(),
            });
        };
        let (_, parsed) =
            X509Certificate::from_der(leaf).map_err(|_| IdentityError::ParseCertificate {
                path: certificate.to_owned(),
            })?;
        let der =
            PrivateKeyDer::from_pem_file(private_key).map_err(|source| IdentityError::ReadKey {
                path: private_key.to_owned(),
                source,
            })?;
        let key = SigningKey::from_der(&der).ok_or_else(|| IdentityError::UnsupportedKey {
            path: private_key.to_owned(),
        })?;
        if !key.matches(&parsed.public_key().subject_public_key.data) {
            return Err(IdentityError::KeyMismatch {
                certificate: certificate.to_owned(),
                key: private_key.to_owned(),
            });
        }
        let chain = (!intermediates.is_empty()).then(|| {
            intermediates
                .iter()
                .map(|intermediate| STANDARD.encode(intermediate))
                .collect::<Vec<_>>()
                .join(",")
        });
        Ok(Self {
            certificate: STANDARD.encode(leaf),
            chain,
            serial: parsed.tbs_certificate.serial.to_string(),
            key,
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use aws_lc_rs::encoding::AsDer as _;
    use aws_lc_rs::signature::{self, EcdsaKeyPair, UnparsedPublicKey, VerificationAlgorithm};
    use rcgen::{
        KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA256,
        PKCS_ED25519, PKCS_RSA_SHA256, SignatureAlgorithm,
    };

    use super::*;
    use crate::key::Algorithm;
    use crate::testing::{Pki, SERIAL, TempDir, pem, pkcs8_inner_key};

    fn load(pki: &Pki, key_pem: &str) -> Result<Identity, IdentityError> {
        let dir = TempDir::new();
        let certificate = dir.write("tls.crt", pki.bundle());
        let key = dir.write("tls.key", key_pem);
        Identity::load(&certificate, &key)
    }

    /// Signs with the loaded key and verifies with the certificate's public key, as Roles
    /// Anywhere does.
    fn assert_signs_for(
        pki: &Pki,
        identity: &Identity,
        verify: &'static dyn VerificationAlgorithm,
    ) {
        let message = b"string to sign";
        let signature = identity.key.sign(message).unwrap();
        let (_, leaf) = X509Certificate::from_der(&pki.leaf_der).unwrap();
        UnparsedPublicKey::new(verify, &leaf.public_key().subject_public_key.data)
            .verify(message, &signature)
            .unwrap();
    }

    #[test]
    fn every_supported_key_type_loads_and_signs_over_sha256() {
        let cases: [(
            &'static SignatureAlgorithm,
            Algorithm,
            &'static dyn VerificationAlgorithm,
        ); 4] = [
            (
                &PKCS_RSA_SHA256,
                Algorithm::Rsa,
                &signature::RSA_PKCS1_2048_8192_SHA256,
            ),
            (
                &PKCS_ECDSA_P256_SHA256,
                Algorithm::Ecdsa,
                &signature::ECDSA_P256_SHA256_ASN1,
            ),
            (
                &PKCS_ECDSA_P384_SHA384,
                Algorithm::Ecdsa,
                &signature::ECDSA_P384_SHA256_ASN1,
            ),
            (
                &PKCS_ECDSA_P521_SHA256,
                Algorithm::Ecdsa,
                &signature::ECDSA_P521_SHA256_ASN1,
            ),
        ];
        for (generate, algorithm, verify) in cases {
            let pki = Pki::issue(generate);
            let identity = load(&pki, &pki.key.serialize_pem()).unwrap();
            assert_eq!(identity.key.algorithm(), algorithm, "{generate:?}");
            assert_signs_for(&pki, &identity, verify);
        }
    }

    #[test]
    fn debug_output_names_the_key_type_and_nothing_else() {
        for (generate, expected) in [
            (&PKCS_RSA_SHA256, "Rsa"),
            (&PKCS_ECDSA_P256_SHA256, "EcdsaP256"),
            (&PKCS_ECDSA_P384_SHA384, "EcdsaP384"),
            (&PKCS_ECDSA_P521_SHA256, "EcdsaP521"),
        ] {
            let pki = Pki::issue(generate);
            let identity = load(&pki, &pki.key.serialize_pem()).unwrap();
            assert_eq!(
                format!("{:?}", identity.key),
                format!("SigningKey({expected:?})")
            );
        }
    }

    #[test]
    fn sec1_and_pkcs1_keys_load() {
        for (generate, signing, verify) in [
            (
                &PKCS_ECDSA_P256_SHA256,
                &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                &signature::ECDSA_P256_SHA256_ASN1,
            ),
            (
                &PKCS_ECDSA_P384_SHA384,
                &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                &signature::ECDSA_P384_SHA256_ASN1,
            ),
            (
                &PKCS_ECDSA_P521_SHA256,
                &signature::ECDSA_P521_SHA256_ASN1_SIGNING,
                &signature::ECDSA_P521_SHA256_ASN1,
            ),
        ] {
            let pki = Pki::issue(generate);
            let sec1 = EcdsaKeyPair::from_pkcs8(signing, &pki.key.serialize_der())
                .unwrap()
                .private_key()
                .as_der()
                .unwrap();
            let identity = load(&pki, &pem("EC PRIVATE KEY", sec1.as_ref())).unwrap();
            assert_signs_for(&pki, &identity, verify);
        }
        let pki = Pki::issue(&PKCS_RSA_SHA256);
        let pkcs1 = pkcs8_inner_key(&pki.key.serialize_der());
        let identity = load(&pki, &pem("RSA PRIVATE KEY", &pkcs1)).unwrap();
        assert_eq!(identity.key.algorithm(), Algorithm::Rsa);
        assert_signs_for(&pki, &identity, &signature::RSA_PKCS1_2048_8192_SHA256);
    }

    #[test]
    fn the_headers_carry_the_leaf_its_intermediates_and_the_decimal_serial() {
        let pki = Pki::issue(&PKCS_ECDSA_P256_SHA256);
        let identity = load(&pki, &pki.key.serialize_pem()).unwrap();
        assert_eq!(identity.certificate, STANDARD.encode(&pki.leaf_der));
        assert_eq!(
            identity.chain.as_deref(),
            Some(STANDARD.encode(&pki.intermediate_der).as_str())
        );
        assert_eq!(identity.serial, u128::from_be_bytes(SERIAL).to_string());

        let dir = TempDir::new();
        let certificate = dir.write(
            "tls.crt",
            format!(
                "{}{}{}",
                pki.leaf_pem, pki.intermediate_pem, pki.intermediate_pem
            ),
        );
        let key = dir.write("tls.key", pki.key.serialize_pem());
        let two = Identity::load(&certificate, &key).unwrap();
        let intermediate = STANDARD.encode(&pki.intermediate_der);
        assert_eq!(two.chain.unwrap(), format!("{intermediate},{intermediate}"));

        let alone = dir.write("leaf.crt", &pki.leaf_pem);
        assert_eq!(Identity::load(&alone, &key).unwrap().chain, None);
    }

    #[test]
    fn unusable_files_are_reported_by_path() {
        let pki = Pki::issue(&PKCS_ECDSA_P256_SHA256);
        let dir = TempDir::new();
        let (certificate, key) = pki.write(&dir);
        let missing = dir.path("missing.pem");
        let empty = dir.write("empty.pem", "");
        let garbage = dir.write("garbage.pem", pem("CERTIFICATE", b"not a certificate"));

        let error = Identity::load(&missing, &key).unwrap_err();
        assert!(
            matches!(error, IdentityError::ReadCertificate { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("missing.pem"), "{error}");
        let error = Identity::load(&empty, &key).unwrap_err();
        assert!(
            matches!(error, IdentityError::NoCertificate { .. }),
            "{error}"
        );
        assert_eq!(
            error.to_string(),
            format!("{} holds no certificate", empty.display())
        );
        let error = Identity::load(&garbage, &key).unwrap_err();
        assert!(
            matches!(error, IdentityError::ParseCertificate { .. }),
            "{error}"
        );
        let error = Identity::load(&certificate, &missing).unwrap_err();
        assert!(matches!(error, IdentityError::ReadKey { .. }), "{error}");
        let error = Identity::load(&certificate, &certificate).unwrap_err();
        assert!(matches!(error, IdentityError::ReadKey { .. }), "{error}");
    }

    #[test]
    fn other_key_types_and_other_keys_are_rejected() {
        let pki = Pki::issue(&PKCS_ECDSA_P256_SHA256);
        let ed25519 = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let error = load(&pki, &ed25519.serialize_pem()).unwrap_err();
        assert!(
            matches!(error, IdentityError::UnsupportedKey { .. }),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .ends_with("is not an RSA, P-256, P-384, or P-521 key"),
            "{error}"
        );

        for other in [
            &PKCS_ECDSA_P256_SHA256,
            &PKCS_ECDSA_P384_SHA384,
            &PKCS_ECDSA_P521_SHA256,
            &PKCS_RSA_SHA256,
        ] {
            let other = KeyPair::generate_for(other).unwrap();
            let error = load(&pki, &other.serialize_pem()).unwrap_err();
            assert!(
                matches!(error, IdentityError::KeyMismatch { .. }),
                "{error}"
            );
        }
        let p384 = Pki::issue(&PKCS_ECDSA_P384_SHA384);
        let other = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let error = load(&p384, &other.serialize_pem()).unwrap_err();
        assert!(
            matches!(error, IdentityError::KeyMismatch { .. }),
            "{error}"
        );
    }
}
