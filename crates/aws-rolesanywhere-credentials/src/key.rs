//! The certificate's private key, and signing with it.
//!
//! Roles Anywhere hashes the string to sign with SHA-256 whatever the key: RSA signs with
//! PKCS#1 v1.5 and ECDSA with an ASN.1 DER signature. aws-lc-rs signs every supported key
//! except P-384; see [`nist_p384`].

mod nist_p384;

use std::fmt;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa;
use aws_lc_rs::signature::{
    self, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P521_SHA256_ASN1_SIGNING, EcdsaKeyPair,
    UnparsedPublicKey, VerificationAlgorithm,
};
use rustls_pki_types::PrivateKeyDer;

use self::nist_p384::P384Key;

/// Signs a fixed message to tell whether a private key belongs to a certificate.
const PROBE: &[u8] = b"aws-rolesanywhere-credentials key check";

/// The Roles Anywhere signing algorithm a key's type selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Rsa,
    Ecdsa,
}

impl Algorithm {
    /// The name in the string to sign and the `Authorization` header.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Rsa => "AWS4-X509-RSA-SHA256",
            Self::Ecdsa => "AWS4-X509-ECDSA-SHA256",
        }
    }
}

/// The curves aws-lc-rs signs over SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P521,
}

/// A private key Roles Anywhere accepts.
pub(crate) enum SigningKey {
    Rsa(rsa::KeyPair),
    Ecdsa(EcdsaKeyPair, Curve),
    P384(P384Key),
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Rsa(_) => "Rsa",
            Self::Ecdsa(_, Curve::P256) => "EcdsaP256",
            Self::Ecdsa(_, Curve::P521) => "EcdsaP521",
            Self::P384(_) => "EcdsaP384",
        };
        f.debug_tuple("SigningKey").field(&kind).finish()
    }
}

impl SigningKey {
    /// Reads an RSA (PKCS#1 or PKCS#8) or EC (SEC1 or PKCS#8) key on P-256, P-384, or P-521.
    /// Any other key is `None`.
    pub(crate) fn from_der(key: &PrivateKeyDer<'_>) -> Option<Self> {
        match key {
            PrivateKeyDer::Pkcs1(der) => rsa::KeyPair::from_der(der.secret_pkcs1_der())
                .ok()
                .map(Self::Rsa),
            PrivateKeyDer::Sec1(der) => Self::elliptic(der.secret_sec1_der()),
            PrivateKeyDer::Pkcs8(der) => {
                let der = der.secret_pkcs8_der();
                rsa::KeyPair::from_pkcs8(der)
                    .ok()
                    .map(Self::Rsa)
                    .or_else(|| Self::elliptic(der))
            }
            _ => None,
        }
    }

    fn elliptic(der: &[u8]) -> Option<Self> {
        for (algorithm, curve) in [
            (&ECDSA_P256_SHA256_ASN1_SIGNING, Curve::P256),
            (&ECDSA_P521_SHA256_ASN1_SIGNING, Curve::P521),
        ] {
            if let Ok(key) = EcdsaKeyPair::from_private_key_der(algorithm, der) {
                return Some(Self::Ecdsa(key, curve));
            }
        }
        P384Key::from_der(der).map(Self::P384)
    }

    pub(crate) const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Rsa(_) => Algorithm::Rsa,
            Self::Ecdsa(..) | Self::P384(_) => Algorithm::Ecdsa,
        }
    }

    /// The signature of `message`'s SHA-256 digest, or `None` if the key fails to sign.
    pub(crate) fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::Rsa(key) => {
                let mut signature = vec![0_u8; key.public_modulus_len()];
                key.sign(
                    &signature::RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    message,
                    &mut signature,
                )
                .ok()?;
                Some(signature)
            }
            Self::Ecdsa(key, _) => key
                .sign(&SystemRandom::new(), message)
                .ok()
                .map(|signature| signature.as_ref().to_vec()),
            Self::P384(key) => key.sign(message),
        }
    }

    /// Whether this key is the private half of `public_key`, a certificate's
    /// `subjectPublicKey` bits. Checked by signing [`PROBE`] and verifying the signature.
    pub(crate) fn matches(&self, public_key: &[u8]) -> bool {
        self.sign(PROBE).is_some_and(|signature| {
            UnparsedPublicKey::new(self.verification_algorithm(), public_key)
                .verify(PROBE, &signature)
                .is_ok()
        })
    }

    pub(crate) fn verification_algorithm(&self) -> &'static dyn VerificationAlgorithm {
        match self {
            Self::Rsa(_) => &signature::RSA_PKCS1_2048_8192_SHA256,
            Self::Ecdsa(_, Curve::P256) => &signature::ECDSA_P256_SHA256_ASN1,
            Self::Ecdsa(_, Curve::P521) => &signature::ECDSA_P521_SHA256_ASN1,
            Self::P384(_) => &signature::ECDSA_P384_SHA256_ASN1,
        }
    }
}
