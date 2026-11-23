//! P-384 keys, signed with `RustCrypto`'s `p384`.
//!
//! Roles Anywhere signs a SHA-256 digest with every key, and aws-lc-rs 1.19.0 has no signing
//! algorithm for a P-384 key over SHA-256: `ECDSA_P384_SHA256_ASN1` exists only for
//! verification, and `EcdsaKeyPair::sign_digest` refuses a digest other than the key's own.
//! This module is the one place another crypto implementation is used; remove it once
//! aws-lc-rs can sign P-384 over SHA-256. The digest itself is still computed by aws-lc-rs.

use aws_lc_rs::digest::{SHA256, digest};
use p384::SecretKey;
use p384::ecdsa::signature::hazmat::PrehashSigner as _;
use p384::ecdsa::{DerSignature, SigningKey};
use p384::pkcs8::DecodePrivateKey as _;

pub(crate) struct P384Key(SigningKey);

impl P384Key {
    /// Reads a PKCS#8 or SEC1 P-384 key.
    pub(super) fn from_der(der: &[u8]) -> Option<Self> {
        let secret = SecretKey::from_pkcs8_der(der)
            .ok()
            .or_else(|| SecretKey::from_sec1_der(der).ok())?;
        Some(Self(SigningKey::from(secret)))
    }

    pub(super) fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        let hash = digest(&SHA256, message);
        let signature: DerSignature = self.0.sign_prehash(hash.as_ref()).ok()?;
        Some(signature.as_bytes().to_vec())
    }
}
