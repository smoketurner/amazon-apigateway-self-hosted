//! The private key ACM's `ExportCertificate` returns: a PKCS #8
//! `EncryptedPrivateKeyInfo` (RFC 5958) encrypted with PBES2 (RFC 8018).
//! Decrypted with aws-lc-rs, so it stays the only crypto implementation.
//!
//! Only PBES2 with PBKDF2 (HMAC-SHA1/256/384/512) and AES-CBC is accepted: the
//! scheme OpenSSL writes by default and the one RFC 8018 recommends. Anything
//! else (scrypt, PBES1, other ciphers) is refused rather than guessed at.

use std::num::NonZeroU32;

use aws_lc_rs::cipher::{
    AES_128, AES_192, AES_256, Algorithm, DecryptionContext, PaddedBlockDecryptingKey,
    UnboundCipherKey,
};
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::pbkdf2;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use x509_parser::der_parser::ber::BerObject;
use x509_parser::der_parser::der::parse_der;
use zeroize::Zeroizing;

/// The PEM labels an encrypted key is read under: RFC 7468's, and the one
/// ACM's API reference gives.
const LABELS: [&str; 2] = ["ENCRYPTED PRIVATE KEY", "PRIVATE KEY"];

const PBES2: &str = "1.2.840.113549.1.5.13";
const PBKDF2: &str = "1.2.840.113549.1.5.12";

/// More rounds than any exporter writes; the bound keeps a hostile key from
/// costing minutes of CPU.
const MAX_ITERATIONS: u32 = 10_000_000;

#[derive(Debug, thiserror::Error)]
pub(crate) enum EncryptedKeyError {
    #[error("the private key is not an encrypted PKCS #8 PEM block")]
    Pem,
    #[error("the encrypted private key is malformed: {0}")]
    Malformed(&'static str),
    #[error("the private key is encrypted with an unsupported scheme: {0}")]
    Unsupported(String),
    #[error("the private key could not be decrypted with the passphrase")]
    Decrypt,
}

/// An encrypted private key, as PEM.
pub(crate) struct EncryptedKey<'a>(pub(crate) &'a str);

impl EncryptedKey<'_> {
    /// Decrypts the key with `passphrase`.
    ///
    /// # Errors
    ///
    /// When the PEM or DER is malformed, the scheme is not PBES2 with PBKDF2
    /// and AES-CBC, or the passphrase does not decrypt it.
    pub(crate) fn decrypt(
        &self,
        passphrase: &[u8],
    ) -> Result<PrivateKeyDer<'static>, EncryptedKeyError> {
        let der = self.der()?;
        let (rest, info) = parse_der(&der).map_err(|_| EncryptedKeyError::Malformed("not DER"))?;
        if !rest.is_empty() {
            return Err(EncryptedKeyError::Malformed("trailing data"));
        }
        let [algorithm, data] = sequence(&info, "EncryptedPrivateKeyInfo")? else {
            return Err(EncryptedKeyError::Malformed("EncryptedPrivateKeyInfo"));
        };
        let scheme = Pbes2::parse(algorithm)?;
        let data = data
            .as_slice()
            .map_err(|_| EncryptedKeyError::Malformed("encryptedData"))?;
        scheme.decrypt(data, passphrase)
    }

    /// The DER inside the PEM block. ACM's API reference gives the label as
    /// `PRIVATE KEY` and its example as `ENCRYPTED PRIVATE KEY`; either is
    /// read, and the content must decrypt either way.
    fn der(&self) -> Result<Vec<u8>, EncryptedKeyError> {
        let boundary = |line: &str, kind: &str| {
            line.strip_prefix("-----")
                .and_then(|rest| rest.strip_prefix(kind))
                .and_then(|rest| rest.strip_prefix(' '))
                .and_then(|rest| rest.strip_suffix("-----"))
                .is_some_and(|label| LABELS.contains(&label))
        };
        let mut body = String::new();
        let mut inside = false;
        for line in self.0.lines().map(str::trim) {
            if !inside {
                inside = boundary(line, "BEGIN");
            } else if boundary(line, "END") {
                return BASE64.decode(body).map_err(|_| EncryptedKeyError::Pem);
            } else {
                body.push_str(line);
            }
        }
        Err(EncryptedKeyError::Pem)
    }
}

/// The elements of `object`, a SEQUENCE.
fn sequence<'a>(
    object: &'a BerObject<'a>,
    what: &'static str,
) -> Result<&'a [BerObject<'a>], EncryptedKeyError> {
    object
        .as_sequence()
        .map(Vec::as_slice)
        .map_err(|_| EncryptedKeyError::Malformed(what))
}

/// The OID of an `AlgorithmIdentifier` and its parameters.
fn algorithm_identifier<'a>(
    object: &'a BerObject<'a>,
    what: &'static str,
) -> Result<(String, Option<&'a BerObject<'a>>), EncryptedKeyError> {
    let (oid, parameters) = match sequence(object, what)? {
        [oid] => (oid, None),
        [oid, parameters] => (oid, Some(parameters)),
        _ => return Err(EncryptedKeyError::Malformed(what)),
    };
    let oid = oid
        .as_oid()
        .map_err(|_| EncryptedKeyError::Malformed(what))?
        .to_id_string();
    Ok((oid, parameters))
}

/// The cipher of a PBES2 `encryptionScheme`.
#[derive(Debug, Clone, Copy)]
struct Cipher {
    algorithm: &'static Algorithm,
    key_len: usize,
}

impl Cipher {
    fn from_oid(oid: &str) -> Result<Self, EncryptedKeyError> {
        let (algorithm, key_len) = match oid {
            "2.16.840.1.101.3.4.1.2" => (&AES_128, 16),
            "2.16.840.1.101.3.4.1.22" => (&AES_192, 24),
            "2.16.840.1.101.3.4.1.42" => (&AES_256, 32),
            other => return Err(EncryptedKeyError::Unsupported(format!("cipher {other}"))),
        };
        Ok(Self { algorithm, key_len })
    }
}

fn prf_from_oid(oid: &str) -> Result<pbkdf2::Algorithm, EncryptedKeyError> {
    match oid {
        "1.2.840.113549.2.7" => Ok(pbkdf2::PBKDF2_HMAC_SHA1),
        "1.2.840.113549.2.9" => Ok(pbkdf2::PBKDF2_HMAC_SHA256),
        "1.2.840.113549.2.10" => Ok(pbkdf2::PBKDF2_HMAC_SHA384),
        "1.2.840.113549.2.11" => Ok(pbkdf2::PBKDF2_HMAC_SHA512),
        other => Err(EncryptedKeyError::Unsupported(format!("PRF {other}"))),
    }
}

/// PBES2 parameters: PBKDF2 for the key, AES-CBC for the data.
struct Pbes2<'a> {
    salt: &'a [u8],
    iterations: NonZeroU32,
    prf: pbkdf2::Algorithm,
    cipher: Cipher,
    iv: [u8; 16],
}

impl<'a> Pbes2<'a> {
    fn parse(algorithm: &'a BerObject<'a>) -> Result<Self, EncryptedKeyError> {
        let (oid, parameters) = algorithm_identifier(algorithm, "encryptionAlgorithm")?;
        if oid != PBES2 {
            return Err(EncryptedKeyError::Unsupported(format!("scheme {oid}")));
        }
        let parameters = parameters.ok_or(EncryptedKeyError::Malformed("PBES2-params"))?;
        let [kdf, scheme] = sequence(parameters, "PBES2-params")? else {
            return Err(EncryptedKeyError::Malformed("PBES2-params"));
        };

        let (kdf_oid, kdf_parameters) = algorithm_identifier(kdf, "keyDerivationFunc")?;
        if kdf_oid != PBKDF2 {
            return Err(EncryptedKeyError::Unsupported(format!(
                "key derivation {kdf_oid}"
            )));
        }
        let kdf_parameters = kdf_parameters.ok_or(EncryptedKeyError::Malformed("PBKDF2-params"))?;
        let Some((salt, rest)) = sequence(kdf_parameters, "PBKDF2-params")?.split_first() else {
            return Err(EncryptedKeyError::Malformed("PBKDF2-params"));
        };
        let salt = salt.as_slice().map_err(|_| {
            EncryptedKeyError::Unsupported("a PBKDF2 salt that is not an OCTET STRING".to_owned())
        })?;
        let Some((iterations, rest)) = rest.split_first() else {
            return Err(EncryptedKeyError::Malformed("iterationCount"));
        };
        let iterations = iterations
            .as_u32()
            .ok()
            .filter(|n| *n <= MAX_ITERATIONS)
            .and_then(NonZeroU32::new)
            .ok_or(EncryptedKeyError::Malformed("iterationCount"))?;
        // keyLength and prf are both optional; prf defaults to HMAC-SHA1.
        let mut key_length = None;
        let mut prf = pbkdf2::PBKDF2_HMAC_SHA1;
        for field in rest {
            if let Ok(length) = field.as_u32() {
                key_length = Some(length);
            } else {
                let (prf_oid, _) = algorithm_identifier(field, "prf")?;
                prf = prf_from_oid(&prf_oid)?;
            }
        }

        let (cipher_oid, iv) = algorithm_identifier(scheme, "encryptionScheme")?;
        let cipher = Cipher::from_oid(&cipher_oid)?;
        if key_length.is_some_and(|length| usize::try_from(length).ok() != Some(cipher.key_len)) {
            return Err(EncryptedKeyError::Malformed("keyLength"));
        }
        let iv = iv
            .and_then(|iv| iv.as_slice().ok())
            .and_then(|iv| <[u8; 16]>::try_from(iv).ok())
            .ok_or(EncryptedKeyError::Malformed("AES-CBC IV"))?;
        Ok(Self {
            salt,
            iterations,
            prf,
            cipher,
            iv,
        })
    }

    fn decrypt(
        &self,
        data: &[u8],
        passphrase: &[u8],
    ) -> Result<PrivateKeyDer<'static>, EncryptedKeyError> {
        let mut key = Zeroizing::new(vec![0_u8; self.cipher.key_len]);
        pbkdf2::derive(self.prf, self.iterations, self.salt, passphrase, &mut key);
        let key = UnboundCipherKey::new(self.cipher.algorithm, &key)
            .and_then(PaddedBlockDecryptingKey::cbc_pkcs7)
            .map_err(|_| EncryptedKeyError::Decrypt)?;
        let mut buffer = Zeroizing::new(data.to_vec());
        let plain = key
            .decrypt(
                &mut buffer,
                DecryptionContext::Iv128(FixedLength::from(self.iv)),
            )
            .map_err(|_| EncryptedKeyError::Decrypt)?;
        // A wrong passphrase can still unpad cleanly; what it yields is not a
        // single DER SEQUENCE.
        let whole = parse_der(plain)
            .is_ok_and(|(rest, info)| rest.is_empty() && info.as_sequence().is_ok());
        if !whole {
            return Err(EncryptedKeyError::Decrypt);
        }
        Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            plain.to_vec(),
        )))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests over fixed fixtures")]
pub(crate) mod tests {
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _, RsaKeyPair,
    };
    use rustls::pki_types::SubjectPublicKeyInfoDer;
    use rustls::pki_types::pem::PemObject as _;
    use x509_parser::prelude::FromDer as _;
    use x509_parser::x509::SubjectPublicKeyInfo;

    use super::*;

    /// The passphrase every fixture was encrypted with (`openssl pkcs8 -topk8`).
    const PASSPHRASE: &[u8] = b"correct-horse";

    /// `der` as an encrypted key PEM block. Assembled from the label so the
    /// source holds no PEM header for secret scanners to find.
    pub(crate) fn encrypted_pem(der: &[u8]) -> String {
        let label = LABELS.first().unwrap();
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            BASE64.encode(der)
        )
    }

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!("../../tests/fixtures/encrypted-keys/", $name))
        };
    }

    fn public_key(pem: &str) -> Vec<u8> {
        let der = SubjectPublicKeyInfoDer::from_pem_slice(pem.as_bytes()).unwrap();
        let (_, spki) = SubjectPublicKeyInfo::from_der(der.as_ref()).unwrap();
        spki.subject_public_key.data.to_vec()
    }

    fn pkcs8(key: &PrivateKeyDer<'_>) -> Vec<u8> {
        let PrivateKeyDer::Pkcs8(der) = key else {
            return Vec::new();
        };
        der.secret_pkcs8_der().to_vec()
    }

    #[test]
    fn every_pbkdf2_prf_and_aes_key_size_decrypts_to_the_same_key() {
        let expected = public_key(fixture!("ec.pub.pem"));
        for pem in [
            fixture!("aes256-sha256.pem"),
            fixture!("aes128-sha1.pem"),
            fixture!("aes192-sha512.pem"),
        ] {
            let key = EncryptedKey(pem).decrypt(PASSPHRASE).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8(&key)).unwrap();
            assert_eq!(pair.public_key().as_ref(), expected.as_slice());
        }
    }

    #[test]
    fn rsa_keys_decrypt_too() {
        let key = EncryptedKey(fixture!("rsa-aes256-sha384.pem"))
            .decrypt(PASSPHRASE)
            .unwrap();
        let pair = RsaKeyPair::from_pkcs8(&pkcs8(&key)).unwrap();
        assert_eq!(
            pair.public_key().as_ref(),
            public_key(fixture!("rsa.pub.pem"))
        );
    }

    #[test]
    fn a_wrong_passphrase_is_refused() {
        for pem in [
            fixture!("aes256-sha256.pem"),
            fixture!("rsa-aes256-sha384.pem"),
        ] {
            assert!(matches!(
                EncryptedKey(pem).decrypt(b"wrong-horse"),
                Err(EncryptedKeyError::Decrypt)
            ));
        }
    }

    #[test]
    fn schemes_other_than_pbes2_with_pbkdf2_and_aes_are_unsupported() {
        for (pem, what) in [
            (fixture!("scrypt.pem"), "key derivation"),
            (fixture!("pbes1.pem"), "scheme"),
            (fixture!("sha224.pem"), "PRF"),
        ] {
            let err = EncryptedKey(pem).decrypt(PASSPHRASE).unwrap_err();
            assert!(
                matches!(err, EncryptedKeyError::Unsupported(ref reason) if reason.starts_with(what)),
                "{err}"
            );
        }
    }

    #[test]
    fn an_unencrypted_key_is_not_mistaken_for_an_encrypted_one() {
        let plain = rcgen::KeyPair::generate().unwrap().serialize_pem();
        assert!(EncryptedKey(&plain).decrypt(PASSPHRASE).is_err());
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        let pem = fixture!("aes256-sha256.pem");
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = BASE64.decode(body).unwrap();
        for cut in [0, 1, 10, 50, der.len() - 1] {
            let truncated = encrypted_pem(der.split_at_checked(cut).unwrap().0);
            assert!(
                EncryptedKey(&truncated).decrypt(PASSPHRASE).is_err(),
                "cut at {cut}"
            );
        }
        let not_base64 = encrypted_pem(b"").replace("\n\n", "\n!!!\n");
        let unterminated = encrypted_pem(b"\0\0\0")
            .lines()
            .take(2)
            .collect::<Vec<_>>()
            .join("\n");
        let unlabeled = encrypted_pem(&der).replace(LABELS.first().unwrap(), "CERTIFICATE");
        for pem in [
            "",
            not_base64.as_str(),
            unterminated.as_str(),
            unlabeled.as_str(),
        ] {
            assert!(
                matches!(
                    EncryptedKey(pem).decrypt(PASSPHRASE),
                    Err(EncryptedKeyError::Pem)
                ),
                "{pem}"
            );
        }
        let acm_label =
            encrypted_pem(&der).replace(LABELS.first().unwrap(), LABELS.get(1).unwrap());
        assert!(EncryptedKey(&acm_label).decrypt(PASSPHRASE).is_ok());
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..400)) {
            drop(EncryptedKey(&encrypted_pem(&bytes)).decrypt(PASSPHRASE));
        }
    }
}
