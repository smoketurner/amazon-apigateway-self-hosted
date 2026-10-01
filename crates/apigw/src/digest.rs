//! SHA-256 digests, for keeping credentials out of cache keys and memory.
//!
//! A digest stands in for a secret wherever the secret itself would only be
//! compared: an authorizer cache key must not hold the caller's token, because
//! the cache may be shared between replicas.

use std::fmt;

use aws_lc_rs::digest::{Context, SHA256};

/// The SHA-256 digest of some bytes, written in lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// The digest of the concatenation of `parts`, each preceded by its length
    /// so that no two different lists of parts share a digest.
    pub(crate) fn of_parts<P: AsRef<[u8]>>(parts: &[P]) -> Self {
        let mut context = Context::new(&SHA256);
        for part in parts {
            let part = part.as_ref();
            context.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
            context.update(part);
        }
        let mut digest = [0_u8; 32];
        let finished = context.finish();
        for (slot, byte) in digest.iter_mut().zip(finished.as_ref()) {
            *slot = *byte;
        }
        Self(digest)
    }
}

impl Sha256Digest {
    /// The digest written by [`Display`](fmt::Display), or `None` for any other
    /// text.
    pub(crate) fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut digest = [0_u8; 32];
        let (pairs, _) = text.as_bytes().as_chunks::<2>();
        for (slot, pair) in digest.iter_mut().zip(pairs) {
            let pair = std::str::from_utf8(pair).ok()?;
            *slot = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(digest))
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn no_parts_hash_as_the_empty_message() {
        let empty = Sha256Digest::of_parts::<&[u8]>(&[]);
        assert_eq!(
            empty.to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hex_round_trips_and_rejects_anything_else() {
        let digest = Sha256Digest::of_parts(&["token"]);
        assert_eq!(Sha256Digest::from_hex(&digest.to_string()), Some(digest));
        let text = Sha256Digest::of_parts(&["x"]).to_string();
        assert!(
            Sha256Digest::from_hex(&text.to_uppercase()).is_some(),
            "case is not significant"
        );
        let short: String = text.chars().take(63).collect();
        let tail: String = text.chars().skip(1).collect();
        for bad in [
            String::new(),
            "abc".to_owned(),
            short,
            format!("{text}0"),
            format!("g{tail}"),
            "\u{e9}".repeat(32),
            format!("+{tail}"),
        ] {
            assert_eq!(Sha256Digest::from_hex(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn digests_are_64_lowercase_hex_characters() {
        let text = Sha256Digest::of_parts(&["token"]).to_string();
        assert_eq!(text.len(), 64);
        assert!(
            text.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn splitting_the_parts_differently_changes_the_digest() {
        assert_ne!(
            Sha256Digest::of_parts(&["ab", "c"]),
            Sha256Digest::of_parts(&["a", "bc"])
        );
        assert_ne!(
            Sha256Digest::of_parts(&["a", ""]),
            Sha256Digest::of_parts(&["a"])
        );
    }

    proptest! {
        #[test]
        fn equal_parts_give_equal_digests_and_different_parts_differ(
            a in proptest::collection::vec("[a-z]{0,6}", 0..4),
            b in proptest::collection::vec("[a-z]{0,6}", 0..4),
        ) {
            prop_assert_eq!(Sha256Digest::of_parts(&a) == Sha256Digest::of_parts(&b), a == b);
        }
    }
}
