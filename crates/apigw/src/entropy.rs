//! Random numbers from the process's crypto provider (aws-lc-rs).

/// Source of random bytes. Every method is `None` when the provider cannot
/// produce randomness, so callers decide how to fail (traffic goes to the
/// production release, a request is left untraced).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Entropy;

impl Entropy {
    pub(crate) fn bytes<const N: usize>() -> Option<[u8; N]> {
        let mut bytes = [0_u8; N];
        rustls::crypto::aws_lc_rs::default_provider()
            .secure_random
            .fill(&mut bytes)
            .ok()?;
        Some(bytes)
    }

    pub(crate) fn u64() -> Option<u64> {
        Self::bytes().map(u64::from_be_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_filled_and_differ_between_calls() {
        let first = Entropy::bytes::<32>();
        let second = Entropy::bytes::<32>();
        assert!(first.is_some());
        assert_ne!(first, second);
        assert_eq!(Entropy::bytes::<0>(), Some([]));
        assert!(Entropy::u64().is_some());
    }
}
