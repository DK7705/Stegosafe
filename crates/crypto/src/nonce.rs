//! Nonce management with structural uniqueness guarantees.
//!
//! Nonce reuse under the same key with AES-GCM is catastrophic — it breaks
//! both confidentiality and authentication. This module makes reuse
//! structurally impossible via a random-base + counter hybrid scheme.
//!
//! # Nonce structure (96 bits)
//!
//! ```text
//! ┌──────────────────────────┬────────────────┐
//! │   Random base (64 bits)  │ Counter (32 b) │
//! └──────────────────────────┴────────────────┘
//!  Bytes 0..8                 Bytes 8..12
//! ```
//!
//! - The 64-bit random base is drawn from [`EntropyOracle`] at construction
//!   and remains fixed for the lifetime of the manager.
//! - The 32-bit counter increments on each call to [`NonceManager::next`].
//! - At `u32::MAX` (4 billion encryptions), the key is considered exhausted
//!   and [`CryptoError::KeyExhausted`] is returned.
//!
//! # Non-cloneable
//!
//! `NonceManager` is deliberately not `Clone` or `Copy`. It cannot be
//! accidentally shared across threads without an explicit `Arc<Mutex<>>`.

use zeroize::Zeroize;

use crate::entropy::EntropyOracle;
use crate::error::CryptoError;

/// Nonce manager bound to one [`AeadKey`](crate::aead::AeadKey) instance.
///
/// Produces unique 96-bit nonces using a random base + counter hybrid.
/// Not `Clone` or `Copy` — must be explicitly wrapped in synchronization
/// primitives if shared.
#[derive(Debug)]
pub struct NonceManager {
    /// 64-bit random base (high 8 bytes of each nonce).
    base: [u8; 8],
    /// 32-bit monotonic counter (low 4 bytes of each nonce).
    counter: u32,
}

impl NonceManager {
    /// Create a new nonce manager, drawing a random base from the entropy oracle.
    pub fn new(entropy: &EntropyOracle) -> Result<Self, CryptoError> {
        let mut base = [0u8; 8];
        entropy.fill(&mut base)?;
        Ok(Self { base, counter: 0 })
    }

    /// Generate the next unique 96-bit nonce.
    ///
    /// Returns [`CryptoError::KeyExhausted`] if the counter has reached
    /// `u32::MAX`, meaning the key must be rekeyed.
    pub fn next(&mut self) -> Result<[u8; 12], CryptoError> {
        if self.counter == u32::MAX {
            return Err(CryptoError::KeyExhausted);
        }

        let mut nonce = [0u8; 12];

        // High 8 bytes: random base (session-unique)
        nonce[..8].copy_from_slice(&self.base);

        // Low 4 bytes: counter (monotonically increasing)
        nonce[8..12].copy_from_slice(&self.counter.to_be_bytes());

        self.counter += 1;

        Ok(nonce)
    }

    /// Return the current counter value (for diagnostics/testing).
    pub fn counter(&self) -> u32 {
        self.counter
    }
}

impl Drop for NonceManager {
    fn drop(&mut self) {
        self.base.zeroize();
        self.counter = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_oracle() -> EntropyOracle {
        EntropyOracle::init().expect("entropy oracle should initialize")
    }

    #[test]
    fn nonce_is_12_bytes() {
        let oracle = test_oracle();
        let mut mgr = NonceManager::new(&oracle).expect("nonce manager init");
        let nonce = mgr.next().expect("first nonce");
        assert_eq!(nonce.len(), 12);
    }

    #[test]
    fn counter_increments() {
        let oracle = test_oracle();
        let mut mgr = NonceManager::new(&oracle).expect("nonce manager init");
        assert_eq!(mgr.counter(), 0);

        let _ = mgr.next().expect("nonce");
        assert_eq!(mgr.counter(), 1);

        let _ = mgr.next().expect("nonce");
        assert_eq!(mgr.counter(), 2);
    }

    #[test]
    fn sequential_nonces_differ() {
        let oracle = test_oracle();
        let mut mgr = NonceManager::new(&oracle).expect("nonce manager init");

        let n1 = mgr.next().expect("nonce 1");
        let n2 = mgr.next().expect("nonce 2");
        assert_ne!(n1, n2);
    }

    #[test]
    fn no_duplicates_over_many_calls() {
        let oracle = test_oracle();
        let mut mgr = NonceManager::new(&oracle).expect("nonce manager init");

        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let nonce = mgr.next().expect("nonce");
            assert!(seen.insert(nonce), "duplicate nonce detected");
        }
    }

    #[test]
    fn two_managers_produce_different_nonces() {
        let oracle = test_oracle();
        let mut mgr1 = NonceManager::new(&oracle).expect("mgr1");
        let mut mgr2 = NonceManager::new(&oracle).expect("mgr2");

        let n1 = mgr1.next().expect("nonce from mgr1");
        let n2 = mgr2.next().expect("nonce from mgr2");
        // Different random bases → different nonces (probability of collision: 2^-64)
        assert_ne!(n1, n2);
    }

    #[test]
    fn high_bytes_stay_constant() {
        let oracle = test_oracle();
        let mut mgr = NonceManager::new(&oracle).expect("nonce manager init");

        let n1 = mgr.next().expect("nonce 1");
        let n2 = mgr.next().expect("nonce 2");

        // High 8 bytes (random base) should be identical
        assert_eq!(&n1[..8], &n2[..8]);
        // Low 4 bytes (counter) should differ
        assert_ne!(&n1[8..12], &n2[8..12]);
    }

    #[test]
    fn exhaustion_at_u32_max() {
        let oracle = test_oracle();
        let mut mgr = NonceManager::new(&oracle).expect("nonce manager init");

        // Fast-forward counter to just before exhaustion
        mgr.counter = u32::MAX;

        let result = mgr.next();
        assert!(result.is_err());
        match result {
            Err(CryptoError::KeyExhausted) => {} // expected
            other => panic!("expected KeyExhausted, got {:?}", other),
        }
    }
}
