//! Fuzz target: NonceManager uniqueness under random call sequences.
//!
//! Drives `NonceManager::next()` a fuzzer-controlled number of times
//! and asserts that no duplicate nonces are produced. The fuzzer input
//! determines how many nonces to generate (bounded to prevent OOM).

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use stegosafe_crypto::EntropyOracle;
use stegosafe_crypto::nonce::NonceManager;

/// Maximum number of nonces to generate per fuzz iteration.
/// Bounded to prevent excessive memory/time usage.
const MAX_ITERATIONS: usize = 10_000;

fuzz_target!(|data: &[u8]| {
    // Use the fuzzer input to determine how many nonces to generate.
    // If input is empty, default to 1.
    let count = if data.is_empty() {
        1
    } else {
        // Interpret first 2 bytes as u16, then clamp to MAX_ITERATIONS.
        let raw = if data.len() >= 2 {
            u16::from_le_bytes([data[0], data[1]]) as usize
        } else {
            data[0] as usize
        };
        raw.min(MAX_ITERATIONS).max(1)
    };

    // Initialise entropy oracle.
    let entropy = match EntropyOracle::init() {
        Ok(e) => e,
        Err(_) => return,
    };

    // Create a NonceManager.
    let mut mgr = match NonceManager::new(&entropy) {
        Ok(m) => m,
        Err(_) => return,
    };

    // Generate `count` nonces and verify no duplicates.
    let mut seen = HashSet::with_capacity(count);

    for i in 0..count {
        match mgr.next() {
            Ok(nonce) => {
                assert!(
                    seen.insert(nonce),
                    "Duplicate nonce detected at iteration {}! nonce={:?}",
                    i,
                    nonce,
                );
            }
            Err(_) => {
                // KeyExhausted is acceptable — stop generating.
                break;
            }
        }
    }

    // Verify the counter matches the number of nonces generated.
    assert_eq!(
        mgr.counter() as usize,
        seen.len(),
        "Counter mismatch: counter={}, seen={}",
        mgr.counter(),
        seen.len(),
    );
});
