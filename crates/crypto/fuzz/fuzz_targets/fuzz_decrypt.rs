//! Fuzz target: AeadKey::decrypt with random ciphertext.
//!
//! Feeds arbitrary byte sequences into `AeadKey::decrypt` and verifies
//! that the function never panics and always returns `Err` (since random
//! bytes are not valid AES-256-GCM ciphertext).

#![no_main]

use libfuzzer_sys::fuzz_target;
use stegosafe_crypto::{AeadKey, EntropyOracle};

fuzz_target!(|data: &[u8]| {
    // Initialise entropy oracle (one-time, but libfuzzer may call us many times).
    // If entropy is unavailable, we can't construct a key — just bail.
    let entropy = match EntropyOracle::init() {
        Ok(e) => e,
        Err(_) => return,
    };

    // Construct a deterministic key (the key value doesn't matter for this test).
    let key = match AeadKey::new([0x42; 32], &entropy) {
        Ok(k) => k,
        Err(_) => return,
    };

    // Feed random data as ciphertext. AAD is fixed — we're fuzzing the
    // ciphertext parser, not the AAD handling.
    let result = key.decrypt(data, b"fuzz-aad");

    // The result MUST be Err — random bytes should never decrypt successfully.
    // If it somehow returns Ok, that's a critical bug.
    assert!(
        result.is_err(),
        "decrypt returned Ok on random input! len={}, data={:?}",
        data.len(),
        &data[..data.len().min(64)],
    );
});
