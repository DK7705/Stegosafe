//! Fuzz target: derive_session_keys with random inputs.
//!
//! Feeds arbitrary shared secrets and session nonces into the KDF and
//! verifies that the function never panics. Errors are expected for
//! invalid inputs (empty secret, all-zero nonce) but panics are bugs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use stegosafe_crypto::{EntropyOracle, derive_session_keys};

fuzz_target!(|data: &[u8]| {
    // We need at least 12 bytes for the session nonce, plus at least 1 byte
    // for the shared secret.
    if data.len() < 13 {
        return;
    }

    // Split fuzzer input: first 12 bytes → session_nonce, rest → shared_secret.
    let (nonce_bytes, shared_secret) = data.split_at(12);
    let session_nonce: [u8; 12] = nonce_bytes.try_into().unwrap();

    // Initialise entropy oracle.
    let entropy = match EntropyOracle::init() {
        Ok(e) => e,
        Err(_) => return,
    };

    // Call derive_session_keys — must not panic regardless of input.
    // Errors are fine (e.g., empty secret, all-zero nonce).
    let result = derive_session_keys(shared_secret, &session_nonce, &entropy);

    // If derivation succeeded, verify the keys are usable (no panic on use).
    if let Ok(keys) = result {
        // Try encrypting with the derived key — should not panic.
        let _ = keys.enc_key.encrypt(b"fuzz-test", b"fuzz-aad");

        // Try signing with the MAC key — should not panic.
        let _ = keys.mac_key.sign(b"fuzz-data");
    }
});
