//! Integration tests for AeadKey (AES-256-GCM with compression).
//!
//! Tests are divided into two sections:
//! 1. **NIST CAVP vector tests** — validate raw AES-256-GCM against NIST SP 800-38D
//!    test vectors, using the `aes-gcm` crate directly (because AeadKey compresses
//!    internally, so raw vectors can't round-trip through the public API).
//! 2. **Public API round-trip tests** — validate AeadKey::encrypt/decrypt works
//!    end-to-end (compress → encrypt → decrypt → decompress).

use std::fs;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use serde::Deserialize;
use stegosafe_crypto::{AeadKey, CryptoError, EntropyOracle};

// ---------------------------------------------------------------------------
// Test vector schema
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AesGcmVector {
    description: String,
    key: String,
    iv: String,
    aad: String,
    plaintext: String,
    ciphertext: String,
    tag: String,
    should_fail: bool,
}

fn load_aes_gcm_vectors() -> Vec<AesGcmVector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/aes_gcm.json");
    let data = fs::read_to_string(path).expect("failed to read aes_gcm.json");
    serde_json::from_str(&data).expect("failed to parse aes_gcm.json")
}

// ---------------------------------------------------------------------------
// NIST CAVP AES-256-GCM vector tests (raw crypto, no compression)
// ---------------------------------------------------------------------------

#[test]
fn nist_aes256_gcm_encrypt_vectors() {
    let vectors = load_aes_gcm_vectors();
    for (i, v) in vectors.iter().enumerate() {
        if v.should_fail {
            continue; // Skip failure vectors for encryption test
        }

        let key_bytes = hex::decode(&v.key).expect("hex key");
        let iv_bytes = hex::decode(&v.iv).expect("hex iv");
        let aad_bytes = hex::decode(&v.aad).expect("hex aad");
        let pt_bytes = hex::decode(&v.plaintext).expect("hex plaintext");
        let expected_ct = hex::decode(&v.ciphertext).expect("hex ciphertext");
        let expected_tag = hex::decode(&v.tag).expect("hex tag");

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .unwrap_or_else(|_| panic!("vector {i}: invalid key length"));

        let nonce = Nonce::from_slice(&iv_bytes);
        let payload = Payload {
            msg: &pt_bytes,
            aad: &aad_bytes,
        };

        let result = cipher.encrypt(nonce, payload)
            .unwrap_or_else(|_| panic!("vector {i}: encryption failed — {}", v.description));

        // aes-gcm returns ciphertext ‖ tag
        let (ct_part, tag_part) = result.split_at(result.len() - 16);

        assert_eq!(
            ct_part, &expected_ct[..],
            "vector {i} ciphertext mismatch: {}",
            v.description
        );
        assert_eq!(
            tag_part, &expected_tag[..],
            "vector {i} tag mismatch: {}",
            v.description
        );
    }
}

#[test]
fn nist_aes256_gcm_decrypt_vectors() {
    let vectors = load_aes_gcm_vectors();
    for (i, v) in vectors.iter().enumerate() {
        let key_bytes = hex::decode(&v.key).expect("hex key");
        let iv_bytes = hex::decode(&v.iv).expect("hex iv");
        let aad_bytes = hex::decode(&v.aad).expect("hex aad");
        let ct_bytes = hex::decode(&v.ciphertext).expect("hex ciphertext");
        let tag_bytes = hex::decode(&v.tag).expect("hex tag");

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .unwrap_or_else(|_| panic!("vector {i}: invalid key length"));

        let nonce = Nonce::from_slice(&iv_bytes);

        // Construct ciphertext ‖ tag for decryption
        let mut ct_and_tag = Vec::with_capacity(ct_bytes.len() + tag_bytes.len());
        ct_and_tag.extend_from_slice(&ct_bytes);
        ct_and_tag.extend_from_slice(&tag_bytes);

        let payload = Payload {
            msg: &ct_and_tag,
            aad: &aad_bytes,
        };

        let result = cipher.decrypt(nonce, payload);

        if v.should_fail {
            assert!(
                result.is_err(),
                "vector {i} should have failed but succeeded: {}",
                v.description
            );
        } else {
            let pt_bytes = hex::decode(&v.plaintext).expect("hex plaintext");
            let decrypted = result
                .unwrap_or_else(|_| panic!("vector {i}: decryption failed — {}", v.description));
            assert_eq!(
                decrypted, pt_bytes,
                "vector {i} plaintext mismatch: {}",
                v.description
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Public API round-trip tests (AeadKey with compression)
// ---------------------------------------------------------------------------

fn test_oracle() -> EntropyOracle {
    EntropyOracle::init().expect("entropy oracle should initialize")
}

#[test]
fn aead_round_trip_empty() {
    let oracle = test_oracle();
    let key = AeadKey::new([0x42; 32], &oracle).expect("key creation");
    let aad = b"integration-test-session";

    let ct = key.encrypt(b"", aad).expect("encrypt empty");
    let pt = key.decrypt(&ct, aad).expect("decrypt empty");
    assert_eq!(pt, b"");
}

#[test]
fn aead_round_trip_hello_world() {
    let oracle = test_oracle();
    let key = AeadKey::new([0xAA; 32], &oracle).expect("key creation");
    let aad = b"session-hello";
    let msg = b"Hello, World!";

    let ct = key.encrypt(msg, aad).expect("encrypt");
    let pt = key.decrypt(&ct, aad).expect("decrypt");
    assert_eq!(&pt, msg);
}

#[test]
fn aead_round_trip_large_payload() {
    let oracle = test_oracle();
    let key = AeadKey::new([0xBB; 32], &oracle).expect("key creation");
    let aad = b"session-large";
    let msg = vec![0xCD; 100_000]; // 100 KB payload

    let ct = key.encrypt(&msg, aad).expect("encrypt large");
    let pt = key.decrypt(&ct, aad).expect("decrypt large");
    assert_eq!(pt, msg);
}

#[test]
fn aead_ciphertext_minimum_length() {
    let oracle = test_oracle();
    let key = AeadKey::new([0x11; 32], &oracle).expect("key creation");
    let ct = key.encrypt(b"x", b"aad").expect("encrypt");
    // Must be at least 28 bytes: 12-byte nonce + 16-byte tag
    assert!(ct.len() >= 28, "ciphertext too short: {} bytes", ct.len());
}

#[test]
fn aead_nonce_uniqueness() {
    let oracle = test_oracle();
    let key = AeadKey::new([0x22; 32], &oracle).expect("key creation");
    let aad = b"nonce-test";
    let msg = b"same plaintext";

    let ct1 = key.encrypt(msg, aad).expect("encrypt 1");
    let ct2 = key.encrypt(msg, aad).expect("encrypt 2");

    // Different nonces → different ciphertexts
    assert_ne!(ct1, ct2);
    // First 12 bytes are the nonce — should differ
    assert_ne!(&ct1[..12], &ct2[..12]);
}

#[test]
fn aead_wrong_aad_decryption_fails() {
    let oracle = test_oracle();
    let key = AeadKey::new([0x33; 32], &oracle).expect("key creation");

    let ct = key.encrypt(b"secret", b"correct-aad").expect("encrypt");
    let result = key.decrypt(&ct, b"wrong-aad");
    assert!(result.is_err());
    match result {
        Err(CryptoError::DecryptionFailed) => {} // expected
        other => panic!("expected DecryptionFailed, got {:?}", other),
    }
}

#[test]
fn aead_corrupted_tag_decryption_fails() {
    let oracle = test_oracle();
    let key = AeadKey::new([0x44; 32], &oracle).expect("key creation");
    let aad = b"tag-test";

    let mut ct = key.encrypt(b"secret", aad).expect("encrypt");
    // Flip last byte (part of GCM tag)
    let last = ct.len() - 1;
    ct[last] ^= 0xFF;

    let result = key.decrypt(&ct, aad);
    assert!(result.is_err());
}

#[test]
fn aead_wrong_key_decryption_fails() {
    let oracle = test_oracle();
    let key1 = AeadKey::new([0x55; 32], &oracle).expect("key1");
    let key2 = AeadKey::new([0x66; 32], &oracle).expect("key2");
    let aad = b"cross-key-test";

    let ct = key1.encrypt(b"secret", aad).expect("encrypt with key1");
    let result = key2.decrypt(&ct, aad);
    assert!(result.is_err());
}

#[test]
fn aead_too_short_ciphertext_rejected() {
    let oracle = test_oracle();
    let key = AeadKey::new([0x77; 32], &oracle).expect("key creation");

    // Less than 28 bytes → InvalidInput
    let result = key.decrypt(&[0u8; 27], b"test");
    assert!(result.is_err());
    match result {
        Err(CryptoError::InvalidInput(msg)) => {
            assert!(msg.contains("too short"), "unexpected message: {msg}");
        }
        other => panic!("expected InvalidInput, got {:?}", other),
    }
}

#[test]
fn aead_compression_reduces_repetitive_data() {
    let oracle = test_oracle();
    let key = AeadKey::new([0x88; 32], &oracle).expect("key creation");
    let aad = b"compress-test";

    // 8 KB of highly compressible data
    let msg = vec![b'Z'; 8192];
    let ct = key.encrypt(&msg, aad).expect("encrypt");

    // Compressed + encrypted should be much smaller than the original
    assert!(
        ct.len() < msg.len(),
        "expected compression: ct={} bytes, pt={} bytes",
        ct.len(),
        msg.len()
    );
}

#[test]
fn aead_empty_aad_round_trip() {
    let oracle = test_oracle();
    let key = AeadKey::new([0x99; 32], &oracle).expect("key creation");

    let msg = b"message with empty AAD";
    let ct = key.encrypt(msg, b"").expect("encrypt");
    let pt = key.decrypt(&ct, b"").expect("decrypt");
    assert_eq!(&pt, msg);
}
