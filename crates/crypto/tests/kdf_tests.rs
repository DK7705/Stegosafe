//! Integration tests for SessionKeys, derive_session_keys, and HKDF.
//!
//! Tests are divided into two sections:
//! 1. **RFC 5869 HKDF-SHA-256 vector tests** — validate the raw HKDF implementation
//!    against Appendix A test vectors using the `hkdf` crate directly.
//! 2. **Public API tests** — validate derive_session_keys produces correct,
//!    deterministic, domain-separated keys.

use std::fs;

use hkdf::Hkdf;
use serde::Deserialize;
use sha2::Sha256;
use stegosafe_crypto::{
    derive_session_keys, CryptoError, EntropyOracle, HmacKey,
};

// ---------------------------------------------------------------------------
// Test vector schema
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct HkdfVector {
    description: String,
    hash: String,
    ikm: String,
    salt: String,
    info: String,
    L: usize,
    prk: String,
    okm: String,
}

fn load_hkdf_vectors() -> Vec<HkdfVector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/hkdf.json");
    let data = fs::read_to_string(path).expect("failed to read hkdf.json");
    serde_json::from_str(&data).expect("failed to parse hkdf.json")
}

// ---------------------------------------------------------------------------
// RFC 5869 HKDF-SHA-256 vector tests
// ---------------------------------------------------------------------------

#[test]
fn rfc5869_hkdf_sha256_extract() {
    let vectors = load_hkdf_vectors();
    for (i, v) in vectors.iter().enumerate() {
        assert_eq!(v.hash, "SHA-256", "vector {i}: only SHA-256 supported");

        let ikm = hex::decode(&v.ikm).expect("hex ikm");
        let salt_bytes = hex::decode(&v.salt).expect("hex salt");
        let expected_prk = hex::decode(&v.prk).expect("hex prk");

        let salt = if salt_bytes.is_empty() {
            None
        } else {
            Some(salt_bytes.as_slice())
        };

        let hk = Hkdf::<Sha256>::new(salt, &ikm);

        // Extract the PRK by using the internal representation
        // We verify the PRK by doing expand and checking OKM
        let info = hex::decode(&v.info).expect("hex info");
        let expected_okm = hex::decode(&v.okm).expect("hex okm");

        let mut okm = vec![0u8; v.L];
        hk.expand(&info, &mut okm)
            .unwrap_or_else(|_| panic!("vector {i}: HKDF expand failed — {}", v.description));

        assert_eq!(
            okm, expected_okm,
            "vector {i} OKM mismatch: {}",
            v.description
        );

        // Also verify PRK via extract
        let (prk, _) = Hkdf::<Sha256>::extract(salt, &ikm);
        assert_eq!(
            prk.as_slice(),
            &expected_prk[..],
            "vector {i} PRK mismatch: {}",
            v.description
        );
    }
}

#[test]
fn rfc5869_hkdf_sha256_expand() {
    let vectors = load_hkdf_vectors();
    for (i, v) in vectors.iter().enumerate() {
        let ikm = hex::decode(&v.ikm).expect("hex ikm");
        let salt_bytes = hex::decode(&v.salt).expect("hex salt");
        let info = hex::decode(&v.info).expect("hex info");
        let expected_okm = hex::decode(&v.okm).expect("hex okm");

        let salt = if salt_bytes.is_empty() {
            None
        } else {
            Some(salt_bytes.as_slice())
        };

        let hk = Hkdf::<Sha256>::new(salt, &ikm);
        let mut okm = vec![0u8; v.L];

        hk.expand(&info, &mut okm)
            .unwrap_or_else(|_| panic!("vector {i}: expand failed — {}", v.description));

        assert_eq!(
            okm, expected_okm,
            "vector {i} OKM mismatch: {}",
            v.description
        );
    }
}

// ---------------------------------------------------------------------------
// Public API: derive_session_keys
// ---------------------------------------------------------------------------

fn test_oracle() -> EntropyOracle {
    EntropyOracle::init().expect("entropy oracle should initialize")
}

#[test]
fn derive_produces_working_encryption_key() {
    let oracle = test_oracle();
    let secret = b"integration-test-shared-secret";
    let nonce = [0x01u8; 12];

    let keys = derive_session_keys(secret, &nonce, &oracle).expect("derivation");

    let msg = b"test payload for encryption";
    let aad = b"session-context";

    let ct = keys.enc_key.encrypt(msg, aad).expect("encrypt");
    let pt = keys.enc_key.decrypt(&ct, aad).expect("decrypt");
    assert_eq!(&pt, msg);
}

#[test]
fn derive_produces_working_mac_key() {
    let oracle = test_oracle();
    let secret = b"mac-test-secret";
    let nonce = [0x02u8; 12];

    let keys = derive_session_keys(secret, &nonce, &oracle).expect("derivation");

    let data = b"data to authenticate";
    let tag = keys.mac_key.sign(data).expect("sign");
    keys.mac_key.verify(data, &tag).expect("verify should succeed");
}

#[test]
fn derive_deterministic_mac_key() {
    let oracle = test_oracle();
    let secret = b"deterministic-test";
    let nonce = [0x03u8; 12];

    let keys1 = derive_session_keys(secret, &nonce, &oracle).expect("derive 1");
    let keys2 = derive_session_keys(secret, &nonce, &oracle).expect("derive 2");

    // Same inputs → same MAC keys → same tags
    let data = b"check determinism";
    let tag1 = keys1.mac_key.sign(data).expect("sign 1");
    let tag2 = keys2.mac_key.sign(data).expect("sign 2");
    assert_eq!(tag1, tag2, "MAC tags should be identical for same inputs");
}

#[test]
fn derive_deterministic_seeds() {
    let oracle = test_oracle();
    let secret = b"seed-determinism-test";
    let nonce = [0x04u8; 12];

    let keys1 = derive_session_keys(secret, &nonce, &oracle).expect("derive 1");
    let keys2 = derive_session_keys(secret, &nonce, &oracle).expect("derive 2");

    assert_eq!(
        *keys1.technique_seed, *keys2.technique_seed,
        "technique seeds should match"
    );
    assert_eq!(
        *keys1.param_seed, *keys2.param_seed,
        "param seeds should match"
    );
}

#[test]
fn derive_different_secret_different_keys() {
    let oracle = test_oracle();
    let nonce = [0x05u8; 12];

    let keys_a = derive_session_keys(b"secret-alpha", &nonce, &oracle).expect("derive A");
    let keys_b = derive_session_keys(b"secret-beta", &nonce, &oracle).expect("derive B");

    let tag_a = keys_a.mac_key.sign(b"x").expect("sign A");
    let tag_b = keys_b.mac_key.sign(b"x").expect("sign B");
    assert_ne!(tag_a, tag_b, "different secrets must produce different keys");

    assert_ne!(
        *keys_a.technique_seed, *keys_b.technique_seed,
        "technique seeds should differ"
    );
}

#[test]
fn derive_different_nonce_different_keys() {
    let oracle = test_oracle();
    let secret = b"same-secret";

    let keys1 = derive_session_keys(secret, &[0x10; 12], &oracle).expect("derive 1");
    let keys2 = derive_session_keys(secret, &[0x20; 12], &oracle).expect("derive 2");

    let tag1 = keys1.mac_key.sign(b"data").expect("sign 1");
    let tag2 = keys2.mac_key.sign(b"data").expect("sign 2");
    assert_ne!(tag1, tag2, "different nonces must produce different keys");
}

#[test]
fn derive_domain_separation() {
    let oracle = test_oracle();
    let secret = b"domain-separation-test";
    let nonce = [0x06u8; 12];

    let keys = derive_session_keys(secret, &nonce, &oracle).expect("derivation");

    // All derived values should be cryptographically independent
    let mac_tag = keys.mac_key.sign(b"").expect("empty sign");
    assert_ne!(
        &mac_tag[..], &*keys.technique_seed,
        "MAC key and technique seed should differ"
    );
    assert_ne!(
        &mac_tag[..], &*keys.param_seed,
        "MAC key and param seed should differ"
    );
    assert_ne!(
        &*keys.technique_seed, &*keys.param_seed,
        "technique and param seeds should differ"
    );
}

#[test]
fn derive_seeds_are_nonzero() {
    let oracle = test_oracle();
    let secret = b"nonzero-check";
    let nonce = [0x07u8; 12];

    let keys = derive_session_keys(secret, &nonce, &oracle).expect("derivation");

    assert!(
        keys.technique_seed.iter().any(|&b| b != 0),
        "technique seed should not be all zeros"
    );
    assert!(
        keys.param_seed.iter().any(|&b| b != 0),
        "param seed should not be all zeros"
    );
}

#[test]
fn derive_empty_secret_rejected() {
    let oracle = test_oracle();
    let result = derive_session_keys(b"", &[0x08; 12], &oracle);
    assert!(result.is_err());
    match result {
        Err(CryptoError::InvalidInput(msg)) => {
            assert!(msg.contains("empty"), "unexpected error message: {msg}");
        }
        other => panic!("expected InvalidInput, got {:?}", other),
    }
}

#[test]
fn derive_zero_nonce_rejected() {
    let oracle = test_oracle();
    let result = derive_session_keys(b"secret", &[0x00; 12], &oracle);
    assert!(result.is_err());
    match result {
        Err(CryptoError::InvalidInput(msg)) => {
            assert!(msg.contains("zero"), "unexpected error message: {msg}");
        }
        other => panic!("expected InvalidInput, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// HmacKey standalone tests
// ---------------------------------------------------------------------------

#[test]
fn hmac_sign_verify_round_trip() {
    let key = HmacKey::from_bytes([0xAB; 32]);
    let data = b"integration test data";
    let tag = key.sign(data).expect("sign");
    key.verify(data, &tag).expect("verify should succeed");
}

#[test]
fn hmac_wrong_data_fails() {
    let key = HmacKey::from_bytes([0xCD; 32]);
    let tag = key.sign(b"original").expect("sign");
    let result = key.verify(b"tampered", &tag);
    assert!(result.is_err());
}

#[test]
fn hmac_wrong_tag_fails() {
    let key = HmacKey::from_bytes([0xEF; 32]);
    let data = b"test data";
    let mut tag = key.sign(data).expect("sign");
    tag[0] ^= 0xFF; // corrupt first byte
    let result = key.verify(data, &tag);
    assert!(result.is_err());
}

#[test]
fn hmac_different_keys_different_tags() {
    let key1 = HmacKey::from_bytes([0x11; 32]);
    let key2 = HmacKey::from_bytes([0x22; 32]);
    let data = b"same data for both keys";

    let tag1 = key1.sign(data).expect("sign 1");
    let tag2 = key2.sign(data).expect("sign 2");
    assert_ne!(tag1, tag2);
}

#[test]
fn hmac_empty_data() {
    let key = HmacKey::from_bytes([0x33; 32]);
    let tag = key.sign(b"").expect("sign empty");
    key.verify(b"", &tag).expect("verify empty");
    assert_eq!(tag.len(), 32);
}

#[test]
fn hmac_deterministic() {
    let key = HmacKey::from_bytes([0x44; 32]);
    let data = b"determinism check";
    let tag1 = key.sign(data).expect("sign 1");
    let tag2 = key.sign(data).expect("sign 2");
    assert_eq!(tag1, tag2, "HMAC must be deterministic");
}
