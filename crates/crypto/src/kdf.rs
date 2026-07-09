//! HKDF-SHA-256 key derivation and HMAC-SHA-256 message authentication.
//!
//! Derives domain-separated, cryptographically independent keys from a
//! shared secret using HKDF (RFC 5869). Each derived key has a unique
//! `info` string so changing any one produces an entirely different key.
//!
//! # Derived keys
//!
//! | Key                 | Info string            | Purpose                         |
//! |---------------------|------------------------|---------------------------------|
//! | `session_enc_key`   | `stego-v1-enc`         | AES-256-GCM payload encryption  |
//! | `session_mac_key`   | `stego-v1-mac`         | Cover image HMAC-SHA-256        |
//! | `technique_seed`    | `stego-v1-technique`   | Phase 3 technique selection RNG |
//! | `param_seed`        | `stego-v1-params`      | Phase 3 parameter randomisation |

use hkdf::Hkdf;
use hmac::Hmac;
use hmac::digest::KeyInit;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::aead::AeadKey;
use crate::entropy::EntropyOracle;
use crate::error::CryptoError;

/// HMAC-SHA-256 type alias.
type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Domain separation info strings (must never change once deployed)
// ---------------------------------------------------------------------------

const INFO_ENC: &[u8] = b"stego-v1-enc";
const INFO_MAC: &[u8] = b"stego-v1-mac";
const INFO_TECHNIQUE: &[u8] = b"stego-v1-technique";
const INFO_PARAMS: &[u8] = b"stego-v1-params";

// ---------------------------------------------------------------------------
// HmacKey
// ---------------------------------------------------------------------------

/// HMAC-SHA-256 key with secure memory clearing on drop.
///
/// Provides `sign` and `verify` operations. The underlying key material
/// is wrapped in [`Zeroizing`] and cleared when the key is dropped.
#[derive(Debug)]
pub struct HmacKey {
    key: Zeroizing<[u8; 32]>,
}

impl HmacKey {
    /// Construct from raw 32-byte key material.
    ///
    /// The bytes are moved into a `Zeroizing` wrapper.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(bytes),
        }
    }

    /// Compute HMAC-SHA-256 tag over `data`.
    pub fn sign(&self, data: &[u8]) -> Result<[u8; 32], CryptoError> {
        let mut mac = HmacSha256::new_from_slice(&*self.key)
            .map_err(|_| CryptoError::InvalidInput("invalid HMAC key length"))?;
        hmac::Mac::update(&mut mac, data);
        let result = hmac::Mac::finalize(mac);
        let mut output = [0u8; 32];
        output.copy_from_slice(&result.into_bytes());
        Ok(output)
    }

    /// Verify HMAC-SHA-256 tag over `data` in constant time.
    ///
    /// Returns `Ok(())` if the tag is valid, or
    /// [`CryptoError::DecryptionFailed`] if verification fails.
    pub fn verify(&self, data: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        let mut mac = HmacSha256::new_from_slice(&*self.key)
            .map_err(|_| CryptoError::InvalidInput("invalid HMAC key length"))?;
        hmac::Mac::update(&mut mac, data);
        hmac::Mac::verify_slice(mac, tag)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    /// Returns a reference to the underlying key bytes.
    ///
    /// Used by the CLI to pass placement key material to the
    /// steganography engine for backward-compatible extraction.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

// ---------------------------------------------------------------------------
// SessionKeys
// ---------------------------------------------------------------------------

/// Bundle of derived session keys produced by [`derive_session_keys`].
///
/// All keys are cryptographically independent — derived from the same
/// Container for all keys derived for a single steganographic session.
#[derive(Debug)]
pub struct SessionKeys {
    /// Encryption key for payload (ChaCha20-Poly1305).
    pub enc_key: AeadKey,
    /// MAC key for metadata authentication.
    pub mac_key: HmacKey,
    /// Seed for determining the embedding technique.
    pub technique_seed: Zeroizing<[u8; 32]>,
    /// Seed for randomising embedding parameters (channels, bit-plane).
    pub param_seed: Zeroizing<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive all session keys from a shared secret using HKDF-SHA-256.
///
/// # Parameters
///
/// - `shared_secret`: Root key material (established out-of-band, e.g., via
///   Phase 5's X3DH exchange). The caller is responsible for zeroizing this
///   after the call returns.
/// - `session_nonce`: 96-bit (12-byte) session-unique value used as the
///   HKDF salt. Must not be all zeros.
/// - `entropy`: Entropy source for initializing the encryption key's nonce
///   manager.
///
/// # Errors
///
/// - [`CryptoError::InvalidInput`] if `shared_secret` is empty or
///   `session_nonce` is all zeros.
/// - [`CryptoError::KdfError`] if HKDF expansion fails.
/// - [`CryptoError::EntropyUnavailable`] if the entropy oracle cannot
///   initialize the nonce manager.
pub fn derive_session_keys(
    shared_secret: &[u8],
    session_nonce: &[u8; 12],
    entropy: &EntropyOracle,
) -> Result<SessionKeys, CryptoError> {
    // Validate inputs
    if shared_secret.is_empty() {
        return Err(CryptoError::InvalidInput("shared secret must not be empty"));
    }
    if session_nonce.iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidInput(
            "session nonce must not be all zeros (use a fresh random nonce)",
        ));
    }

    // HKDF-Extract: salt = session_nonce, IKM = shared_secret
    let hk = Hkdf::<Sha256>::new(Some(session_nonce), shared_secret);

    // Derive encryption key (32 bytes)
    let mut enc_key_bytes = [0u8; 32];
    hk.expand(INFO_ENC, &mut enc_key_bytes)
        .map_err(|_| CryptoError::KdfError)?;

    // Derive MAC key (32 bytes)
    let mut mac_key_bytes = [0u8; 32];
    hk.expand(INFO_MAC, &mut mac_key_bytes)
        .map_err(|_| CryptoError::KdfError)?;

    // Derive technique seed (32 bytes)
    let mut technique_bytes = [0u8; 32];
    hk.expand(INFO_TECHNIQUE, &mut technique_bytes)
        .map_err(|_| CryptoError::KdfError)?;

    // Derive param seed (32 bytes)
    let mut param_bytes = [0u8; 32];
    hk.expand(INFO_PARAMS, &mut param_bytes)
        .map_err(|_| CryptoError::KdfError)?;

    // Construct typed keys
    let enc_key = AeadKey::new(enc_key_bytes, entropy)?;
    let mac_key = HmacKey::from_bytes(mac_key_bytes);
    let technique_seed = Zeroizing::new(technique_bytes);
    let param_seed = Zeroizing::new(param_bytes);

    // Zeroize raw byte arrays
    enc_key_bytes.zeroize();
    mac_key_bytes.zeroize();
    technique_bytes.zeroize();
    param_bytes.zeroize();

    Ok(SessionKeys {
        enc_key,
        mac_key,
        technique_seed,
        param_seed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_oracle() -> EntropyOracle {
        EntropyOracle::init().expect("entropy oracle should initialize")
    }

    #[test]
    fn hmac_sign_and_verify() {
        let key = HmacKey::from_bytes([0x42; 32]);
        let data = b"test message";
        let tag = key.sign(data).expect("sign");
        key.verify(data, &tag).expect("verify should succeed");
    }

    #[test]
    fn hmac_wrong_data_fails_verify() {
        let key = HmacKey::from_bytes([0x42; 32]);
        let tag = key.sign(b"message A").expect("sign");
        let result = key.verify(b"message B", &tag);
        assert!(result.is_err());
    }

    #[test]
    fn hmac_wrong_tag_fails_verify() {
        let key = HmacKey::from_bytes([0x42; 32]);
        let data = b"test message";
        let mut tag = key.sign(data).expect("sign");
        tag[0] ^= 0xFF; // corrupt tag
        let result = key.verify(data, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn hmac_different_keys_produce_different_tags() {
        let key1 = HmacKey::from_bytes([0x11; 32]);
        let key2 = HmacKey::from_bytes([0x22; 32]);
        let data = b"same data";
        let tag1 = key1.sign(data).expect("sign1");
        let tag2 = key2.sign(data).expect("sign2");
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn derive_session_keys_produces_valid_keys() {
        let oracle = test_oracle();
        let secret = b"test-shared-secret-32-bytes-long";
        let nonce = [1u8; 12]; // non-zero

        let keys = derive_session_keys(secret, &nonce, &oracle)
            .expect("derivation should succeed");

        // Verify enc_key works
        let ct = keys.enc_key.encrypt(b"hello", b"aad").expect("encrypt");
        let pt = keys.enc_key.decrypt(&ct, b"aad").expect("decrypt");
        assert_eq!(pt, b"hello");

        // Verify mac_key works
        let tag = keys.mac_key.sign(b"data").expect("sign");
        keys.mac_key.verify(b"data", &tag).expect("verify");

        // Seeds should not be all zeros
        assert!(keys.technique_seed.iter().any(|&b| b != 0));
        assert!(keys.param_seed.iter().any(|&b| b != 0));
    }

    #[test]
    fn derive_deterministic_with_same_inputs() {
        let oracle = test_oracle();
        let secret = b"deterministic-test-secret";
        let nonce = [0xAA; 12];

        let keys1 = derive_session_keys(secret, &nonce, &oracle)
            .expect("derive 1");
        let keys2 = derive_session_keys(secret, &nonce, &oracle)
            .expect("derive 2");

        // MAC keys should be identical (deterministic derivation)
        let tag1 = keys1.mac_key.sign(b"test").expect("sign1");
        let tag2 = keys2.mac_key.sign(b"test").expect("sign2");
        assert_eq!(tag1, tag2);

        // Seeds should be identical
        assert_eq!(*keys1.technique_seed, *keys2.technique_seed);
        assert_eq!(*keys1.param_seed, *keys2.param_seed);
    }

    #[test]
    fn domain_separation_different_info_different_keys() {
        let oracle = test_oracle();
        let secret = b"test-secret";
        let nonce = [0xBB; 12];

        let keys = derive_session_keys(secret, &nonce, &oracle)
            .expect("derive");

        // All derived values should be distinct
        let mac_tag = keys.mac_key.sign(b"").expect("sign");
        assert_ne!(&mac_tag[..], &*keys.technique_seed);
        assert_ne!(&mac_tag[..], &*keys.param_seed);
        assert_ne!(&*keys.technique_seed, &*keys.param_seed);
    }

    #[test]
    fn different_nonce_different_keys() {
        let oracle = test_oracle();
        let secret = b"test-secret";

        let keys1 = derive_session_keys(secret, &[0x01; 12], &oracle)
            .expect("derive 1");
        let keys2 = derive_session_keys(secret, &[0x02; 12], &oracle)
            .expect("derive 2");

        // Different nonces → different MAC keys → different tags
        let tag1 = keys1.mac_key.sign(b"data").expect("sign1");
        let tag2 = keys2.mac_key.sign(b"data").expect("sign2");
        assert_ne!(tag1, tag2);

        // Different seeds
        assert_ne!(*keys1.technique_seed, *keys2.technique_seed);
    }

    #[test]
    fn different_secret_different_keys() {
        let oracle = test_oracle();
        let nonce = [0xCC; 12];

        let keys1 = derive_session_keys(b"secret-one", &nonce, &oracle)
            .expect("derive 1");
        let keys2 = derive_session_keys(b"secret-two", &nonce, &oracle)
            .expect("derive 2");

        let tag1 = keys1.mac_key.sign(b"data").expect("sign1");
        let tag2 = keys2.mac_key.sign(b"data").expect("sign2");
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn empty_secret_rejected() {
        let oracle = test_oracle();
        let result = derive_session_keys(b"", &[1u8; 12], &oracle);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidInput(msg)) => {
                assert!(msg.contains("empty"));
            }
            other => panic!("expected InvalidInput, got {:?}", other),
        }
    }

    #[test]
    fn zero_nonce_rejected() {
        let oracle = test_oracle();
        let result = derive_session_keys(b"secret", &[0u8; 12], &oracle);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidInput(msg)) => {
                assert!(msg.contains("zero"));
            }
            other => panic!("expected InvalidInput, got {:?}", other),
        }
    }
}
