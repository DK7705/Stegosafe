//! AES-256-GCM authenticated encryption with Zstandard compression.
//!
//! Payloads are Zstandard-compressed before encryption to reduce size
//! and improve entropy distribution in the final stego object. The
//! compression/decompression is internal — callers see plaintext in,
//! plaintext out.
//!
//! # Output format
//!
//! ```text
//! ┌──────────────┬───────────────────┬──────────────┐
//! │ Nonce (12 B) │ Ciphertext (var)  │ Tag (16 B)   │
//! └──────────────┴───────────────────┴──────────────┘
//! ```
//!
//! The tag is appended by AES-GCM directly (not a separate field).
//! Minimum valid ciphertext length is 28 bytes (12 nonce + 16 tag).
//!
//! # AAD (Additional Authenticated Data)
//!
//! AAD is a required parameter — callers must supply context (e.g.,
//! session ID, truncated timestamp) to bind ciphertext to its transmission
//! context and prevent cut-and-paste attacks across sessions.

use std::sync::Mutex;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use zeroize::Zeroizing;

use crate::entropy::EntropyOracle;
use crate::error::CryptoError;
use crate::nonce::NonceManager;

/// Minimum ciphertext length: 12-byte nonce + 16-byte tag.
const MIN_CIPHERTEXT_LEN: usize = 12 + 16;

/// Zstandard compression level (balances speed and ratio).
const ZSTD_LEVEL: i32 = 3;

/// AES-256-GCM encryption key with integrated nonce management.
///
/// Wraps a 256-bit key with automatic nonce generation and
/// Zstandard compression. The key material is zeroized on drop.
///
/// # Nonce management
///
/// Each `AeadKey` owns a [`NonceManager`] that produces unique nonces
/// via a random-base + counter hybrid. The `Mutex` enables `encrypt`
/// to take `&self` (not `&mut self`) while maintaining nonce uniqueness.
///
/// # Construction
///
/// Use [`AeadKey::new`] to construct from raw key bytes and an
/// [`EntropyOracle`] for nonce generation. There is no fallible-free
/// constructor — entropy is always required.
#[derive(Debug)]
pub struct AeadKey {
    key: Zeroizing<[u8; 32]>,
    nonce_mgr: Mutex<NonceManager>,
}

impl AeadKey {
    /// Construct from raw key material and an entropy source.
    ///
    /// The `EntropyOracle` is used to initialize the internal
    /// [`NonceManager`]. The key bytes are moved into a `Zeroizing`
    /// wrapper and cleared on drop.
    pub fn new(bytes: [u8; 32], entropy: &EntropyOracle) -> Result<Self, CryptoError> {
        let nonce_mgr = NonceManager::new(entropy)?;
        Ok(Self {
            key: Zeroizing::new(bytes),
            nonce_mgr: Mutex::new(nonce_mgr),
        })
    }

    /// Encrypt plaintext with associated data.
    ///
    /// 1. Compresses plaintext with Zstandard (level 3)
    /// 2. Generates a unique 96-bit nonce
    /// 3. Encrypts with AES-256-GCM
    /// 4. Returns `nonce ‖ ciphertext ‖ tag`
    ///
    /// # Errors
    ///
    /// - [`CryptoError::KeyExhausted`] if the nonce counter has reached `u32::MAX`
    /// - [`CryptoError::InvalidInput`] if compression or encryption fails
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Step 1: Compress
        let compressed = compress(plaintext)?;

        // Step 2: Generate unique nonce
        let nonce_bytes = {
            let mut mgr = self.nonce_mgr.lock()
                .map_err(|_| CryptoError::InvalidInput("nonce manager lock poisoned"))?;
            mgr.next()?
        };

        // Step 3: Create cipher and encrypt
        let cipher = Aes256Gcm::new_from_slice(&*self.key)
            .map_err(|_| CryptoError::InvalidInput("invalid key length"))?;

        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: &compressed,
            aad,
        };

        let ciphertext_and_tag = cipher.encrypt(nonce, payload)
            .map_err(|_| CryptoError::InvalidInput("encryption failed"))?;

        // Step 4: Format output: nonce ‖ ciphertext ‖ tag
        let mut output = Vec::with_capacity(12 + ciphertext_and_tag.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext_and_tag);

        Ok(output)
    }

    /// Decrypt and verify ciphertext with associated data.
    ///
    /// 1. Validates minimum length (28 bytes: 12 nonce + 16 tag)
    /// 2. Splits nonce from ciphertext+tag
    /// 3. Decrypts and verifies tag with AES-256-GCM
    /// 4. Decompresses Zstandard
    /// 5. Returns plaintext only if tag is valid
    ///
    /// # Errors
    ///
    /// - [`CryptoError::InvalidInput`] if `ciphertext` is too short
    /// - [`CryptoError::DecryptionFailed`] for **all** authentication failures
    ///   (single opaque error — no oracle)
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Step 1: Validate minimum length
        if ciphertext.len() < MIN_CIPHERTEXT_LEN {
            return Err(CryptoError::InvalidInput(
                "ciphertext too short (minimum 28 bytes: 12 nonce + 16 tag)",
            ));
        }

        // Step 2: Split nonce and ciphertext+tag
        let (nonce_bytes, ct_and_tag) = ciphertext.split_at(12);

        // Step 3: Create cipher and decrypt
        let cipher = Aes256Gcm::new_from_slice(&*self.key)
            .map_err(|_| CryptoError::InvalidInput("invalid key length"))?;

        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
        let payload = Payload {
            msg: ct_and_tag,
            aad,
        };

        let compressed = cipher.decrypt(nonce, payload)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        // Step 4: Decompress
        let plaintext = decompress(&compressed)?;

        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// Internal: Zstandard compression
// ---------------------------------------------------------------------------

/// Compress data with Zstandard at the configured level.
fn compress(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    zstd::encode_all(data, ZSTD_LEVEL)
        .map_err(|_| CryptoError::InvalidInput("compression failed"))
}

/// Decompress Zstandard data.
///
/// Errors are mapped to [`CryptoError::DecryptionFailed`] to avoid
/// leaking information about which stage failed.
fn decompress(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    zstd::decode_all(data)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_oracle() -> EntropyOracle {
        EntropyOracle::init().expect("entropy oracle should initialize")
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let oracle = test_oracle();
        let key = AeadKey::new([0x42; 32], &oracle).expect("key creation");
        let aad = b"test-session-id";

        let ct = key.encrypt(b"", aad).expect("encrypt empty");
        let pt = key.decrypt(&ct, aad).expect("decrypt empty");
        assert_eq!(pt, b"");
    }

    #[test]
    fn round_trip_small_plaintext() {
        let oracle = test_oracle();
        let key = AeadKey::new([0x42; 32], &oracle).expect("key creation");
        let aad = b"session-001";
        let msg = b"hello world";

        let ct = key.encrypt(msg, aad).expect("encrypt");
        let pt = key.decrypt(&ct, aad).expect("decrypt");
        assert_eq!(pt, msg);
    }

    #[test]
    fn round_trip_large_plaintext() {
        let oracle = test_oracle();
        let key = AeadKey::new([0x42; 32], &oracle).expect("key creation");
        let aad = b"session-002";
        let msg = vec![0xAB; 65536]; // 64 KB

        let ct = key.encrypt(&msg, aad).expect("encrypt");
        let pt = key.decrypt(&ct, aad).expect("decrypt");
        assert_eq!(pt, msg);
    }

    #[test]
    fn ciphertext_has_nonce_prepended() {
        let oracle = test_oracle();
        let key = AeadKey::new([0x42; 32], &oracle).expect("key creation");
        let aad = b"test";

        let ct = key.encrypt(b"payload", aad).expect("encrypt");
        // Must be at least 28 bytes (12 nonce + 16 tag + compressed payload)
        assert!(ct.len() >= MIN_CIPHERTEXT_LEN);
    }

    #[test]
    fn two_encryptions_produce_different_ciphertexts() {
        let oracle = test_oracle();
        let key = AeadKey::new([0x42; 32], &oracle).expect("key creation");
        let aad = b"test";
        let msg = b"same message";

        let ct1 = key.encrypt(msg, aad).expect("encrypt 1");
        let ct2 = key.encrypt(msg, aad).expect("encrypt 2");

        // Different nonces → different ciphertexts
        assert_ne!(ct1, ct2);
        // Nonces should differ (first 12 bytes)
        assert_ne!(&ct1[..12], &ct2[..12]);
    }

    #[test]
    fn wrong_aad_fails_decryption() {
        let oracle = test_oracle();
        let key = AeadKey::new([0x42; 32], &oracle).expect("key creation");

        let ct = key.encrypt(b"secret", b"correct-aad").expect("encrypt");
        let result = key.decrypt(&ct, b"wrong-aad");

        assert!(result.is_err());
        match result {
            Err(CryptoError::DecryptionFailed) => {} // expected
            other => panic!("expected DecryptionFailed, got {:?}", other),
        }
    }

    #[test]
    fn corrupted_tag_fails_decryption() {
        let oracle = test_oracle();
        let key = AeadKey::new([0x42; 32], &oracle).expect("key creation");
        let aad = b"test";

        let mut ct = key.encrypt(b"secret", aad).expect("encrypt");
        // Corrupt the last byte (part of the tag)
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;

        let result = key.decrypt(&ct, aad);
        assert!(result.is_err());
        match result {
            Err(CryptoError::DecryptionFailed) => {} // expected
            other => panic!("expected DecryptionFailed, got {:?}", other),
        }
    }

    #[test]
    fn corrupted_ciphertext_fails_decryption() {
        let oracle = test_oracle();
        let key = AeadKey::new([0x42; 32], &oracle).expect("key creation");
        let aad = b"test";

        let mut ct = key.encrypt(b"secret data", aad).expect("encrypt");
        // Corrupt a byte in the middle (ciphertext body)
        if ct.len() > 20 {
            ct[15] ^= 0xFF;
        }

        let result = key.decrypt(&ct, aad);
        assert!(result.is_err());
    }

    #[test]
    fn too_short_ciphertext_returns_invalid_input() {
        let oracle = test_oracle();
        let key = AeadKey::new([0x42; 32], &oracle).expect("key creation");

        let result = key.decrypt(&[0u8; 27], b"test");
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidInput(_)) => {} // expected
            other => panic!("expected InvalidInput, got {:?}", other),
        }
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let oracle = test_oracle();
        let key1 = AeadKey::new([0x11; 32], &oracle).expect("key1");
        let key2 = AeadKey::new([0x22; 32], &oracle).expect("key2");
        let aad = b"test";

        let ct = key1.encrypt(b"secret", aad).expect("encrypt with key1");
        let result = key2.decrypt(&ct, aad);

        assert!(result.is_err());
        match result {
            Err(CryptoError::DecryptionFailed) => {} // expected
            other => panic!("expected DecryptionFailed, got {:?}", other),
        }
    }

    #[test]
    fn compression_reduces_repetitive_payload() {
        let oracle = test_oracle();
        let key = AeadKey::new([0x42; 32], &oracle).expect("key creation");
        let aad = b"test";

        // Highly compressible: 4 KB of repeated 'A'
        let msg = vec![b'A'; 4096];
        let ct = key.encrypt(&msg, aad).expect("encrypt");

        // Compressed ciphertext should be much smaller than plaintext
        // (nonce + compressed + tag) < plaintext length
        assert!(ct.len() < msg.len());
    }
}
