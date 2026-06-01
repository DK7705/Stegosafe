//! Cryptographic primitives for the Stegosafe adaptive steganography tool.
//!
//! This crate provides the foundational crypto layer (Phase 1) that all
//! subsequent phases build upon:
//!
//! - **AES-256-GCM** authenticated encryption with integrated Zstandard
//!   compression ([`AeadKey`])
//! - **HKDF-SHA-256** domain-separated key derivation ([`derive_session_keys`])
//! - **HMAC-SHA-256** message authentication ([`HmacKey`])
//! - **Hardware-seeded entropy oracle** combining TRNG and OS randomness
//!   ([`EntropyOracle`])
//! - **Nonce management** with structural uniqueness guarantees ([`nonce::NonceManager`])
//!
//! # Security properties
//!
//! - All key material is zeroized on drop (`zeroize` crate)
//! - No timing side-channels in tag comparison (constant-time via `subtle`)
//! - No panics in the crypto path (no `.unwrap()` or `.expect()`)
//! - Nonce reuse is structurally prevented by the random+counter hybrid
//! - Single opaque `DecryptionFailed` error prevents error oracle attacks
//!
//! # Quick start
//!
//! ```no_run
//! use stegosafe_crypto::{EntropyOracle, derive_session_keys};
//!
//! let entropy = EntropyOracle::init().expect("entropy init");
//!
//! // Derive session keys from a shared secret
//! let session_nonce = [0x01u8; 12]; // should be random in production
//! let keys = derive_session_keys(
//!     b"shared-secret-from-key-exchange",
//!     &session_nonce,
//!     &entropy,
//! ).expect("key derivation");
//!
//! // Encrypt a payload
//! let ciphertext = keys.enc_key
//!     .encrypt(b"secret payload", b"session-context")
//!     .expect("encryption");
//!
//! // Decrypt
//! let plaintext = keys.enc_key
//!     .decrypt(&ciphertext, b"session-context")
//!     .expect("decryption");
//! ```

// ============================================================================
// Crate-level lint configuration
// ============================================================================

// No .unwrap() or .expect() in the crypto path — all errors are handled.
#![forbid(clippy::unwrap_used)]

// No unsafe code in this crate. Hardware TRNG access is handled by the
// `rdrand` crate (its unsafe is outside our crate boundary).
#![forbid(unsafe_code)]

// ============================================================================
// Module declarations
// ============================================================================

pub mod error;
pub mod entropy;
pub mod nonce;
pub mod aead;
pub mod kdf;

// ============================================================================
// Public re-exports (frozen API surface for Phase 2 handoff)
// ============================================================================

pub use error::CryptoError;
pub use entropy::{EntropyOracle, EntropyHealth};
pub use aead::AeadKey;
pub use kdf::{HmacKey, SessionKeys, derive_session_keys};
