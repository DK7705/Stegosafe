//! Typed error types for the crypto crate.
//!
//! All errors are represented as a single enum with opaque variants
//! to prevent information leakage (no error oracle).

/// Result type alias for crypto operations.
pub type Result<T> = core::result::Result<T, CryptoError>;

/// Cryptographic error enum.
///
/// Deliberately opaque for security-sensitive variants to prevent
/// error oracles that could leak information about internal state.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Decryption or authentication verification failed.
    ///
    /// This is deliberately opaque — it does not distinguish between
    /// tag failure, padding failure, decompression failure, or any
    /// other post-decryption check. This prevents error oracle attacks.
    #[error("decryption failed")]
    DecryptionFailed,

    /// Input data is malformed or invalid.
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),

    /// No entropy source is available.
    #[error("entropy source unavailable")]
    EntropyUnavailable,

    /// The key has been used for the maximum number of operations
    /// and must be replaced (rekeyed).
    #[error("key exhausted — rekey required")]
    KeyExhausted,

    /// Key derivation operation failed.
    #[error("key derivation failed")]
    KdfError,
}
