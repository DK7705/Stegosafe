use thiserror::Error;

/// Errors arising from steganographic operations.
#[derive(Error, Debug)]
pub enum StegoError {
    #[error("payload too large for cover image")]
    PayloadTooLarge,
    #[error("malformed stego image")]
    MalformedImage,
    #[error("invalid parameters: {0}")]
    InvalidParams(&'static str),
    #[error("unsupported technique: {0}")]
    UnsupportedTechnique(String),
    #[error("internal error: {0}")]
    InternalError(String),
}
