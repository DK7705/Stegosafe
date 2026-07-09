//! Embedding technique trait and identifiers.

use image::RgbImage;

use crate::error::StegoError;
use crate::params::EmbedParams;

/// Identifies a specific embedding technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TechniqueId {
    LsbSequential,
    LsbRandomHmac,
    EdgeAdaptiveLsb,
}

impl TechniqueId {
    /// Stable string name stored in metadata.
    pub fn name(&self) -> &'static str {
        match self {
            Self::LsbSequential => "lsb-sequential-v1",
            Self::LsbRandomHmac => "lsb-random-hmac-v1",
            Self::EdgeAdaptiveLsb => "edge-adaptive-lsb-v1",
        }
    }

    /// Parse a technique name back into a [`TechniqueId`].
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "lsb-sequential-v1" => Some(Self::LsbSequential),
            "lsb-random-hmac-v1" => Some(Self::LsbRandomHmac),
            "edge-adaptive-lsb-v1" => Some(Self::EdgeAdaptiveLsb),
            _ => None,
        }
    }
}

/// A steganographic embedding / extraction algorithm.
pub trait EmbeddingTechnique: Send + Sync {
    /// Technique identifier.
    fn id(&self) -> TechniqueId;

    /// Maximum payload bytes (excluding frame overhead) that can be embedded.
    fn capacity(&self, width: u32, height: u32, params: &EmbedParams) -> usize;

    /// Embed `payload` into `cover`, returning the stego image.
    fn embed(
        &self,
        cover: &RgbImage,
        payload: &[u8],
        params: &EmbedParams,
    ) -> Result<RgbImage, StegoError>;

    /// Extract a payload of `expected_len` bytes from `stego`.
    fn extract(
        &self,
        stego: &RgbImage,
        expected_len: usize,
        params: &EmbedParams,
    ) -> Result<Vec<u8>, StegoError>;
}

pub mod lsb_sequential;
pub mod lsb_random;
pub mod edge_adaptive;
