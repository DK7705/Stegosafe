//! Sequential LSB embedding — deterministic, fast, no key required for
//! position ordering.

use image::RgbImage;

use crate::error::StegoError;
use crate::params::EmbedParams;
use crate::techniques::{EmbeddingTechnique, TechniqueId};
use crate::util;

/// Sequential LSB technique — embeds bits in channel order, filtered by the
/// active channel mask.
pub struct LsbSequential;

impl LsbSequential {
    /// Generate the ordered list of channel-byte positions that participate in
    /// embedding.
    fn positions(width: u32, height: u32, params: &EmbedParams) -> Vec<usize> {
        let total_channels = (width as usize) * (height as usize) * 3;
        (0..total_channels)
            .filter(|&i| params.channels.includes_channel(i % 3))
            .collect()
    }
}

impl EmbeddingTechnique for LsbSequential {
    fn id(&self) -> TechniqueId {
        TechniqueId::LsbSequential
    }

    fn capacity(&self, width: u32, height: u32, params: &EmbedParams) -> usize {
        let positions = Self::positions(width, height, params);
        let usable_bytes = positions.len() / 8;
        usable_bytes.saturating_sub(4) // subtract length-prefix overhead
    }

    fn embed(
        &self,
        cover: &RgbImage,
        payload: &[u8],
        params: &EmbedParams,
    ) -> Result<RgbImage, StegoError> {
        let (w, h) = cover.dimensions();
        let positions = Self::positions(w, h, params);

        let framed = util::frame_payload(payload);
        let needed_bits = framed.len() * 8;
        if needed_bits > positions.len() {
            return Err(StegoError::PayloadTooLarge);
        }

        let mut stego = cover.clone();
        let raw = stego.as_mut();
        util::write_bits_at_positions(raw, &positions, &framed, params.bit_plane);
        Ok(stego)
    }

    fn extract(
        &self,
        stego: &RgbImage,
        expected_len: usize,
        params: &EmbedParams,
    ) -> Result<Vec<u8>, StegoError> {
        let (w, h) = stego.dimensions();
        let positions = Self::positions(w, h, params);

        let total_bytes = expected_len + 4; // include length prefix
        let raw = stego.as_raw();
        let data = util::read_bits_at_positions(raw, &positions, total_bytes, params.bit_plane)?;
        util::validate_frame(&data, expected_len)
    }
}
