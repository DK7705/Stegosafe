//! HMAC-based random-placement LSB embedding.
//!
//! This is the original Stegosafe algorithm, preserved here for backward
//! compatibility.  It ignores the channel mask and bit-plane from
//! [`EmbedParams`] — all channels are used, and only bit-plane 0 (LSB) is
//! modified.  Position ordering is derived from `params.placement_key`.

use hmac::{Hmac, Mac};
use image::RgbImage;
use sha2::Sha256;

use crate::error::StegoError;
use crate::params::EmbedParams;
use crate::techniques::{EmbeddingTechnique, TechniqueId};
use crate::util;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA-256 signing helper.
fn hmac_sign(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Generate HMAC-scored placement positions — identical to the original CLI
/// implementation.
fn placement_positions(
    key: &[u8; 32],
    channel_count: usize,
    needed: usize,
) -> Result<Vec<usize>, StegoError> {
    if needed > channel_count {
        return Err(StegoError::PayloadTooLarge);
    }

    let mut scored: Vec<([u8; 32], usize)> = Vec::with_capacity(channel_count);
    for index in 0..channel_count {
        let mut input = Vec::with_capacity(32);
        input.extend_from_slice(b"stegosafe-placement-v1:");
        input.extend_from_slice(&(index as u64).to_be_bytes());
        let score = hmac_sign(key, &input);
        scored.push((score, index));
    }

    scored.sort_unstable_by(|(sa, ia), (sb, ib)| match sa.cmp(sb) {
        std::cmp::Ordering::Equal => ia.cmp(ib),
        other => other,
    });

    Ok(scored.into_iter().take(needed).map(|(_, i)| i).collect())
}

/// HMAC-based random-placement LSB technique.
pub struct LsbRandomHmac;

impl EmbeddingTechnique for LsbRandomHmac {
    fn id(&self) -> TechniqueId {
        TechniqueId::LsbRandomHmac
    }

    fn capacity(&self, width: u32, height: u32, _params: &EmbedParams) -> usize {
        let channel_count = (width as usize) * (height as usize) * 3;
        let usable_bytes = channel_count / 8;
        usable_bytes.saturating_sub(4)
    }

    fn embed(
        &self,
        cover: &RgbImage,
        payload: &[u8],
        params: &EmbedParams,
    ) -> Result<RgbImage, StegoError> {
        let (w, h) = cover.dimensions();
        let channel_count = (w as usize) * (h as usize) * 3;

        let framed = util::frame_payload(payload);
        let needed_bits = framed.len() * 8;
        let positions = placement_positions(&params.placement_key, channel_count, needed_bits)?;

        let mut stego = cover.clone();
        let raw = stego.as_mut();
        // Hardcoded bit_plane = 0 for backward compatibility.
        util::write_bits_at_positions(raw, &positions, &framed, 0);
        Ok(stego)
    }

    fn extract(
        &self,
        stego: &RgbImage,
        expected_len: usize,
        params: &EmbedParams,
    ) -> Result<Vec<u8>, StegoError> {
        let (w, h) = stego.dimensions();
        let channel_count = (w as usize) * (h as usize) * 3;

        let total_bytes = expected_len + 4;
        let needed_bits = total_bytes * 8;
        let positions = placement_positions(&params.placement_key, channel_count, needed_bits)?;

        let raw = stego.as_raw();
        // Hardcoded bit_plane = 0 for backward compatibility.
        let data = util::read_bits_at_positions(raw, &positions, total_bytes, 0)?;
        util::validate_frame(&data, expected_len)
    }
}
