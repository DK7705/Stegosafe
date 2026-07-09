//! Edge-adaptive LSB embedding — preferentially hides data in high-edge
//! regions of the image using Sobel magnitude scoring.

use image::RgbImage;

use crate::error::StegoError;
use crate::params::EmbedParams;
use crate::techniques::{EmbeddingTechnique, TechniqueId};
use crate::util;

// ---------------------------------------------------------------------------
// Sobel helpers
// ---------------------------------------------------------------------------

/// Convert an RGB triple to a scalar luminance value.
pub(crate) fn luminance(r: u8, g: u8, b: u8) -> f32 {
    0.299 * r as f32 + 0.587 * g as f32 + 0.114 * b as f32
}

/// Compute per-pixel Sobel edge magnitude.  Border pixels (row/column 0 and
/// the last row/column) are assigned magnitude 0.0 (lowest priority).
pub(crate) fn compute_edge_map(img: &RgbImage) -> Vec<f32> {
    let (w, h) = img.dimensions();
    let mut magnitudes = vec![0.0f32; (w * h) as usize];

    // Pre-compute luminance for the whole image so the 3×3 neighbourhood
    // lookups are cheap.
    let lum: Vec<f32> = img
        .pixels()
        .map(|p| luminance(p[0], p[1], p[2]))
        .collect();

    let w_usize = w as usize;

    for y in 1..h - 1 {
        for x in 1..w - 1 {
            let idx = |dx: i32, dy: i32| -> f32 {
                lum[((y as i32 + dy) as usize) * w_usize + (x as i32 + dx) as usize]
            };

            // Sobel Gx kernel: [[-1,0,1],[-2,0,2],[-1,0,1]]
            let gx = -idx(-1, -1) + idx(1, -1)
                + -2.0 * idx(-1, 0)
                + 2.0 * idx(1, 0)
                + -idx(-1, 1)
                + idx(1, 1);

            // Sobel Gy kernel: [[-1,-2,-1],[0,0,0],[1,2,1]]
            let gy = -idx(-1, -1) - 2.0 * idx(0, -1) - idx(1, -1)
                + idx(-1, 1)
                + 2.0 * idx(0, 1)
                + idx(1, 1);

            // Manhattan approximation of magnitude.
            let magnitude = gx.abs() + gy.abs();
            magnitudes[(y * w + x) as usize] = magnitude;
        }
    }

    magnitudes
}

// ---------------------------------------------------------------------------
// Edge-adaptive technique
// ---------------------------------------------------------------------------

/// Edge-adaptive LSB technique.
pub struct EdgeAdaptiveLsb;

impl EdgeAdaptiveLsb {
    /// Build an ordered list of channel-byte positions sorted by descending
    /// edge magnitude of the owning pixel, with ties broken by ascending
    /// pixel index.  Only channels allowed by `params.channels` are included.
    fn priority_positions(
        edge_map: &[f32],
        width: u32,
        height: u32,
        params: &EmbedParams,
    ) -> Vec<usize> {
        let pixel_count = (width as usize) * (height as usize);

        // Build (magnitude, pixel_index) list and sort descending by
        // magnitude, ascending by pixel_index for ties.
        let mut priority: Vec<(f32, u32)> = edge_map
            .iter()
            .enumerate()
            .take(pixel_count)
            .map(|(i, &mag)| (mag, i as u32))
            .collect();

        priority.sort_unstable_by(|(ma, ia), (mb, ib)| {
            mb.partial_cmp(ma)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| ia.cmp(ib))
        });

        // Flatten to channel indices.
        let mut positions = Vec::with_capacity(pixel_count * params.channels.active_count());
        for &(_mag, px) in &priority {
            let base = (px as usize) * 3;
            for ch in 0..3u8 {
                if params.channels.includes_channel(ch as usize) {
                    positions.push(base + ch as usize);
                }
            }
        }
        positions
    }
}

impl EmbeddingTechnique for EdgeAdaptiveLsb {
    fn id(&self) -> TechniqueId {
        TechniqueId::EdgeAdaptiveLsb
    }

    fn capacity(&self, width: u32, height: u32, params: &EmbedParams) -> usize {
        let pixel_count = (width as usize) * (height as usize);
        let usable_channels = pixel_count * params.channels.active_count();
        let usable_bytes = usable_channels / 8;
        usable_bytes.saturating_sub(4)
    }

    fn embed(
        &self,
        cover: &RgbImage,
        payload: &[u8],
        params: &EmbedParams,
    ) -> Result<RgbImage, StegoError> {
        let (w, h) = cover.dimensions();
        let edge_map = compute_edge_map(cover);
        let positions = Self::priority_positions(&edge_map, w, h, params);

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
        let edge_map = compute_edge_map(stego);
        let positions = Self::priority_positions(&edge_map, w, h, params);

        let total_bytes = expected_len + 4;
        let raw = stego.as_raw();
        let data = util::read_bits_at_positions(raw, &positions, total_bytes, params.bit_plane)?;
        util::validate_frame(&data, expected_len)
    }
}
