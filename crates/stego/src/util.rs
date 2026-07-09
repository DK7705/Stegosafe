//! Shared helpers for bit-level I/O on raw pixel buffers.

use crate::error::StegoError;

/// Iterate bits MSB-first within each byte.
pub fn bits_from_bytes(data: &[u8]) -> impl Iterator<Item = u8> + '_ {
    data.iter().flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1))
}

/// Prepend a 4-byte big-endian length prefix to `payload`.
pub fn frame_payload(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(payload);
    framed
}

/// Verify the 4-byte length prefix matches `expected_len` and return the
/// payload without the prefix.
pub fn validate_frame(data: &[u8], expected_len: usize) -> Result<Vec<u8>, StegoError> {
    if data.len() < 4 {
        return Err(StegoError::MalformedImage);
    }
    let stored_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if stored_len != expected_len {
        return Err(StegoError::MalformedImage);
    }
    if data.len() < 4 + expected_len {
        return Err(StegoError::MalformedImage);
    }
    Ok(data[4..4 + expected_len].to_vec())
}

/// Write bits from `data` into `raw` pixel buffer at the given channel
/// `positions`, modifying the specified `bit_plane` (0 = LSB, 1 = second bit).
pub fn write_bits_at_positions(
    raw: &mut [u8],
    positions: &[usize],
    data: &[u8],
    bit_plane: u8,
) {
    let mask = 1u8 << bit_plane;
    let clear = !mask;
    for (bit, &pos) in bits_from_bytes(data).zip(positions.iter()) {
        if pos < raw.len() {
            raw[pos] = (raw[pos] & clear) | (bit << bit_plane);
        }
    }
}

/// Read bits from `raw` pixel buffer at the given channel `positions` and
/// reassemble into `total_bytes` bytes.
pub fn read_bits_at_positions(
    raw: &[u8],
    positions: &[usize],
    total_bytes: usize,
    bit_plane: u8,
) -> Result<Vec<u8>, StegoError> {
    let total_bits = total_bytes * 8;
    if positions.len() < total_bits {
        return Err(StegoError::MalformedImage);
    }
    let mut result = vec![0u8; total_bytes];
    for (i, &pos) in positions.iter().take(total_bits).enumerate() {
        if pos >= raw.len() {
            return Err(StegoError::MalformedImage);
        }
        let bit = (raw[pos] >> bit_plane) & 1;
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8); // MSB-first
        result[byte_idx] |= bit << bit_idx;
    }
    Ok(result)
}
