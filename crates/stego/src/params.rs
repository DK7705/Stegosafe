//! Embedding parameters — both the rich internal type and the serialisable
//! metadata variant written into JSON alongside the stego image.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// HMAC helper
// ---------------------------------------------------------------------------

fn hmac_derive(key: &[u8], info: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(info);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// ChannelMask
// ---------------------------------------------------------------------------

/// Selects which colour channels participate in embedding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelMask {
    pub red: bool,
    pub green: bool,
    pub blue: bool,
}

impl ChannelMask {
    /// All three channels active.
    pub fn all() -> Self {
        Self {
            red: true,
            green: true,
            blue: true,
        }
    }

    /// Number of active channels.
    pub fn active_count(&self) -> usize {
        self.red as usize + self.green as usize + self.blue as usize
    }

    /// Whether the channel at `channel_offset` (mod 3: 0=R, 1=G, 2=B) is
    /// active.
    pub fn includes_channel(&self, channel_offset: usize) -> bool {
        match channel_offset % 3 {
            0 => self.red,
            1 => self.green,
            2 => self.blue,
            _ => unreachable!(),
        }
    }

    /// Serialise to a compact tag such as `"rgb"`, `"rg"`, `"b"`, etc.
    pub fn to_tag(&self) -> String {
        let mut s = String::new();
        if self.red {
            s.push('r');
        }
        if self.green {
            s.push('g');
        }
        if self.blue {
            s.push('b');
        }
        s
    }

    /// Parse from a tag string produced by [`to_tag`]. Returns `None` if the
    /// tag would result in zero active channels.
    pub fn from_tag(s: &str) -> Option<Self> {
        let mask = Self {
            red: s.contains('r'),
            green: s.contains('g'),
            blue: s.contains('b'),
        };
        if mask.active_count() == 0 {
            None
        } else {
            Some(mask)
        }
    }
}

// ---------------------------------------------------------------------------
// EmbedParams (internal, rich type)
// ---------------------------------------------------------------------------

/// Internal embedding parameters carrying the full key material.
#[derive(Debug, Clone)]
pub struct EmbedParams {
    pub channels: ChannelMask,
    /// 0 = LSB, 1 = second bit.
    pub bit_plane: u8,
    /// Key used by keyed-placement techniques.
    pub placement_key: [u8; 32],
}

impl EmbedParams {
    /// Convert to the serialisable metadata variant.
    pub fn to_meta(&self) -> EmbedParamsMeta {
        EmbedParamsMeta {
            channels: self.channels.to_tag(),
            bit_plane: self.bit_plane,
        }
    }

    /// Reconstruct from serialised metadata plus the placement key.
    /// Returns `None` if the channel tag is invalid or `bit_plane > 1`.
    pub fn from_meta(meta: &EmbedParamsMeta, placement_key: [u8; 32]) -> Option<Self> {
        let channels = ChannelMask::from_tag(&meta.channels)?;
        if meta.bit_plane > 1 {
            return None;
        }
        Some(Self {
            channels,
            bit_plane: meta.bit_plane,
            placement_key,
        })
    }

    /// Backward-compatible defaults: all channels, LSB, with the given key.
    pub fn legacy(placement_key: [u8; 32]) -> Self {
        Self {
            channels: ChannelMask::all(),
            bit_plane: 0,
            placement_key,
        }
    }
}

// ---------------------------------------------------------------------------
// EmbedParamsMeta (serialisable for JSON metadata)
// ---------------------------------------------------------------------------

/// Serialisable subset of [`EmbedParams`] stored in the stego metadata JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedParamsMeta {
    pub channels: String,
    pub bit_plane: u8,
}

impl EmbedParamsMeta {
    /// Legacy default: all channels, bit-plane 0.
    pub fn default_legacy() -> Self {
        Self {
            channels: "rgb".to_string(),
            bit_plane: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic parameter randomisation
// ---------------------------------------------------------------------------

/// The seven valid channel combinations, indexed 0–6.
const CHANNEL_COMBOS: [(bool, bool, bool); 7] = [
    (true, false, false),  // r
    (false, true, false),  // g
    (false, false, true),  // b
    (true, true, false),   // rg
    (true, false, true),   // rb
    (false, true, true),   // gb
    (true, true, true),    // rgb
];

/// Derive embedding parameters deterministically from `param_seed`.
pub fn randomize_params(param_seed: &[u8; 32]) -> EmbedParams {
    // Channels
    let ch_hash = hmac_derive(param_seed, b"stegosafe-param-channels-v1");
    let ch_idx = (ch_hash[0] as usize) % 7;
    let (r, g, b) = CHANNEL_COMBOS[ch_idx];
    let channels = ChannelMask {
        red: r,
        green: g,
        blue: b,
    };

    // Bit-plane (80 % LSB, 20 % second bit)
    let bp_hash = hmac_derive(param_seed, b"stegosafe-param-bitplane-v1");
    let bit_plane = if bp_hash[0] < 204 { 0 } else { 1 };

    // Placement key
    let placement_key = hmac_derive(param_seed, b"stegosafe-param-placement-v1");

    EmbedParams {
        channels,
        bit_plane,
        placement_key,
    }
}

/// Derive the placement key from `param_seed` (public so the CLI can
/// reconstruct it for extraction without the full [`randomize_params`] call).
pub fn derive_placement_key(param_seed: &[u8; 32]) -> [u8; 32] {
    hmac_derive(param_seed, b"stegosafe-param-placement-v1")
}
