//! Adaptive steganography engine for the Stegosafe tool.
//!
//! Provides multiple embedding techniques with automatic technique
//! selection and parameter randomisation driven by cryptographic seeds.

pub mod error;
pub mod params;
pub mod techniques;
pub mod selector;
pub mod engine;
mod util;

pub use error::StegoError;
pub use params::{ChannelMask, EmbedParams, EmbedParamsMeta, randomize_params, derive_placement_key};
pub use techniques::TechniqueId;
pub use engine::{StegoEngine, EmbedResult};
