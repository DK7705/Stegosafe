use crate::techniques::TechniqueId;
use crate::params::EmbedParams;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn hmac_derive(key: &[u8], info: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(info);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn select_technique(
    technique_seed: &[u8; 32],
    _width: u32,
    _height: u32,
    edge_density: f32,
    _params: &EmbedParams,
) -> TechniqueId {
    // Derive selection byte
    let hash = hmac_derive(technique_seed, b"stegosafe-technique-select-v1");
    let selector = hash[0];
    
    // Build candidate list based on image properties
    let mut candidates = vec![TechniqueId::LsbSequential, TechniqueId::LsbRandomHmac];
    if edge_density > 0.15 {
        candidates.push(TechniqueId::EdgeAdaptiveLsb);
    }
    
    // Select deterministically
    let index = (selector as usize) % candidates.len();
    candidates[index]
}

pub fn compute_edge_density(img: &image::RgbImage) -> f32 {
    let (w, h) = img.dimensions();
    if w < 3 || h < 3 {
        return 0.0;
    }
    let mut high_edge_count = 0;
    let total_pixels = w * h;
    
    let raw = img.as_raw();
    let get_luma = |x: u32, y: u32| -> f32 {
        let idx = (y * w + x) as usize * 3;
        0.299 * raw[idx] as f32 + 0.587 * raw[idx + 1] as f32 + 0.114 * raw[idx + 2] as f32
    };

    for y in 1..h-1 {
        for x in 1..w-1 {
            let p00 = get_luma(x - 1, y - 1);
            let p10 = get_luma(x, y - 1);
            let p20 = get_luma(x + 1, y - 1);
            let p01 = get_luma(x - 1, y);
            let p21 = get_luma(x + 1, y);
            let p02 = get_luma(x - 1, y + 1);
            let p12 = get_luma(x, y + 1);
            let p22 = get_luma(x + 1, y + 1);

            let gx = p20 - p00 + 2.0 * p21 - 2.0 * p01 + p22 - p02;
            let gy = p02 - p00 + 2.0 * p12 - 2.0 * p10 + p22 - p20;
            
            let magnitude = gx.abs() + gy.abs();
            if magnitude > 30.0 {
                high_edge_count += 1;
            }
        }
    }
    
    high_edge_count as f32 / total_pixels as f32
}
