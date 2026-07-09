use std::collections::HashMap;
use image::DynamicImage;
use crate::error::StegoError;
use crate::params::{EmbedParams, EmbedParamsMeta, randomize_params};
use crate::techniques::{TechniqueId, EmbeddingTechnique};
use crate::techniques::lsb_sequential::LsbSequential;
use crate::techniques::lsb_random::LsbRandomHmac;
use crate::techniques::edge_adaptive::EdgeAdaptiveLsb;
use crate::selector;

pub struct EmbedResult {
    pub technique_name: String,
    pub params_meta: EmbedParamsMeta,
}

pub struct StegoEngine {
    techniques: HashMap<TechniqueId, Box<dyn EmbeddingTechnique>>,
}

impl Default for StegoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl StegoEngine {
    pub fn new() -> Self {
        let mut techniques: HashMap<TechniqueId, Box<dyn EmbeddingTechnique>> = HashMap::new();
        techniques.insert(TechniqueId::LsbSequential, Box::new(LsbSequential));
        techniques.insert(TechniqueId::LsbRandomHmac, Box::new(LsbRandomHmac));
        techniques.insert(TechniqueId::EdgeAdaptiveLsb, Box::new(EdgeAdaptiveLsb));
        Self { techniques }
    }
    
    pub fn embed(
        &self,
        cover: &DynamicImage,
        payload: &[u8],
        technique_seed: &[u8; 32],
        param_seed: &[u8; 32],
    ) -> Result<(DynamicImage, EmbedResult), StegoError> {
        let rgb = cover.to_rgb8();
        let (w, h) = rgb.dimensions();
        
        let params = randomize_params(param_seed);
        let edge_density = selector::compute_edge_density(&rgb);
        let technique_id = selector::select_technique(technique_seed, w, h, edge_density, &params);
        
        let technique = self.techniques.get(&technique_id)
            .ok_or_else(|| StegoError::InternalError("technique not registered".into()))?;
        
        let result_rgb = technique.embed(&rgb, payload, &params)?;
        
        Ok((DynamicImage::ImageRgb8(result_rgb), EmbedResult {
            technique_name: technique_id.name().to_string(),
            params_meta: params.to_meta(),
        }))
    }
    
    pub fn extract(
        &self,
        stego: &DynamicImage,
        technique_name: &str,
        params: &EmbedParams,
        expected_len: usize,
    ) -> Result<Vec<u8>, StegoError> {
        let technique_id = TechniqueId::from_name(technique_name)
            .ok_or_else(|| StegoError::UnsupportedTechnique(technique_name.to_string()))?;
        
        let technique = self.techniques.get(&technique_id)
            .ok_or_else(|| StegoError::UnsupportedTechnique(technique_name.to_string()))?;
        
        let rgb = stego.to_rgb8();
        technique.extract(&rgb, expected_len, params)
    }
}
