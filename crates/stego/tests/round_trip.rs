use image::{ImageBuffer, Rgb};
use stegosafe_stego::{StegoEngine, ChannelMask, EmbedParams, randomize_params, derive_placement_key};

fn create_test_image(width: u32, height: u32) -> image::DynamicImage {
    let img = ImageBuffer::from_fn(width, height, |x, y| {
        Rgb([
            (x % 251) as u8,
            (y % 251) as u8,
            ((x + y) % 251) as u8,
        ])
    });
    image::DynamicImage::ImageRgb8(img)
}

fn create_edge_image(width: u32, height: u32) -> image::DynamicImage {
    let img = ImageBuffer::from_fn(width, height, |x, _y| {
        if x % 2 == 0 {
            Rgb([255, 255, 255])
        } else {
            Rgb([0, 0, 0])
        }
    });
    image::DynamicImage::ImageRgb8(img)
}

#[test]
fn round_trip_test() {
    let cover = create_test_image(64, 64);
    let payload = b"hello stego";
    let technique_seed = [0x42; 32];
    let param_seed = [0x11; 32];

    let engine = StegoEngine::new();
    let (stego, result) = engine.embed(&cover, payload, &technique_seed, &param_seed).unwrap();

    let placement_key = derive_placement_key(&param_seed);
    let extract_params = EmbedParams::from_meta(&result.params_meta, placement_key).unwrap();

    let recovered = engine.extract(&stego, &result.technique_name, &extract_params, payload.len()).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn edge_adaptive_round_trip() {
    let cover = create_edge_image(64, 64);
    let payload = b"hello edge";
    let technique_seed = [0x55; 32]; // Try a seed that might pick it
    let param_seed = [0x11; 32];

    let engine = StegoEngine::new();
    let (stego, result) = engine.embed(&cover, payload, &technique_seed, &param_seed).unwrap();

    let placement_key = derive_placement_key(&param_seed);
    let extract_params = EmbedParams::from_meta(&result.params_meta, placement_key).unwrap();

    let recovered = engine.extract(&stego, &result.technique_name, &extract_params, payload.len()).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn payload_too_large() {
    let cover = create_test_image(4, 4);
    let payload = vec![0u8; 1000];
    let technique_seed = [0x42; 32];
    let param_seed = [0x11; 32];

    let engine = StegoEngine::new();
    let result = engine.embed(&cover, &payload, &technique_seed, &param_seed);
    assert!(result.is_err());
}
