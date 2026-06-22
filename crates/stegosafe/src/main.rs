use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use image::{DynamicImage, GenericImageView, ImageBuffer, Pixel};
use stegosafe_crypto::{derive_session_keys, EntropyOracle, HmacKey};

const SESSION_NONCE_LEN: usize = 12;

#[derive(Parser)]
#[command(name = "stegosafe")]
#[command(author = "Stegosafe")]
#[command(version = "0.1.0")]
#[command(about = "Adaptive steganography tool built on stegosafe-crypto", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Embed {
        #[arg(long)]
        cover: PathBuf,
        #[arg(long)]
        payload: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        secret: String,
        #[arg(long)]
        context: String,
    },
    Extract {
        #[arg(long)]
        stego: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        secret: String,
        #[arg(long)]
        context: String,
        #[arg(long)]
        nonce: Option<String>,
    },
}

#[derive(thiserror::Error, Debug)]
enum StegoError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Image error: {0}")]
    Image(#[from] image::ImageError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] stegosafe_crypto::CryptoError),
    #[error("Invalid nonce: must be 12 bytes hex")]
    InvalidNonce,
    #[error("Payload too large for cover image")]
    PayloadTooLarge,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Embed { cover, payload, output, secret, context } => {
            embed(&cover, &payload, &output, &secret, &context)
        }
        Commands::Extract { stego, output, secret, context, nonce } => {
            extract(&stego, &output, &secret, &context, &nonce)
        }
    }
}

fn embed(cover_path: &PathBuf, payload_path: &PathBuf, output_path: &PathBuf, secret: &str, context: &str) -> Result<()> {
    let entropy = EntropyOracle::init().context("failed to initialize entropy oracle")?;
    let secret_bytes = secret.as_bytes();
    let session_nonce = generate_session_nonce(&entropy)?;
    let keys = derive_session_keys(secret_bytes, &session_nonce, &entropy)
        .context("failed to derive session keys")?;

    let payload = fs::read(payload_path).context("failed to read payload")?;
    let encrypted = keys.enc_key.encrypt(&payload, context.as_bytes())
        .context("payload encryption failed")?;

    let mut cover = image::open(cover_path).context("failed to open cover image")?;
    let stego = embed_payload_in_image(&mut cover, &encrypted)
        .context("failed to embed payload into cover image")?;

    // Save stego image and separate metadata file (nonce + HMAC)
    let meta_path = output_path.with_extension("meta");
    let image_path = output_path;

    let mac_tag = keys.mac_key.sign(&encrypted)?;
    let metadata = format!("nonce:{}\nmac:{}\n", hex::encode(session_nonce), hex::encode(mac_tag));
    fs::write(&meta_path, metadata.as_bytes()).context("failed to write metadata file")?;

    stego.save(image_path)?;
    println!("Embedded payload successfully. Session nonce={}", hex::encode(session_nonce));
    Ok(())
}

fn extract(stego_path: &PathBuf, output_path: &PathBuf, secret: &str, context: &str, nonce_hex: &Option<String>) -> Result<()> {
    let entropy = EntropyOracle::init().context("failed to initialize entropy oracle")?;
    let secret_bytes = secret.as_bytes();
    // Obtain session nonce and optional HMAC from metadata if nonce not provided
    let (session_nonce, _expected_mac_opt) = if let Some(nhex) = nonce_hex {
        (parse_nonce(nhex)?, None)
    } else {
        let meta_path = stego_path.with_extension("meta");
        let meta = fs::read_to_string(&meta_path).context("failed to read metadata file; provide --nonce or ensure .meta file exists")?;
        // parse lines like "nonce:<hex>\nmac:<hex>"
        let mut nonce_opt: Option<String> = None;
        let mut mac_opt: Option<String> = None;
        for line in meta.lines() {
            if let Some(rest) = line.strip_prefix("nonce:") {
                nonce_opt = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("mac:") {
                mac_opt = Some(rest.trim().to_string());
            }
        }
        let nhex = nonce_opt.ok_or_else(|| StegoError::InvalidNonce)?;
        (parse_nonce(&nhex)?, mac_opt)
    };

    let keys = derive_session_keys(secret_bytes, &session_nonce, &entropy)
        .context("failed to derive session keys")?;

    let stego = image::open(stego_path).context("failed to open stego image")?;
    let payload = extract_payload_from_image(&stego)
        .context("failed to extract payload from stego image")?;

    // If metadata provided HMAC, verify before decryption
    let meta_path = stego_path.with_extension("meta");
    if let Ok(meta) = fs::read_to_string(&meta_path) {
        for line in meta.lines() {
            if let Some(rest) = line.strip_prefix("mac:") {
                let mac_hex = rest.trim();
                let mac_bytes = hex::decode(mac_hex).map_err(|_| StegoError::InvalidNonce)?;
                keys.mac_key.verify(&payload, &mac_bytes).map_err(|e| e)?;
                break;
            }
        }
    }

    let plaintext = keys.enc_key.decrypt(&payload, context.as_bytes())
        .context("payload decryption failed")?;

    fs::write(output_path, &plaintext).context("failed to write extracted payload")?;
    println!("Extraction succeeded");
    Ok(())
}

fn generate_session_nonce(entropy: &EntropyOracle) -> Result<[u8; SESSION_NONCE_LEN]> {
    let mut nonce = [0u8; SESSION_NONCE_LEN];
    entropy.fill(&mut nonce).context("failed to generate session nonce")?;
    if nonce.iter().all(|&b| b == 0) {
        return Err(StegoError::InvalidNonce.into());
    }
    Ok(nonce)
}

fn parse_nonce(hex_str: &str) -> Result<[u8; SESSION_NONCE_LEN]> {
    let bytes = hex::decode(hex_str).map_err(|_| StegoError::InvalidNonce)?;
    if bytes.len() != SESSION_NONCE_LEN {
        return Err(StegoError::InvalidNonce.into());
    }
    let mut nonce = [0u8; SESSION_NONCE_LEN];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

fn embed_payload_in_image(image: &mut DynamicImage, payload: &[u8]) -> Result<DynamicImage, StegoError> {
    let (width, height) = image.dimensions();
    let available_bits = (width as usize * height as usize * 3) / 8;
    if payload.len() + 4 > available_bits {
        return Err(StegoError::PayloadTooLarge);
    }

    let mut data = Vec::with_capacity(payload.len() + 4);
    data.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    data.extend_from_slice(payload);

    let mut bits = data.iter().flat_map(|byte| {
        (0..8).rev().map(move |bit| (byte >> bit) & 1)
    });

    let mut img = image.to_rgb8();
    for pixel in img.pixels_mut() {
        for channel in pixel.0.iter_mut() {
            if let Some(bit) = bits.next() {
                *channel = (*channel & 0xFE) | bit;
            }
        }
    }

    Ok(DynamicImage::ImageRgb8(img))
}

fn extract_payload_from_image(image: &DynamicImage) -> Result<Vec<u8>, StegoError> {
    let img = image.to_rgb8();
    let mut bits = img.pixels().flat_map(|pixel| {
        pixel.0.iter().map(|channel| channel & 1)
    });

    let mut len_bytes = [0u8; 4];
    for byte in &mut len_bytes {
        let mut value = 0u8;
        for _ in 0..8 {
            value = (value << 1) | bits.next().unwrap_or(0);
        }
        *byte = value;
    }

    let payload_len = u32::from_be_bytes(len_bytes) as usize;
    let mut payload = vec![0u8; payload_len];
    for byte in &mut payload {
        let mut value = 0u8;
        for _ in 0..8 {
            value = (value << 1) | bits.next().unwrap_or(0);
        }
        *byte = value;
    }

    Ok(payload)
}
