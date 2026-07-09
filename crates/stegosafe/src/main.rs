use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use stegosafe_crypto::{derive_session_keys, EntropyOracle, HmacKey};
use stegosafe_stego::{StegoEngine, EmbedParams, EmbedParamsMeta, derive_placement_key};
use zeroize::Zeroizing;

const SESSION_NONCE_LEN: usize = 12;
const ARGON2_SALT_LEN: usize = 16;
const ROOT_KEY_LEN: usize = 32;
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const METADATA_VERSION: u8 = 1;
const KDF_ALGORITHM: &str = "argon2id-v1";

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
        #[arg(long, value_name = "PATH", conflicts_with = "secret")]
        secret_file: Option<PathBuf>,
        #[arg(long, hide = true)]
        secret: Option<String>,
        #[arg(long)]
        context: String,
    },
    Extract {
        #[arg(long)]
        stego: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_name = "PATH", conflicts_with = "secret")]
        secret_file: Option<PathBuf>,
        #[arg(long, hide = true)]
        secret: Option<String>,
        #[arg(long)]
        context: String,
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
    #[error("metadata error: {0}")]
    Metadata(&'static str),
    #[error("invalid hex field in metadata")]
    InvalidHex,
    #[error("missing secret input; provide --secret-file")]
    MissingSecret,
    #[error("secret input is invalid")]
    InvalidSecret,
    #[error("engine error: {0}")]
    Engine(#[from] stegosafe_stego::StegoError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Metadata {
    version: u8,
    session_nonce: String,
    kdf: KdfMetadata,
    embedding: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    embed_params: Option<EmbedParamsMeta>,
    encrypted_len: usize,
    mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfMetadata {
    algorithm: String,
    salt: String,
    memory_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
    output_len: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Embed {
            cover,
            payload,
            output,
            secret_file,
            secret,
            context,
        } => embed(&cover, &payload, &output, secret_file.as_deref(), secret.as_deref(), &context),
        Commands::Extract {
            stego,
            output,
            secret_file,
            secret,
            context,
        } => extract(&stego, &output, secret_file.as_deref(), secret.as_deref(), &context),
    }
}

fn embed(
    cover_path: &Path,
    payload_path: &Path,
    output_path: &Path,
    secret_file: Option<&Path>,
    deprecated_secret: Option<&str>,
    context: &str,
) -> Result<()> {
    let entropy = EntropyOracle::init().context("failed to initialize entropy oracle")?;
    let secret = load_secret(secret_file, deprecated_secret)?;
    let session_nonce = generate_session_nonce(&entropy)?;
    let kdf = generate_kdf_metadata(&entropy)?;
    let root_key = derive_root_key(&secret, &kdf).context("failed to derive root key")?;
    let keys = derive_session_keys(&*root_key, &session_nonce, &entropy)
        .context("failed to derive session keys")?;

    let payload = fs::read(payload_path).context("failed to read payload")?;
    let encrypted = keys.enc_key.encrypt(&payload, context.as_bytes())
        .context("payload encryption failed")?;

    let cover = image::open(cover_path).context("failed to open cover image")?;

    let engine = StegoEngine::new();
    let (stego, embed_result) = engine.embed(
        &cover, &encrypted, &*keys.technique_seed, &*keys.param_seed
    ).context("failed to embed payload into cover image")?;

    let mut metadata = Metadata {
        version: METADATA_VERSION,
        session_nonce: hex::encode(session_nonce),
        kdf,
        embedding: embed_result.technique_name,
        embed_params: Some(embed_result.params_meta),
        encrypted_len: encrypted.len(),
        mac: String::new(),
    };
    metadata.mac = hex::encode(metadata_mac(&keys.mac_key, &metadata, context, &encrypted)?);

    stego.save(output_path).context("failed to save stego image")?;
    fs::write(output_path.with_extension("meta"), serde_json::to_vec_pretty(&metadata)?)
        .context("failed to write metadata file")?;

    println!("Embedded payload successfully");
    Ok(())
}

fn extract(
    stego_path: &Path,
    output_path: &Path,
    secret_file: Option<&Path>,
    deprecated_secret: Option<&str>,
    context: &str,
) -> Result<()> {
    let entropy = EntropyOracle::init().context("failed to initialize entropy oracle")?;
    let metadata = read_metadata(&stego_path.with_extension("meta"))?;
    validate_metadata(&metadata)?;

    let secret = load_secret(secret_file, deprecated_secret)?;
    let root_key = derive_root_key(&secret, &metadata.kdf).context("failed to derive root key")?;
    let session_nonce = parse_session_nonce(&metadata.session_nonce)?;
    let keys = derive_session_keys(&*root_key, &session_nonce, &entropy)
        .context("failed to derive session keys")?;

    let embed_params = if let Some(ref meta_params) = metadata.embed_params {
        let placement_key = derive_placement_key(&*keys.param_seed);
        EmbedParams::from_meta(meta_params, placement_key)
            .ok_or_else(|| anyhow::anyhow!("invalid embed params in metadata"))?
    } else {
        // Legacy metadata without embed_params — use mac_key for placement
        EmbedParams::legacy(*keys.mac_key.as_bytes())
    };

    let engine = StegoEngine::new();
    let stego = image::open(stego_path).context("failed to open stego image")?;
    let payload = engine.extract(
        &stego, &metadata.embedding, &embed_params, metadata.encrypted_len
    ).context("failed to extract payload from stego image")?;

    let expected_mac = hex::decode(&metadata.mac).map_err(|_| StegoError::InvalidHex)?;
    keys.mac_key
        .verify(&metadata_mac_input(&metadata, context, &payload), &expected_mac)
        .context("metadata authentication failed")?;

    let plaintext = keys.enc_key.decrypt(&payload, context.as_bytes())
        .context("payload decryption failed")?;

    fs::write(output_path, &plaintext).context("failed to write extracted payload")?;
    println!("Extraction succeeded");
    Ok(())
}

fn load_secret(secret_file: Option<&Path>, deprecated_secret: Option<&str>) -> Result<Zeroizing<Vec<u8>>, StegoError> {
    if let Some(secret) = deprecated_secret {
        eprintln!("warning: --secret exposes sensitive data through process arguments; use --secret-file");
        if secret.is_empty() {
            return Err(StegoError::InvalidSecret);
        }
        return Ok(Zeroizing::new(secret.as_bytes().to_vec()));
    }

    let path = secret_file.ok_or(StegoError::MissingSecret)?;
    let mut secret = fs::read(path)?;
    trim_single_trailing_newline(&mut secret);
    if secret.is_empty() {
        return Err(StegoError::InvalidSecret);
    }
    Ok(Zeroizing::new(secret))
}

fn trim_single_trailing_newline(secret: &mut Vec<u8>) {
    if secret.last() == Some(&b'\n') {
        secret.pop();
        if secret.last() == Some(&b'\r') {
            secret.pop();
        }
    }
}

fn generate_kdf_metadata(entropy: &EntropyOracle) -> Result<KdfMetadata, StegoError> {
    let mut salt = [0u8; ARGON2_SALT_LEN];
    entropy.fill(&mut salt)?;
    Ok(KdfMetadata {
        algorithm: KDF_ALGORITHM.to_string(),
        salt: hex::encode(salt),
        memory_cost_kib: ARGON2_MEMORY_KIB,
        time_cost: ARGON2_TIME_COST,
        parallelism: ARGON2_PARALLELISM,
        output_len: ROOT_KEY_LEN,
    })
}

fn derive_root_key(secret: &[u8], kdf: &KdfMetadata) -> Result<Zeroizing<[u8; ROOT_KEY_LEN]>, StegoError> {
    if kdf.algorithm != KDF_ALGORITHM || kdf.output_len != ROOT_KEY_LEN {
        return Err(StegoError::Metadata("unsupported KDF metadata"));
    }

    let salt = hex::decode(&kdf.salt).map_err(|_| StegoError::InvalidHex)?;
    if salt.len() != ARGON2_SALT_LEN {
        return Err(StegoError::Metadata("invalid KDF salt length"));
    }

    let params = Params::new(
        kdf.memory_cost_kib,
        kdf.time_cost,
        kdf.parallelism,
        Some(kdf.output_len),
    )
    .map_err(|_| StegoError::Metadata("invalid Argon2 parameters"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut root = Zeroizing::new([0u8; ROOT_KEY_LEN]);
    argon2
        .hash_password_into(secret, &salt, &mut root[..])
        .map_err(|_| StegoError::InvalidSecret)?;
    Ok(root)
}

fn read_metadata(path: &Path) -> Result<Metadata> {
    let bytes = fs::read(path).context("failed to read metadata file")?;
    serde_json::from_slice(&bytes).context("failed to parse metadata file")
}

fn validate_metadata(metadata: &Metadata) -> Result<(), StegoError> {
    if metadata.version != METADATA_VERSION {
        return Err(StegoError::Metadata("unsupported metadata version"));
    }
    if metadata.mac.is_empty() {
        return Err(StegoError::Metadata("missing metadata MAC"));
    }
    if metadata.encrypted_len == 0 {
        return Err(StegoError::Metadata("missing encrypted payload length"));
    }
    Ok(())
}

fn metadata_mac(key: &HmacKey, metadata: &Metadata, context: &str, payload: &[u8]) -> Result<[u8; 32], StegoError> {
    key.sign(&metadata_mac_input(metadata, context, payload))
        .map_err(StegoError::Crypto)
}

fn metadata_mac_input(metadata: &Metadata, context: &str, payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(b"stegosafe-metadata-v1\n");
    input.extend_from_slice(format!("version:{}\n", metadata.version).as_bytes());
    input.extend_from_slice(format!("session_nonce:{}\n", metadata.session_nonce).as_bytes());
    input.extend_from_slice(format!("kdf_algorithm:{}\n", metadata.kdf.algorithm).as_bytes());
    input.extend_from_slice(format!("kdf_salt:{}\n", metadata.kdf.salt).as_bytes());
    input.extend_from_slice(format!("kdf_memory_cost_kib:{}\n", metadata.kdf.memory_cost_kib).as_bytes());
    input.extend_from_slice(format!("kdf_time_cost:{}\n", metadata.kdf.time_cost).as_bytes());
    input.extend_from_slice(format!("kdf_parallelism:{}\n", metadata.kdf.parallelism).as_bytes());
    input.extend_from_slice(format!("kdf_output_len:{}\n", metadata.kdf.output_len).as_bytes());
    input.extend_from_slice(format!("embedding:{}\n", metadata.embedding).as_bytes());
    if let Some(ref params) = metadata.embed_params {
        input.extend_from_slice(format!("embed_channels:{}\n", params.channels).as_bytes());
        input.extend_from_slice(format!("embed_bit_plane:{}\n", params.bit_plane).as_bytes());
    }
    input.extend_from_slice(format!("encrypted_len:{}\n", metadata.encrypted_len).as_bytes());
    input.extend_from_slice(format!("context:{}\n", context).as_bytes());
    input.extend_from_slice(b"payload:\n");
    input.extend_from_slice(payload);
    input
}

fn generate_session_nonce(entropy: &EntropyOracle) -> Result<[u8; SESSION_NONCE_LEN]> {
    let mut nonce = [0u8; SESSION_NONCE_LEN];
    entropy.fill(&mut nonce).context("failed to generate session nonce")?;
    if nonce.iter().all(|&b| b == 0) {
        return Err(StegoError::Metadata("generated all-zero session nonce").into());
    }
    Ok(nonce)
}

fn parse_session_nonce(hex_str: &str) -> Result<[u8; SESSION_NONCE_LEN], StegoError> {
    let bytes = hex::decode(hex_str).map_err(|_| StegoError::InvalidHex)?;
    if bytes.len() != SESSION_NONCE_LEN {
        return Err(StegoError::Metadata("invalid session nonce length"));
    }
    let mut nonce = [0u8; SESSION_NONCE_LEN];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_one_trailing_newline() {
        let mut secret = b"secret\r\n".to_vec();
        trim_single_trailing_newline(&mut secret);
        assert_eq!(secret, b"secret");
    }
}
