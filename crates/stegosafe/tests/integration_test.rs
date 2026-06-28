use std::fs;
use std::process::Command;

use image::{ImageBuffer, Rgb};

fn write_cover(path: &std::path::Path) {
    let img = ImageBuffer::from_fn(128, 128, |x, y| {
        Rgb([
            (x % 251) as u8,
            (y % 251) as u8,
            ((x + y) % 251) as u8,
        ])
    });
    img.save(path).expect("write cover image");
}

#[test]
fn embed_and_extract_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cover = dir.path().join("cover.png");
    let payload = dir.path().join("payload.txt");
    let secret = dir.path().join("secret.txt");
    let out = dir.path().join("out.png");
    let recovered = dir.path().join("recovered.bin");

    write_cover(&cover);
    fs::write(&payload, b"payload data").expect("write payload");
    fs::write(&secret, b"test passphrase\n").expect("write secret");

    let embed_status = Command::new(env!("CARGO_BIN_EXE_stegosafe"))
        .args([
            "embed",
            "--cover",
            cover.to_str().expect("cover path"),
            "--payload",
            payload.to_str().expect("payload path"),
            "--output",
            out.to_str().expect("output path"),
            "--secret-file",
            secret.to_str().expect("secret path"),
            "--context",
            "test-ctx",
        ])
        .status()
        .expect("run embed command");
    assert!(embed_status.success());

    let extract_status = Command::new(env!("CARGO_BIN_EXE_stegosafe"))
        .args([
            "extract",
            "--stego",
            out.to_str().expect("stego path"),
            "--output",
            recovered.to_str().expect("recovered path"),
            "--secret-file",
            secret.to_str().expect("secret path"),
            "--context",
            "test-ctx",
        ])
        .status()
        .expect("run extract command");
    assert!(extract_status.success());

    assert_eq!(fs::read(recovered).expect("read recovered"), b"payload data");
}

#[test]
fn extraction_fails_when_metadata_mac_is_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cover = dir.path().join("cover.png");
    let payload = dir.path().join("payload.txt");
    let secret = dir.path().join("secret.txt");
    let out = dir.path().join("out.png");
    let recovered = dir.path().join("recovered.bin");

    write_cover(&cover);
    fs::write(&payload, b"payload data").expect("write payload");
    fs::write(&secret, b"test passphrase\n").expect("write secret");

    let embed_status = Command::new(env!("CARGO_BIN_EXE_stegosafe"))
        .args([
            "embed",
            "--cover",
            cover.to_str().expect("cover path"),
            "--payload",
            payload.to_str().expect("payload path"),
            "--output",
            out.to_str().expect("output path"),
            "--secret-file",
            secret.to_str().expect("secret path"),
            "--context",
            "test-ctx",
        ])
        .status()
        .expect("run embed command");
    assert!(embed_status.success());

    let meta_path = out.with_extension("meta");
    let mut meta: serde_json::Value =
        serde_json::from_slice(&fs::read(&meta_path).expect("read metadata")).expect("parse metadata");
    meta["mac"] = serde_json::Value::String(String::new());
    fs::write(&meta_path, serde_json::to_vec_pretty(&meta).expect("serialize metadata"))
        .expect("tamper metadata");

    let extract_status = Command::new(env!("CARGO_BIN_EXE_stegosafe"))
        .args([
            "extract",
            "--stego",
            out.to_str().expect("stego path"),
            "--output",
            recovered.to_str().expect("recovered path"),
            "--secret-file",
            secret.to_str().expect("secret path"),
            "--context",
            "test-ctx",
        ])
        .status()
        .expect("run extract command");
    assert!(!extract_status.success());
}
