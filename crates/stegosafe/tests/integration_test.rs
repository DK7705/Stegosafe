use std::fs;
use std::path::PathBuf;

#[test]
fn embed_and_extract_round_trip() {
    // This test is simple and uses small in-repo files; adapt paths as needed.
    let cover = PathBuf::from("tests/fixtures/cover_small.png");
    let payload = PathBuf::from("tests/fixtures/payload.txt");
    let out = PathBuf::from("tests/fixtures/out.png");
    let secret = "test-secret";
    let context = "test-ctx";

    // Ensure fixtures exist
    assert!(cover.exists());
    assert!(payload.exists());

    // Run embed
    let status = std::process::Command::new("cargo")
        .args(["run", "-p", "stegosafe", "--", "embed", "--cover", cover.to_str().unwrap(), "--payload", payload.to_str().unwrap(), "--output", out.to_str().unwrap(), "--secret", secret, "--context", context])
        .status()
        .expect("failed to run embed command");

    assert!(status.success());

    // Read nonce from meta
    let meta = fs::read_to_string(out.with_extension("meta")).expect("read meta");
    let mut nonce_hex = None;
    for line in meta.lines() {
        if let Some(rest) = line.strip_prefix("nonce:") {
            nonce_hex = Some(rest.trim().to_string());
        }
    }
    let nonce_hex = nonce_hex.expect("nonce in metadata");

    // Run extract
    let recovered = PathBuf::from("tests/fixtures/recovered.bin");
    let status2 = std::process::Command::new("cargo")
        .args(["run", "-p", "stegosafe", "--", "extract", "--stego", out.to_str().unwrap(), "--output", recovered.to_str().unwrap(), "--secret", secret, "--context", context])
        .status()
        .expect("failed to run extract command");

    assert!(status2.success());

    // Cleanup
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(out.with_extension("meta"));
    let _ = fs::remove_file(recovered);
}
