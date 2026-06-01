//! Integration tests for EntropyOracle.
//!
//! These tests verify the public API of the entropy oracle: initialization,
//! byte generation, health reporting, and basic statistical properties.
//! Since entropy is non-deterministic, tests focus on structural properties
//! rather than exact output values.

use stegosafe_crypto::{EntropyOracle, EntropyHealth};

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

#[test]
fn entropy_oracle_initializes() {
    let oracle = EntropyOracle::init().expect("should initialize on real hardware");
    let health = oracle.health();
    assert!(health.os_pool_available, "OS entropy pool must be available");
    assert!(health.last_check_passed, "initial health check should pass");
}

// ---------------------------------------------------------------------------
// Byte generation
// ---------------------------------------------------------------------------

#[test]
fn fill_produces_nonzero_bytes() {
    let oracle = EntropyOracle::init().expect("init");
    let mut buf = [0u8; 64];
    oracle.fill(&mut buf).expect("fill");
    // Probability of all zeros from 64 random bytes: 2^-512
    assert!(buf.iter().any(|&b| b != 0), "64 random bytes should not all be zero");
}

#[test]
fn fill_empty_buffer_is_noop() {
    let oracle = EntropyOracle::init().expect("init");
    let mut buf = [];
    oracle.fill(&mut buf).expect("empty fill should succeed");
}

#[test]
fn bytes_returns_correct_lengths() {
    let oracle = EntropyOracle::init().expect("init");
    for &n in &[0, 1, 7, 16, 31, 32, 33, 64, 128, 255, 512, 1024] {
        let result = oracle.bytes(n).expect("bytes");
        assert_eq!(result.len(), n, "requested {n} bytes, got {}", result.len());
    }
}

#[test]
fn seed32_returns_32_bytes() {
    let oracle = EntropyOracle::init().expect("init");
    let seed = oracle.seed32().expect("seed32");
    assert_eq!(seed.len(), 32);
    assert!(seed.iter().any(|&b| b != 0), "seed should not be all zeros");
}

// ---------------------------------------------------------------------------
// Uniqueness
// ---------------------------------------------------------------------------

#[test]
fn two_fills_produce_different_output() {
    let oracle = EntropyOracle::init().expect("init");
    let a = oracle.bytes(32).expect("bytes a");
    let b = oracle.bytes(32).expect("bytes b");
    // Probability of collision: 2^-256
    assert_ne!(a, b, "two 32-byte fills should differ");
}

#[test]
fn many_seeds_are_unique() {
    let oracle = EntropyOracle::init().expect("init");
    let mut seeds: Vec<[u8; 32]> = Vec::with_capacity(100);
    for _ in 0..100 {
        let seed = oracle.seed32().expect("seed32");
        assert!(
            !seeds.contains(&seed),
            "duplicate seed detected among 100 samples"
        );
        seeds.push(seed);
    }
}

// ---------------------------------------------------------------------------
// Health reporting
// ---------------------------------------------------------------------------

#[test]
fn health_reports_os_pool_available() {
    let oracle = EntropyOracle::init().expect("init");
    let health = oracle.health();
    assert!(health.os_pool_available);
}

#[test]
fn health_check_passes_initially() {
    let oracle = EntropyOracle::init().expect("init");
    let health = oracle.health();
    assert!(health.last_check_passed, "initial monobit check should pass");
}

#[test]
fn bytes_generated_counter_increases() {
    let oracle = EntropyOracle::init().expect("init");
    let health_before = oracle.health();
    let initial = health_before.bytes_generated;

    // Generate 256 bytes
    let _ = oracle.bytes(256).expect("bytes");

    let health_after = oracle.health();
    assert!(
        health_after.bytes_generated > initial,
        "bytes_generated should increase: before={initial}, after={}",
        health_after.bytes_generated
    );
}

// ---------------------------------------------------------------------------
// Statistical properties (basic sanity checks)
// ---------------------------------------------------------------------------

#[test]
fn output_has_reasonable_entropy() {
    let oracle = EntropyOracle::init().expect("init");
    let sample = oracle.bytes(1024).expect("1KB sample");

    // Count unique byte values — good RNG should produce many distinct values
    let mut seen = [false; 256];
    for &b in &sample {
        seen[b as usize] = true;
    }
    let unique_count = seen.iter().filter(|&&s| s).count();

    // With 1024 random bytes, we should see at least 200 unique byte values
    // (expected ≈ 256 * (1 - (255/256)^1024) ≈ 254)
    assert!(
        unique_count >= 200,
        "expected at least 200 unique byte values in 1KB, got {unique_count}"
    );
}

#[test]
fn output_monobit_balance() {
    let oracle = EntropyOracle::init().expect("init");
    let sample = oracle.bytes(1024).expect("1KB sample");

    // Count 1-bits
    let ones: u32 = sample.iter().map(|b| b.count_ones()).sum();
    let total_bits = (sample.len() * 8) as f64;
    let ratio = ones as f64 / total_bits;

    // Should be within 45%-55% for truly random data
    assert!(
        (0.45..=0.55).contains(&ratio),
        "monobit ratio {ratio:.4} is outside [0.45, 0.55] — possible entropy issue"
    );
}

#[test]
fn different_oracles_produce_different_output() {
    let oracle1 = EntropyOracle::init().expect("init 1");
    let oracle2 = EntropyOracle::init().expect("init 2");

    let a = oracle1.bytes(32).expect("bytes from oracle1");
    let b = oracle2.bytes(32).expect("bytes from oracle2");

    assert_ne!(a, b, "independent oracles should produce different output");
}
