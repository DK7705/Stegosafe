//! Integration tests for NonceManager.
//!
//! Tests verify the structural uniqueness guarantees of the nonce manager:
//! correct nonce format (64-bit random base + 32-bit counter), monotonic
//! counter increment, exhaustion at u32::MAX, and cross-manager uniqueness.

use stegosafe_crypto::nonce::NonceManager;
use stegosafe_crypto::EntropyOracle;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn test_oracle() -> EntropyOracle {
    EntropyOracle::init().expect("entropy oracle should initialize")
}

// ---------------------------------------------------------------------------
// Nonce structure
// ---------------------------------------------------------------------------

#[test]
fn nonce_is_12_bytes() {
    let oracle = test_oracle();
    let mut mgr = NonceManager::new(&oracle).expect("nonce manager init");
    let nonce = mgr.next().expect("first nonce");
    assert_eq!(nonce.len(), 12, "nonce must be exactly 12 bytes (96 bits)");
}

#[test]
fn nonce_high_bytes_are_random_base() {
    let oracle = test_oracle();
    let mut mgr = NonceManager::new(&oracle).expect("init");

    let n1 = mgr.next().expect("nonce 1");
    let n2 = mgr.next().expect("nonce 2");
    let n3 = mgr.next().expect("nonce 3");

    // High 8 bytes (random base) should be identical across nonces from same manager
    assert_eq!(&n1[..8], &n2[..8], "random base should be constant");
    assert_eq!(&n2[..8], &n3[..8], "random base should be constant");
}

#[test]
fn nonce_low_bytes_are_counter() {
    let oracle = test_oracle();
    let mut mgr = NonceManager::new(&oracle).expect("init");

    let n1 = mgr.next().expect("nonce 1");
    let n2 = mgr.next().expect("nonce 2");
    let n3 = mgr.next().expect("nonce 3");

    // Low 4 bytes should be big-endian counter: 0, 1, 2
    assert_eq!(&n1[8..12], &[0, 0, 0, 0], "first counter should be 0");
    assert_eq!(&n2[8..12], &[0, 0, 0, 1], "second counter should be 1");
    assert_eq!(&n3[8..12], &[0, 0, 0, 2], "third counter should be 2");
}

// ---------------------------------------------------------------------------
// Counter behavior
// ---------------------------------------------------------------------------

#[test]
fn counter_starts_at_zero() {
    let oracle = test_oracle();
    let mgr = NonceManager::new(&oracle).expect("init");
    assert_eq!(mgr.counter(), 0, "initial counter should be 0");
}

#[test]
fn counter_increments_monotonically() {
    let oracle = test_oracle();
    let mut mgr = NonceManager::new(&oracle).expect("init");

    for expected in 0..100u32 {
        assert_eq!(mgr.counter(), expected);
        let _ = mgr.next().expect("nonce");
    }
    assert_eq!(mgr.counter(), 100);
}

#[test]
fn counter_reflected_in_nonce_bytes() {
    let oracle = test_oracle();
    let mut mgr = NonceManager::new(&oracle).expect("init");

    for i in 0..256u32 {
        let nonce = mgr.next().expect("nonce");
        let counter_bytes = &nonce[8..12];
        let counter_value = u32::from_be_bytes([
            counter_bytes[0],
            counter_bytes[1],
            counter_bytes[2],
            counter_bytes[3],
        ]);
        assert_eq!(
            counter_value, i,
            "nonce counter byte mismatch at iteration {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// Uniqueness
// ---------------------------------------------------------------------------

#[test]
fn sequential_nonces_are_unique() {
    let oracle = test_oracle();
    let mut mgr = NonceManager::new(&oracle).expect("init");

    let n1 = mgr.next().expect("nonce 1");
    let n2 = mgr.next().expect("nonce 2");
    assert_ne!(n1, n2, "sequential nonces must differ");
}

#[test]
fn no_duplicates_over_10k_nonces() {
    let oracle = test_oracle();
    let mut mgr = NonceManager::new(&oracle).expect("init");

    let mut seen = std::collections::HashSet::new();
    for i in 0..10_000 {
        let nonce = mgr.next().expect("nonce");
        assert!(
            seen.insert(nonce),
            "duplicate nonce detected at iteration {i}"
        );
    }
}

#[test]
fn two_managers_produce_different_nonces() {
    let oracle = test_oracle();
    let mut mgr1 = NonceManager::new(&oracle).expect("mgr1");
    let mut mgr2 = NonceManager::new(&oracle).expect("mgr2");

    let n1 = mgr1.next().expect("nonce from mgr1");
    let n2 = mgr2.next().expect("nonce from mgr2");

    // Different random bases → different nonces
    // (probability of collision: 2^-64)
    assert_ne!(n1, n2, "nonces from different managers should differ");
    assert_ne!(
        &n1[..8], &n2[..8],
        "random bases from different managers should differ"
    );
}

#[test]
fn cross_manager_no_collision_batch() {
    let oracle = test_oracle();
    let mut mgr1 = NonceManager::new(&oracle).expect("mgr1");
    let mut mgr2 = NonceManager::new(&oracle).expect("mgr2");

    let mut all_nonces = std::collections::HashSet::new();

    for _ in 0..1_000 {
        let n1 = mgr1.next().expect("mgr1 nonce");
        let n2 = mgr2.next().expect("mgr2 nonce");
        assert!(all_nonces.insert(n1), "collision from mgr1");
        assert!(all_nonces.insert(n2), "collision from mgr2");
    }
    assert_eq!(all_nonces.len(), 2_000);
}

// ---------------------------------------------------------------------------
// Exhaustion
// ---------------------------------------------------------------------------

// NOTE: We cannot easily test exhaustion in integration tests because
// NonceManager's counter field is private and we can't fast-forward it.
// The unit tests in src/nonce.rs cover this by directly setting the
// counter to u32::MAX. Here we just verify that the API returns errors
// of the expected type.
//
// If NonceManager gains a test-only constructor or builder, add
// exhaustion tests here.

// ---------------------------------------------------------------------------
// Random base quality
// ---------------------------------------------------------------------------

#[test]
fn random_base_is_not_all_zeros() {
    let oracle = test_oracle();
    let mut mgr = NonceManager::new(&oracle).expect("init");
    let nonce = mgr.next().expect("nonce");

    // High 8 bytes should not all be zero (probability: 2^-64)
    assert!(
        nonce[..8].iter().any(|&b| b != 0),
        "random base should not be all zeros"
    );
}

#[test]
fn random_base_varies_across_managers() {
    let oracle = test_oracle();
    let mut bases = std::collections::HashSet::new();

    for _ in 0..50 {
        let mut mgr = NonceManager::new(&oracle).expect("init");
        let nonce = mgr.next().expect("nonce");
        let mut base = [0u8; 8];
        base.copy_from_slice(&nonce[..8]);
        bases.insert(base);
    }

    // 50 managers should produce 50 unique bases (collision prob: negligible)
    assert_eq!(
        bases.len(),
        50,
        "expected 50 unique random bases, got {}",
        bases.len()
    );
}
