//! Hardware-seeded entropy oracle.
//!
//! Single source of truth for all randomness in the system. Nothing calls
//! OS random or `rand::thread_rng()` directly — everything goes through
//! [`EntropyOracle`].
//!
//! # Source hierarchy
//!
//! 1. **OS entropy pool** — `getrandom` (`BCryptGenRandom` on Windows, `/dev/urandom` on Linux).
//! 2. **Hardware TRNG** — optional `rdrand` on x86_64, verified with a startup health check.
//! 3. **Application-level mixing** — XOR of TRNG and OS bytes when TRNG is available,
//!    conditioned through SHA-256.

use std::sync::Mutex;

use sha2::{Sha256, Digest};

use crate::error::CryptoError;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Health status of the entropy oracle.
///
/// Use [`EntropyOracle::health`] to query at any time for monitoring integration.
#[derive(Debug, Clone)]
pub struct EntropyHealth {
    /// Whether hardware TRNG (e.g., x86 RDRAND) is available.
    pub trng_available: bool,
    /// Whether the OS entropy pool is available.
    pub os_pool_available: bool,
    /// Whether the last periodic health check passed (NIST SP 800-22 monobit).
    pub last_check_passed: bool,
    /// Total bytes generated since oracle initialization.
    pub bytes_generated: u64,
}

/// Internal mutable state protected by mutex.
struct OracleState {
    trng_available: bool,
    bytes_generated: u64,
    last_check_passed: bool,
    bytes_since_last_check: u64,
}

/// Single source of truth for all randomness in the system.
///
/// Uses the OS entropy pool as the mandatory baseline, optionally mixing
/// hardware TRNG output when it is available, then conditioning the result
/// through SHA-256.
///
/// # Thread safety
///
/// `EntropyOracle` is `Send + Sync`. Internal mutable state (byte counters,
/// health status) is protected by a `Mutex`.
///
/// # Health checks
///
/// The NIST SP 800-22 monobit test runs at initialization and every 10,000
/// bytes generated. Failures are fail-open: a warning is recorded in the
/// health status but entropy generation continues.
pub struct EntropyOracle {
    os_pool_available: bool,
    state: Mutex<OracleState>,
}

impl EntropyOracle {
    /// Initialize the entropy oracle, running startup health checks.
    ///
    /// Returns [`CryptoError::EntropyUnavailable`] if the OS entropy pool is
    /// unavailable. Hardware TRNG is supplemental and never replaces the OS pool.
    pub fn init() -> Result<Self, CryptoError> {
        let trng_available = Self::check_trng_available();
        let os_pool_available = Self::check_os_pool();

        if !os_pool_available {
            return Err(CryptoError::EntropyUnavailable);
        }

        let oracle = Self {
            os_pool_available,
            state: Mutex::new(OracleState {
                trng_available,
                bytes_generated: 0,
                last_check_passed: true,
                bytes_since_last_check: 0,
            }),
        };

        // Run initial health check on a 1 KB sample
        let mut sample = vec![0u8; 1024];
        oracle.fill_raw(&mut sample)?;
        let check_passed = Self::monobit_test(&sample);

        {
            let mut state = oracle.state.lock()
                .map_err(|_| CryptoError::EntropyUnavailable)?;
            state.last_check_passed = check_passed;
        }

        Ok(oracle)
    }

    /// Fill `buf` with cryptographically random bytes.
    ///
    /// Bytes are produced by XOR-mixing TRNG and OS entropy, then
    /// conditioning through SHA-256 in counter mode.
    pub fn fill(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        if buf.is_empty() {
            return Ok(());
        }

        // Generate raw mixed entropy
        let mut raw = vec![0u8; buf.len()];
        self.fill_raw(&mut raw)?;

        // Condition through SHA-256 in counter mode
        Self::condition(&raw, buf);

        // Zeroize raw buffer
        for b in raw.iter_mut() {
            *b = 0;
        }

        // Update counter and maybe run periodic health check
        self.update_counter_and_check(buf.len() as u64)?;

        Ok(())
    }

    /// Convenience: return `n` random bytes as a new `Vec`.
    pub fn bytes(&self, n: usize) -> Result<Vec<u8>, CryptoError> {
        let mut buf = vec![0u8; n];
        self.fill(&mut buf)?;
        Ok(buf)
    }

    /// Return a 32-byte seed suitable for seeding a CSPRNG.
    pub fn seed32(&self) -> Result<[u8; 32], CryptoError> {
        let mut seed = [0u8; 32];
        self.fill(&mut seed)?;
        Ok(seed)
    }

    /// Report health status for monitoring integration.
    pub fn health(&self) -> EntropyHealth {
        let state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => {
                return EntropyHealth {
                    trng_available: false,
                    os_pool_available: self.os_pool_available,
                    last_check_passed: false,
                    bytes_generated: 0,
                };
            }
        };

        EntropyHealth {
            trng_available: state.trng_available,
            os_pool_available: self.os_pool_available,
            last_check_passed: state.last_check_passed,
            bytes_generated: state.bytes_generated,
        }
    }

    // -----------------------------------------------------------------------
    // Internal: raw entropy generation
    // -----------------------------------------------------------------------

    /// Fill buffer with raw mixed entropy (TRNG XOR OS, or OS-only).
    fn fill_raw(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        // Always get OS entropy as the baseline
        getrandom::getrandom(buf)
            .map_err(|_| CryptoError::EntropyUnavailable)?;

        // Try to mix in TRNG if available
        let trng_available = self.state.lock()
            .map_err(|_| CryptoError::EntropyUnavailable)?
            .trng_available;

        if trng_available {
            let mut trng_buf = vec![0u8; buf.len()];
            if Self::fill_trng(&mut trng_buf) {
                // XOR TRNG output into OS bytes
                for (dst, src) in buf.iter_mut().zip(trng_buf.iter()) {
                    *dst ^= *src;
                }
            }
            // Zeroize TRNG buffer
            for b in trng_buf.iter_mut() {
                *b = 0;
            }
        }

        Ok(())
    }

    /// Condition raw entropy through SHA-256 in counter mode.
    ///
    /// For each 32-byte block of output, compute `SHA-256(counter ‖ input)`.
    /// This ensures uniform distribution even if the raw source has minor biases.
    fn condition(input: &[u8], output: &mut [u8]) {
        let mut offset = 0;
        let mut counter: u64 = 0;

        while offset < output.len() {
            let mut hasher = Sha256::new();
            hasher.update(counter.to_le_bytes());
            hasher.update(input);
            let hash = hasher.finalize();

            let remaining = output.len() - offset;
            let chunk_len = if remaining < 32 { remaining } else { 32 };
            output[offset..offset + chunk_len].copy_from_slice(&hash[..chunk_len]);

            offset += chunk_len;
            counter += 1;
        }
    }

    /// Update byte counter and run periodic health check every 10k bytes.
    fn update_counter_and_check(&self, bytes: u64) -> Result<(), CryptoError> {
        let should_check = {
            let mut state = self.state.lock()
                .map_err(|_| CryptoError::EntropyUnavailable)?;
            state.bytes_generated = state.bytes_generated.saturating_add(bytes);
            state.bytes_since_last_check = state.bytes_since_last_check.saturating_add(bytes);

            if state.bytes_since_last_check >= 10_000 {
                state.bytes_since_last_check = 0;
                true
            } else {
                false
            }
        };

        if should_check {
            let mut sample = vec![0u8; 1024];
            self.fill_raw(&mut sample)?;
            let passed = Self::monobit_test(&sample);

            let mut state = self.state.lock()
                .map_err(|_| CryptoError::EntropyUnavailable)?;
            state.last_check_passed = passed;
            // Fail-open: record the result but never crash a transmission
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: health checks
    // -----------------------------------------------------------------------

    /// NIST SP 800-22 monobit test on a byte sample.
    ///
    /// Counts the number of 1-bits and checks that the proportion is within
    /// the 99% confidence interval of a fair coin (z < 2.576).
    fn monobit_test(data: &[u8]) -> bool {
        let ones: u32 = data.iter().map(|b| b.count_ones()).sum();
        let n = (data.len() * 8) as f64;
        let expected = n / 2.0;
        let stddev = (n / 4.0).sqrt();
        if stddev == 0.0 {
            return false;
        }
        let z = (ones as f64 - expected).abs() / stddev;
        z < 2.576
    }

    /// Check if OS entropy pool is available.
    fn check_os_pool() -> bool {
        let mut test = [0u8; 8];
        getrandom::getrandom(&mut test).is_ok()
    }

    // -----------------------------------------------------------------------
    // Internal: TRNG (platform-specific)
    // -----------------------------------------------------------------------

    /// Check if hardware TRNG is available and passes the FIPS 140-3
    /// startup health check (3 consecutive reads must not all be identical).
    #[cfg(target_arch = "x86_64")]
    fn check_trng_available() -> bool {
        let mut rng = match rdrand::RdRand::new() {
            Ok(rng) => rng,
            Err(_) => return false,
        };

        // FIPS 140-3 health check: 3 consecutive 64-bit reads must not
        // all be identical (stuck-at detection).
        let v1 = match rng.try_next_u64() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let v2 = match rng.try_next_u64() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let v3 = match rng.try_next_u64() {
            Ok(v) => v,
            Err(_) => return false,
        };

        !(v1 == v2 && v2 == v3)
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn check_trng_available() -> bool {
        // No hardware TRNG support on this architecture.
        // Future: add AArch64 RNDR support.
        false
    }

    /// Fill buffer from hardware TRNG in 8-byte chunks.
    #[cfg(target_arch = "x86_64")]
    fn fill_trng(buf: &mut [u8]) -> bool {
        let mut rng = match rdrand::RdRand::new() {
            Ok(rng) => rng,
            Err(_) => return false,
        };

        let mut offset = 0;

        // Fill in 8-byte (u64) chunks
        while offset + 8 <= buf.len() {
            match rng.try_next_u64() {
                Ok(val) => {
                    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
                    offset += 8;
                }
                Err(_) => return false,
            }
        }

        // Handle remaining bytes (< 8)
        if offset < buf.len() {
            match rng.try_next_u64() {
                Ok(val) => {
                    let bytes = val.to_le_bytes();
                    let remaining = buf.len() - offset;
                    buf[offset..].copy_from_slice(&bytes[..remaining]);
                }
                Err(_) => return false,
            }
        }

        true
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn fill_trng(_buf: &mut [u8]) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_initializes() {
        let oracle = EntropyOracle::init()
            .expect("entropy oracle should initialize on real hardware");
        let health = oracle.health();
        assert!(health.os_pool_available);
    }

    #[test]
    fn fill_produces_nonzero_output() {
        let oracle = EntropyOracle::init()
            .expect("entropy oracle init");
        let mut buf = [0u8; 64];
        oracle.fill(&mut buf).expect("fill should succeed");
        // Probability of all zeros from 64 random bytes: 2^-512
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn bytes_returns_correct_length() {
        let oracle = EntropyOracle::init()
            .expect("entropy oracle init");
        for n in [0, 1, 16, 32, 64, 128, 256, 1024] {
            let result = oracle.bytes(n).expect("bytes should succeed");
            assert_eq!(result.len(), n);
        }
    }

    #[test]
    fn seed32_returns_32_bytes() {
        let oracle = EntropyOracle::init()
            .expect("entropy oracle init");
        let seed = oracle.seed32().expect("seed32 should succeed");
        assert_eq!(seed.len(), 32);
        // Should not be all zeros
        assert!(seed.iter().any(|&b| b != 0));
    }

    #[test]
    fn two_fills_produce_different_output() {
        let oracle = EntropyOracle::init()
            .expect("entropy oracle init");
        let a = oracle.bytes(32).expect("bytes");
        let b = oracle.bytes(32).expect("bytes");
        // Probability of collision: 2^-256
        assert_ne!(a, b);
    }

    #[test]
    fn monobit_test_passes_on_random_data() {
        let oracle = EntropyOracle::init()
            .expect("entropy oracle init");
        let mut sample = vec![0u8; 1024];
        oracle.fill(&mut sample).expect("fill");
        assert!(EntropyOracle::monobit_test(&sample));
    }

    #[test]
    fn monobit_test_fails_on_constant_data() {
        // All ones — should fail monobit (all bits are 1)
        let all_ones = vec![0xFFu8; 1024];
        assert!(!EntropyOracle::monobit_test(&all_ones));

        // All zeros — should fail monobit (all bits are 0)
        let all_zeros = vec![0x00u8; 1024];
        assert!(!EntropyOracle::monobit_test(&all_zeros));
    }

    #[test]
    fn health_reports_os_pool() {
        let oracle = EntropyOracle::init()
            .expect("entropy oracle init");
        let health = oracle.health();
        assert!(health.os_pool_available);
        assert!(health.last_check_passed);
    }

    #[test]
    fn empty_fill_is_noop() {
        let oracle = EntropyOracle::init()
            .expect("entropy oracle init");
        let mut buf = [];
        oracle.fill(&mut buf).expect("empty fill should succeed");
    }
}
