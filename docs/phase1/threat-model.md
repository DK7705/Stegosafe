# Threat Model — `stegosafe-crypto` (Phase 1)

> **Document version:** 1.0  
> **Crate version:** 0.1.0  
> **Last updated:** 2026-06-01  
> **Status:** Living document — update on every crypto-relevant change

---

## 1. System Overview

`stegosafe-crypto` provides the cryptographic foundation for the Stegosafe
adaptive steganography tool. It exposes:

| Primitive | Implementation | Module |
|---|---|---|
| Authenticated encryption | AES-256-GCM + Zstandard compression | `aead.rs` |
| Key derivation | HKDF-SHA-256 with domain separation | `kdf.rs` |
| Message authentication | HMAC-SHA-256 | `kdf.rs` |
| Entropy | Hardware TRNG (RDRAND) ⊕ OS pool, SHA-256 conditioned | `entropy.rs` |
| Nonce management | 64-bit random base + 32-bit counter | `nonce.rs` |

All key material is wrapped in `Zeroizing<>` and cleared on drop.
The crate enforces `#![forbid(clippy::unwrap_used)]` and `#![forbid(unsafe_code)]`.

---

## 2. Adversary Model

### 2.1 Passive Steganalyst

**Goal:** Detect the presence of hidden data in a cover medium.

| Attack vector | Risk | Mitigation |
|---|---|---|
| Statistical analysis of pixel distributions | High | Zstandard compression before encryption maximises ciphertext entropy, making it indistinguishable from noise (Phase 3/4 embedding responsibility) |
| Ciphertext length correlation | Medium | Compression normalises payload size; AAD binding prevents cross-session length correlation |
| Known-plaintext header detection | Low | No plaintext headers in output — format is `nonce ‖ ciphertext ‖ tag` only |

### 2.2 Active Attacker (Network Position)

**Goal:** Tamper with, replay, or forge stego payloads.

| Attack vector | Risk | Mitigation |
|---|---|---|
| Ciphertext modification | High | AES-256-GCM tag (128-bit) detects any tampering; single opaque `DecryptionFailed` error prevents error oracles |
| Cut-and-paste (ciphertext transplant) | High | Mandatory AAD parameter binds ciphertext to session context — transplanted ciphertext fails authentication |
| Replay attack | Medium | Session nonce in HKDF salt ensures distinct key material per session; AAD should include timestamps (caller responsibility) |
| Nonce manipulation | Low | Nonce is generated server-side via `NonceManager`, never accepted from external input |

### 2.3 Compromised Endpoint

**Goal:** Extract key material from a running or terminated process.

| Attack vector | Risk | Mitigation |
|---|---|---|
| Memory dump (live) | Critical | `Zeroizing<[u8; 32]>` wraps all key material; `NonceManager::drop` zeroizes base and counter |
| Memory dump (post-process) | High | `Zeroizing` clears on drop; raw derivation buffers are explicitly zeroized in `derive_session_keys` |
| Core dump / swap file | Medium | Caller should `mlock` pages and disable core dumps (OS-level — outside crate scope) |
| Debug builds leaking secrets in logs | Low | `#![forbid(clippy::unwrap_used)]` prevents accidental `Debug` formatting of key material; key types do not implement `Debug` |

---

## 3. Key Compromise Scenarios

### 3.1 Scenario Matrix

| Scenario | Impact | Detection | Recovery |
|---|---|---|---|
| Shared secret leaked before derivation | Full session compromise | Out-of-band (key exchange layer, Phase 5) | Re-establish key exchange; revoke compromised secret |
| Derived `enc_key` leaked | All messages in that session decryptable | Cannot detect purely at crypto layer | Rekey immediately (new `derive_session_keys` call) |
| Derived `mac_key` leaked | Cover image integrity forgeable | HMAC verification still passes for attacker-forged images | Rekey; re-verify cover images with new key |
| `technique_seed` / `param_seed` leaked | Embedding algorithm predictable to adversary | Steganalysis success rate increases | Rekey; re-embed with fresh seeds |
| Entropy source compromised | All keys derived after compromise are predictable | Periodic monobit test may catch TRNG stuck-at; OS pool compromise is silent | Restart with fresh entropy; investigate TRNG/OS |

### 3.2 Mitigations (Defence in Depth)

1. **Domain-separated derivation:** Compromise of one derived key does not reveal others (HKDF with distinct `info` strings: `stego-v1-enc`, `stego-v1-mac`, `stego-v1-technique`, `stego-v1-params`).
2. **Key exhaustion limit:** `NonceManager` returns `KeyExhausted` at `u32::MAX` (≈ 4.29 × 10⁹) encryptions, forcing rekey before nonce space is exhausted.
3. **Zeroization:** All `[u8; 32]` key arrays and `NonceManager` state are zeroized on drop. Intermediate derivation buffers in `derive_session_keys` are explicitly zeroized after use.
4. **No key serialisation:** Keys cannot be serialised or cloned (`AeadKey`, `HmacKey`, `NonceManager` do not implement `Serialize`, `Clone`, or `Copy`).

---

## 4. Nonce Reuse Prevention

> [!CAUTION]
> Nonce reuse under the same AES-GCM key is catastrophic — it enables both
> plaintext recovery (via crib-dragging) and authentication key extraction
> (via polynomial forgery).

### 4.1 Structural Guarantee

```text
┌──────────────────────────┬────────────────┐
│   Random base (64 bits)  │ Counter (32 b) │
└──────────────────────────┴────────────────┘
 Bytes 0..8                 Bytes 8..12
```

- **Random base:** Drawn from `EntropyOracle` at `NonceManager::new()`. Provides inter-session uniqueness (collision probability: 2⁻⁶⁴ per pair of managers).
- **Counter:** Starts at 0, increments monotonically on each `next()` call. Provides intra-session uniqueness (deterministic, no gaps).
- **Exhaustion:** At `counter == u32::MAX`, `next()` returns `Err(CryptoError::KeyExhausted)`. The caller **must** rekey.

### 4.2 Why This Is Sufficient

| Property | Mechanism |
|---|---|
| No duplicate within a session | Monotonic counter (0 → u32::MAX - 1) |
| No duplicate across sessions | 64-bit random base (birthday bound: 2³² sessions before 50% collision) |
| No duplicate across keys | Different keys have different `NonceManager` instances with independent random bases |
| No external nonce input | `NonceManager` is internal to `AeadKey` and protected by `Mutex`; callers cannot supply nonces |

### 4.3 Residual Risk

If `EntropyOracle` produces identical 64-bit bases for two `NonceManager` instances (probability 2⁻⁶⁴), nonce collision is possible. Mitigation: the entropy oracle XOR-mixes TRNG and OS entropy, then conditions through SHA-256, making this probability negligible.

---

## 5. Side-Channel Attacks

### 5.1 Timing Side-Channels

| Operation | Risk | Mitigation |
|---|---|---|
| HMAC tag comparison | High (variable-time `==` leaks tag bits) | `hmac::Mac::verify_slice` uses constant-time comparison internally |
| AES-GCM tag verification | High | `aes-gcm` crate uses `subtle::ConstantTimeEq` for tag comparison |
| HKDF expansion | Low (data-independent control flow) | HKDF-SHA-256 is naturally constant-time in key material |
| Nonce generation | None | Counter increment is data-independent |

### 5.2 Cache Side-Channels

| Operation | Risk | Mitigation |
|---|---|---|
| AES S-box lookup | Medium (T-table implementations are vulnerable) | `aes-gcm` uses AES-NI hardware instructions on x86_64 (no table lookups) |
| SHA-256 rounds | Low | No data-dependent memory access in SHA-256 |
| Zstandard compression | Medium (compression ratio leaks information about plaintext structure) | See §6 — Compression Oracle Attacks |

### 5.3 Power / EM Side-Channels

Out of scope for a software crate. Hardware-level countermeasures (shielding, noise injection) are the responsibility of the deployment environment.

---

## 6. Compression Oracle Attacks (CRIME / BREACH)

### 6.1 The Risk

Zstandard compression before encryption means that an attacker who can:
1. Inject controlled plaintext alongside secret data, and
2. Observe the resulting ciphertext length,

can recover the secret byte-by-byte (the CRIME/BREACH attack pattern).

### 6.2 Applicability to Stegosafe

| Condition | Present? | Notes |
|---|---|---|
| Attacker-controlled plaintext mixed with secrets | **No** — in normal operation, payloads are user-controlled, not attacker-injected | If a future phase introduces attacker-influenced data in the plaintext, this must be revisited |
| Ciphertext length observable | **Partially** — the stego embedding may leak approximate payload size | Compression normalises length somewhat, but does not eliminate length as a signal |

### 6.3 Mitigation: AAD Binding

- **AAD is mandatory** in `AeadKey::encrypt` / `decrypt`. Callers must supply session context (session ID, truncated timestamp, etc.).
- AAD is **not** compressed — it is authenticated but not included in the ciphertext body, so it cannot be used as a compression oracle input.
- The `aad` parameter binds each ciphertext to its session, preventing cross-session oracle queries.

### 6.4 Recommendations for Higher Phases

1. **Never mix attacker-controlled data with secrets** in the same `encrypt()` call.
2. **Pad plaintext to fixed block sizes** before passing to `encrypt()` if ciphertext length is a concern.
3. **Rate-limit encryption calls** to prevent adaptive chosen-plaintext attacks.

---

## 7. Entropy Failure Modes

### 7.1 Failure Scenarios

| Failure | Detection | Impact | Response |
|---|---|---|---|
| TRNG stuck (RDRAND returns identical values) | FIPS 140-3 startup health check (3 consecutive reads must differ) | Entropy quality degrades to OS-only | Fail-open: `trng_available` set to `false`, OS pool used exclusively |
| TRNG biased (non-uniform output) | Periodic NIST SP 800-22 monobit test (every 10,000 bytes) | Conditioning through SHA-256 mitigates minor biases | `last_check_passed` set to `false`; caller can check via `health()` |
| OS entropy pool exhausted / compromised | `getrandom` returns error | `EntropyUnavailable` error propagated | All crypto operations fail safely; no fallback to weak entropy |
| Both sources unavailable | `EntropyOracle::init()` returns `Err` | Oracle cannot be constructed | System cannot start — no cryptographic operations possible |

### 7.2 Defence in Depth: XOR Mixing + Conditioning

```text
TRNG output ──┐
              XOR ──→ SHA-256 counter mode ──→ final output
OS entropy ───┘
```

Even if one source is fully compromised, the other provides security:
- **TRNG compromised:** OS entropy (backed by kernel CSPRNG) is sufficient.
- **OS compromised:** TRNG provides hardware-sourced randomness independent of software state.
- **Both partially weak:** SHA-256 conditioning ensures uniform distribution even with minor source biases.

---

## 8. Memory Safety

### 8.1 Zeroization Guarantees

| Type | Key material | Zeroization mechanism |
|---|---|---|
| `AeadKey` | `key: Zeroizing<[u8; 32]>` | `Zeroizing` wrapper clears on `Drop` |
| `HmacKey` | `key: Zeroizing<[u8; 32]>` | `Zeroizing` wrapper clears on `Drop` |
| `SessionKeys.technique_seed` | `Zeroizing<[u8; 32]>` | `Zeroizing` wrapper clears on `Drop` |
| `SessionKeys.param_seed` | `Zeroizing<[u8; 32]>` | `Zeroizing` wrapper clears on `Drop` |
| `NonceManager` | `base: [u8; 8]`, `counter: u32` | Custom `Drop` impl zeroizes both fields |
| `derive_session_keys` temporaries | `enc_key_bytes`, `mac_key_bytes`, etc. | Explicitly `.zeroize()` after use |

### 8.2 No Heap Remnants

- All key material is stored in fixed-size arrays (`[u8; 32]`, `[u8; 8]`), not heap-allocated `Vec<u8>`.
- `Zeroizing<[u8; N]>` guarantees the stack/struct memory is zeroed on drop.
- Intermediate `Vec<u8>` buffers in `entropy.rs` (`fill_raw`, `update_counter_and_check`) are zeroed manually with `for b in buf.iter_mut() { *b = 0; }`.

### 8.3 No Unsafe Code

`#![forbid(unsafe_code)]` is enforced crate-wide. All unsafe operations (RDRAND access, AES-NI intrinsics) are delegated to audited dependencies (`rdrand`, `aes-gcm`).

---

## 9. Dependency Supply Chain Risks

### 9.1 Direct Dependencies

| Crate | Version | Purpose | Risk | Mitigation |
|---|---|---|---|---|
| `aes-gcm` | `=0.10.3` | AES-256-GCM | RUSTSEC-2023-0096 (plaintext exposure in <0.10.3) | Pinned to exact patched version |
| `hkdf` | `0.12.4` | HKDF-SHA-256 | Low (RustCrypto, well-audited) | `cargo audit` in CI |
| `sha2` | `0.10.8` | SHA-256 | Low (RustCrypto) | `cargo audit` in CI |
| `hmac` | `0.12.1` | HMAC | Low (RustCrypto) | `cargo audit` in CI |
| `zeroize` | `1.8` | Memory clearing | Low (RustCrypto) | `cargo audit` in CI |
| `subtle` | `2.6` | Constant-time operations | Low (well-audited, minimal code) | `cargo audit` in CI |
| `thiserror` | `1` | Error derive macro | Low (proc-macro, no runtime code) | `cargo audit` in CI |
| `zstd` | `0.13` | Zstandard compression | Medium (C FFI to libzstd) | `cargo audit` in CI; consider pure-Rust alternative |
| `getrandom` | `0.2` | OS entropy | Low (platform syscall wrapper) | `cargo audit` in CI |
| `rdrand` | `0.9` | x86_64 TRNG | Low (thin wrapper over RDRAND instruction) | x86_64 only; `cargo audit` in CI |

### 9.2 Supply Chain Mitigations

1. **`cargo audit`** runs in CI on every push and pull request. Any known vulnerability blocks merge.
2. **Exact version pinning** for security-critical crates (`aes-gcm = "=0.10.3"`).
3. **`Cargo.lock`** is committed to the repository to ensure reproducible builds.
4. **Minimal dependency surface:** Only 10 direct dependencies, all from the RustCrypto ecosystem or well-established crates.
5. **No `build.rs` in the crypto crate:** Reduces build-time attack surface (note: `zstd` has a build script for C compilation).

### 9.3 Recommendations

- [ ] Enable `cargo-vet` or `cargo-crev` for supply chain verification.
- [ ] Pin all transitive dependencies via `Cargo.lock` review.
- [ ] Consider replacing `zstd` (C FFI) with a pure-Rust Zstandard implementation when one reaches maturity.
- [ ] Subscribe to RustSec advisories for all direct dependencies.

---

## 10. Risk Summary

| Threat | Severity | Likelihood | Residual risk after mitigation |
|---|---|---|---|
| Nonce reuse | Critical | Very Low | Negligible (structural prevention) |
| Key compromise (memory dump) | Critical | Low | Low (zeroization, but no mlock) |
| Timing side-channel (tag comparison) | High | Low | Negligible (constant-time ops) |
| Entropy source failure | High | Very Low | Low (dual-source + conditioning) |
| Compression oracle (CRIME/BREACH) | High | Very Low | Low (AAD binding; no attacker-injected plaintext) |
| Dependency vulnerability | Medium | Medium | Low (pinning + audit + CI) |
| Error oracle | Medium | Low | Negligible (single opaque `DecryptionFailed`) |
| Cache side-channel (AES) | Medium | Low | Negligible (AES-NI on x86_64) |

---

## Appendix A: References

- NIST SP 800-38D — Recommendation for Block Cipher Modes: GCM
- NIST SP 800-22 — A Statistical Test Suite for RNGs
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- FIPS 140-3 — Security Requirements for Cryptographic Modules
- RUSTSEC-2023-0096 — aes-gcm plaintext exposure advisory
