#!/bin/bash
set -euo pipefail

OUT="VALIDATION.md"
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

# --- Prompt ---
cat > "$OUT" <<'PROMPT'
# Validation Prompt

You are a senior systems/network engineer specializing in cryptographic protocols, Telegram MTProto internals, and Zig (0.15.x). You are given the **complete source code** of a Zig rewrite of a production Telegram MTProto proxy (originally written in Rust as "telemt").

## Your task

Perform a thorough **correctness and security audit** of this codebase. Specifically:

### 1. Protocol correctness
- **Client → Proxy TLS handshake**: Is the HMAC-SHA256 validation of the ClientHello correct? Is the timestamp anti-replay check sound? Is the ServerHello response structurally valid TLS 1.3?
- **MTProto obfuscation handshake**: Is the 64-byte handshake parsing correct? Key derivation: `SHA256(prekey[32] || secret[16])` for decrypt, reversed prekey+IV for encrypt direction — verify this matches the MTProto spec.
- **Telegram DC handshake**: The nonce sent to the DC uses **raw key bytes** (NOT SHA256'd) from `nonce[8..40]` as the encrypt key, `nonce[40..56]` as the IV. The decrypt direction uses the reversed `nonce[8..56]`. The nonce is encrypted by running AES-CTR over the full 64 bytes but only replacing bytes `[56..64]` with ciphertext. **Verify this matches the reference Rust implementation** (`encrypt_tg_nonce_with_ciphers` in `handshake.rs`).
- **dc_idx**: Written as `i16` little-endian at offset 60 of the TG nonce. Negative values = test DCs. Verify the sign handling and 1-based → 0-based index conversion.

### 2. Crypto correctness
- **AES-256-CTR**: Counter is big-endian u128, incremented with wrapping. Keystream is generated per-block and XOR'd. Verify the `apply()` function handles partial blocks and multi-block data correctly.
- **AES-256-CBC**: Verify chaining (previous ciphertext XOR'd with next plaintext before encryption). Check that encrypt and decrypt are consistent (encrypt uses `initEnc`, decrypt uses `initDec`).
- **CTR counter advancement**: After encrypting the 64-byte TG nonce, the encryptor's counter should be at position 4 (64/16 = 4 blocks). Subsequent relay data must use this advanced counter — verify continuity.

### 3. Relay data path
- **C2S (Client → DC)**: TLS record unwrap → AES-CTR decrypt (client key) → AES-CTR encrypt (DC key) → raw send to DC. Verify the TLS state machine handles: partial header reads, partial body reads, CCS records (skip), Alert records (close), Application Data records (process).
- **S2C (DC → Client)**: Raw read from DC → AES-CTR decrypt (DC key) → AES-CTR encrypt (client key) → wrap in TLS Application Data records → send to client.
- **Crypto ordering**: Verify that decrypt-then-encrypt in both directions preserves the correct keystream position for each cipher instance.
- **No plaintext leak**: At no point should unencrypted MTProto data be sent over the wire without the appropriate encryption layer.

### 4. DRS (Dynamic Record Sizing)
- Initial record size 1369 bytes (mimics browser MSS - overhead), ramps to 16384 after 8 records or 128KB.
- Verify this is applied only to S2C direction (proxy → client).
- Check: does the DRS threshold logic have off-by-one errors?

### 5. Architecture & DI
- The codebase uses `ProxyState` passed by reference — no global mutable state. Verify no `OnceLock`, no `static mut`, no global singletons.
- Thread safety: `connection_count` uses `std.atomic.Value(u64)`. Each connection handler runs in a detached thread with its own stack-local state.

### 6. Security concerns
- **Key material wiping**: Are keys zeroed after use? Check for any key material that might leak via stack or log.
- **Constant-time comparison**: The TLS HMAC validation uses a constant-time compare for the first 28 bytes. Is this sufficient? Could timing leak the timestamp bytes?
- **Logging**: Does any log statement leak secrets, keys, or plaintext?
- **Error handling**: Do error paths close connections cleanly? Any resource leaks?
- **Nonce validation**: Reserved patterns (HEAD, POST, GET, 0xef, etc.) are checked. Is the check complete per MTProto spec?

### 7. Zig-specific issues
- Does the code compile on Zig 0.15.x? (It does — `zig build` and `zig build test` pass.)
- Any undefined behavior risks? (Unchecked casts, buffer overflows, use-after-free.)
- Are `@intCast` uses safe? (e.g., `dc_idx` conversion from `i16` to `usize`.)

## Output format

Structure your response as:

1. **Critical issues** — bugs that would prevent the proxy from working or create security vulnerabilities
2. **Correctness concerns** — things that might be wrong but need more context to confirm
3. **Improvements** — suggestions for robustness, performance, or code quality
4. **Verdict** — overall assessment: is this MVP ready for end-to-end testing with a real Telegram client?

---

PROMPT

# --- Collect files ---
echo "" >> "$OUT"
echo "# Source Code" >> "$OUT"
echo "" >> "$OUT"

# build.zig first
echo '## `build.zig`' >> "$OUT"
echo "" >> "$OUT"
echo '```zig' >> "$OUT"
cat "$PROJECT_ROOT/build.zig" >> "$OUT"
echo '```' >> "$OUT"
echo "" >> "$OUT"

# All .zig sources sorted by depth then name
find "$PROJECT_ROOT/src" -name '*.zig' -type f | sort | while read -r f; do
  rel="${f#$PROJECT_ROOT/}"
  echo "## \`$rel\`" >> "$OUT"
  echo "" >> "$OUT"
  echo '```zig' >> "$OUT"
  cat "$f" >> "$OUT"
  echo '```' >> "$OUT"
  echo "" >> "$OUT"
done

wc -l "$OUT"
echo "Done: $PROJECT_ROOT/$OUT"
