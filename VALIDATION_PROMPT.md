# Validation Prompt — Iteration 3

You are a senior systems/network engineer specializing in cryptographic protocols, Telegram MTProto internals, and Zig (0.15.x). You are given the **complete source code** of a Zig rewrite of a production Telegram MTProto proxy.

## Context: iterations 1 & 2

In iteration 1 you audited this codebase and identified 12 critical issues. All 12 were fixed.

In iteration 2 you re-audited and confirmed 9 of the 12 fixes as correct. You flagged 4 new issues (2 critical, 2 correctness) and 2 improvements. **Note**: the 2 "compilation errors" you reported (`@bitOffsetOf` and `ArrayList` API) were false positives — the code compiles and tests pass on Zig 0.15.2. The remaining issues were real.

### Fixes applied after iteration 2

1. **`writeAll` backpressure** (`proxy.zig`): `writeAll()` now handles `error.WouldBlock` by waiting for `POLLOUT` via `posix.poll()` with a configurable timeout (`relay_timeout_ms = 300000`), preventing data loss when the TCP send buffer is full on non-blocking sockets.

2. **CCS state machine unification** (`proxy.zig`): CCS records now share the same `tls_body_buf`/`tls_body_pos`/`tls_body_len` state as Application Data records. The body is read incrementally (surviving `WouldBlock` across poll iterations), then discarded based on `tls_hdr_buf[0]` record type. No more local variables lost on partial reads.

3. **Temporary decryptor wipe** (`obfuscation.zig`): `fromHandshake()` now calls `defer decryptor.wipe()` on the temporary `AesCtr` used to test each secret, preventing the expanded AES key schedule from leaking on the stack.

4. **Slowloris protection** (`proxy.zig`): `SO_RCVTIMEO` is set on the client socket immediately upon entering `handleConnectionInner()` via `setRecvTimeout(fd, 30)`. This limits blocking handshake reads to 30 seconds, preventing thread exhaustion attacks.

5. **Relay idle timeout** (`proxy.zig`): The relay `poll()` timeout changed from `-1` (infinite) to `relay_timeout_ms` (5 minutes). Ghost connections that go silent (e.g., mobile client loses signal without TCP FIN) are now detected and closed, preventing memory leaks.

6. **`setNonBlocking` portability** (`proxy.zig`): Replaced `1 << @bitOffsetOf(posix.O, "NONBLOCK")` with `@bitCast(posix.O{ .NONBLOCK = true })` properly widened to `u64` via `@as(u64, @as(u32, @bitCast(...)))`. This is type-safe and works correctly on both macOS (`packed struct(u32)`) and Linux.

7. **Idiomatic `EncCtx` type** (`crypto.zig`): Extracted `@TypeOf(Aes256.initEnc(...))` into a named constant `const EncCtx = ...` for readability, while remaining backend-independent (works with soft/aesni/armcrypto).

8. **`secureZero` for all key wipes** (`crypto.zig`): Replaced `@memset(&self.key, 0)` and the dummy `Aes256.initEnc([_]u8{0} ** 32)` in `AesCtr.wipe()` with `std.crypto.secureZero()` — which is not subject to dead-store elimination by the optimizer. Also applied to `AesCbc.wipe()`.

## Your task

Perform a **third-pass audit** of the updated codebase. Focus on:

### 1. Verify the iteration-2 fixes
For each of the 8 fixes listed above, confirm that the implementation is correct and complete. Flag any fix that is incomplete or introduces a new issue.

### 2. Protocol correctness (final check)
- **Client → Proxy TLS handshake**: HMAC validation, timestamp anti-replay, ServerHello structure.
- **MTProto obfuscation handshake**: 64-byte parsing, key derivation (`SHA256(prekey[32] || secret[16])`), encrypt/decrypt direction.
- **Telegram DC handshake**: Nonce encryption using raw key bytes from `nonce[8..40]`/`nonce[40..56]`, reversed for decrypt. AES-CTR over full 64 bytes, replacing only `[56..64]`.
- **dc_idx**: `i16` LE at offset 60, negative = test DC, 1-based → 0-based conversion.

### 3. Crypto correctness (final check)
- **AES-256-CTR**: Cached key schedule, counter continuity, partial block handling.
- **AES-256-CBC**: IV chaining across calls.
- **CTR counter sync**: After 64-byte TG nonce → `tg_encryptor` at counter 4. After pipelined data → counters stay in sync.
- **`secureZero`**: Verify it properly prevents dead-store elimination for all wiped fields.

### 4. Relay data path (final check)
- **C2S**: TLS unwrap → client decrypt → DC encrypt → send. CCS routing through shared body buffer. Pipelined data forwarding.
- **S2C**: Raw read → DC decrypt → client encrypt → TLS wrap → send.
- **`writeAll` backpressure**: Does the POLLOUT wait correctly handle edge cases? (timeout, HUP during write, etc.)
- **Non-blocking mode**: `setNonBlocking()` correctness on macOS and Linux.

### 5. DRS (Dynamic Record Sizing)
- Initial 1369 bytes → 16384 after 8 records or 128KB.
- Applied only to S2C (proxy → client).
- Off-by-one checks on thresholds.

### 6. Security concerns (final check)
- **Key wiping**: `secureZero` on all cipher instances + temporary decryptor in `fromHandshake`. Any remaining leaks?
- **Slowloris**: `SO_RCVTIMEO` on handshake phase. Is 30 seconds reasonable?
- **Ghost connections**: 5-minute relay timeout via `poll()`. Sufficient?
- **Logging**: Any log statement that leaks secrets or plaintext?
- **Error handling**: Resource cleanup on all error paths?

### 7. Zig-specific issues
- Zig 0.15.2 compatibility (code compiles with `zig build` and `zig build test` — confirmed).
- `@abs()` on `i16`, `@bitCast` chains, `@intCast` safety.
- Any UB risks: unchecked casts, buffer overflows, use-after-free.

## Output format

Structure your response as:

1. **Fix verification** — for each of the 8 iteration-2 fixes: confirmed OK, or flagged with explanation
2. **New critical issues** — bugs that would prevent the proxy from working or create security vulnerabilities
3. **New correctness concerns** — things that might be wrong but need more context
4. **Improvements** — suggestions for robustness, performance, or code quality
5. **Verdict** — is this MVP ready for end-to-end testing with a real Telegram client?
