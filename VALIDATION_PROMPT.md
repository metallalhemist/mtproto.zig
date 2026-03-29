# Validation Prompt — Iteration 2

You are a senior systems/network engineer specializing in cryptographic protocols, Telegram MTProto internals, and Zig (0.15.x). You are given the **complete source code** of a Zig rewrite of a production Telegram MTProto proxy.

## Context: first iteration

In iteration 1 you audited this codebase and identified critical issues and correctness concerns. The following fixes have been applied since then:

### Fixes applied

1. **AES key schedule caching** (`crypto.zig`): `AesCtr` now caches the expanded key schedule (`enc_ctx`) in `init()` instead of calling `Aes256.initEnc()` on every `apply()` call. The `wipe()` method also zeroes the cached schedule.

2. **AES-CBC IV chaining** (`crypto.zig`): `encryptInPlace()` and `decryptInPlace()` now update `self.iv` to the last ciphertext block after each call, enabling correct chaining across multiple calls. Signatures changed from `*const AesCbc` to `*AesCbc`.

3. **Constant-time comparison** (`tls.zig`): Replaced the custom `constantTimeEq()` function with `std.crypto.timing_safe.eql()` from the Zig standard library — a proven, audited implementation.

4. **ServerHello HMAC** (`tls.zig` / `proxy.zig`): `TlsValidation` now carries the matched `secret` field. `buildServerHello()` is called with the user's secret (not the digest) as the HMAC key, fixing the ServerHello HMAC computation.

5. **Client CTR counter sync** (`proxy.zig`): After `fromHandshake()` verifies the handshake using a temporary decryptor, the fresh `client_decryptor` now has its counter advanced by 4 (`client_decryptor.ctr +%= 4`) to match the client's state after encrypting the 64-byte handshake.

6. **Pipelined data handling** (`proxy.zig`): If the TLS record carrying the 64-byte handshake contains additional bytes (pipelined first RPC), those bytes are now decrypted with the client cipher, re-encrypted with the DC cipher, and forwarded to the DC before entering the relay loop.

7. **TLS payload bounds check** (`proxy.zig`): Added a check `payload_len > max_tls_ciphertext_size` to reject oversized TLS records before reading into the fixed-size buffer.

8. **CCS body handling** (`proxy.zig`): CCS records are now handled with a loop that reads and discards the full variable-length body, not just 1 byte.

9. **dc_idx overflow safety** (`proxy.zig`): Replaced `-params.dc_idx` (which overflows on `minInt(i16)`) with `@abs(params.dc_idx)`.

10. **Non-blocking sockets for relay** (`proxy.zig`): Both client and DC sockets are now set to non-blocking mode via `setNonBlocking()` before entering the `poll()`-based relay loop, preventing deadlocks.

11. **Cipher wipe on all paths** (`proxy.zig`): Added `defer wipe()` for `tg_encryptor`, `tg_decryptor`, `client_decryptor`, and `client_encryptor` to ensure key material is zeroed on all exit paths.

12. **Reserved nonce patterns** (`constants.zig`): Added `OPTIONS` (`0x4F505449`) and `PUT` (`0x50555420`) to the reserved nonce prefix list.

## Your task

Perform a **second-pass audit** of the updated codebase. Focus on:

### 1. Verify the fixes
For each of the 12 fixes listed above, confirm that the implementation is correct and complete. Flag any fix that is incomplete or introduces a new issue.

### 2. Protocol correctness (re-check)
- **Client → Proxy TLS handshake**: HMAC validation, timestamp anti-replay, ServerHello structure.
- **MTProto obfuscation handshake**: 64-byte parsing, key derivation (`SHA256(prekey[32] || secret[16])`), encrypt/decrypt direction.
- **Telegram DC handshake**: Nonce encryption using raw key bytes from `nonce[8..40]`/`nonce[40..56]`, reversed for decrypt. AES-CTR over full 64 bytes, replacing only `[56..64]`.
- **dc_idx**: `i16` LE at offset 60, negative = test DC, 1-based → 0-based conversion.

### 3. Crypto correctness (re-check)
- **AES-256-CTR**: Cached key schedule correctness. Counter continuity after handshake encryption. Partial block handling.
- **AES-256-CBC**: IV chaining now persists — verify `encryptInPlace` → `decryptInPlace` roundtrip still works with the new semantics.
- **CTR counter sync**: After the 64-byte TG nonce, `tg_encryptor` is at counter 4. After pipelined data forwarding, verify `tg_encryptor` and `client_decryptor` counters remain in sync with their peers.

### 4. Relay data path (re-check)
- **C2S**: TLS unwrap → client decrypt → DC encrypt → send. CCS handling with variable-length body. Pipelined data forwarding.
- **S2C**: Raw read → DC decrypt → client encrypt → TLS wrap → send.
- **Non-blocking mode**: Verify `setNonBlocking()` is correct (`O.NONBLOCK` flag via `fcntl`). Verify all `read()`/`write()` paths handle `WouldBlock`.

### 5. DRS (Dynamic Record Sizing)
- Initial 1369 bytes → 16384 after 8 records or 128KB.
- Applied only to S2C (proxy → client).
- Off-by-one checks on thresholds.

### 6. Security concerns
- **Key wiping**: All cipher instances (`tg_encryptor`, `tg_decryptor`, `client_decryptor`, `client_encryptor`) now have `defer wipe()`. Are there any remaining paths where key material leaks?
- **Constant-time**: `std.crypto.timing_safe.eql` for HMAC check — sufficient?
- **Logging**: Any log statement that leaks secrets or plaintext?
- **Error handling**: Resource cleanup on all error paths?

### 7. New issues
Look for any **new bugs or regressions** introduced by the fixes. In particular:
- Does the cached `enc_ctx` in `AesCtr` correctly reflect the key? Is it invalidated if key changes?
- Does `setNonBlocking` work correctly on both macOS and Linux?
- Does the pipelined data path correctly advance both cipher counters?

### 8. Zig-specific issues
- Zig 0.15.x compatibility (code compiles with `zig build` and `zig build test`).
- `@abs()` on `i16` — return type and safety.
- `@TypeOf` / `@bitOffsetOf` usage — portable?
- Any UB risks: unchecked casts, buffer overflows, use-after-free.

## Output format

Structure your response as:

1. **Fix verification** — for each of the 12 fixes: confirmed OK, or flagged with explanation
2. **New critical issues** — bugs that would prevent the proxy from working or create security vulnerabilities
3. **New correctness concerns** — things that might be wrong but need more context
4. **Improvements** — suggestions for robustness, performance, or code quality
5. **Verdict** — is this MVP ready for end-to-end testing with a real Telegram client?
