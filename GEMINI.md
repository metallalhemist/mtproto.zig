# MTProto Proxy (Zig)

A production-grade Telegram MTProto proxy implemented in Zig, featuring TLS-fronted obfuscated connections to bypass network censorship.

## Project Overview

This project is a high-performance MTProto proxy that mimics a standard TLS 1.3 handshake (domain fronting) to hide Telegram traffic. It is designed to be compatible with the configuration format of the Rust-based `telemt` proxy.

### Key Features
- **Fake TLS 1.3 Handshake**: Validates ClientHello messages using HMAC-SHA256 and generates indistinguishable ServerHello responses.
- **MTProto Obfuscation**: Full support for MTProto v2 obfuscation, including abridged, intermediate, and secure protocol tags.
- **Multi-user Support**: Multiple user secrets with independent validation.
- **Zero Global State**: Uses dependency injection for allocators and shared state, ensuring thread safety and testability.
- **High Performance**: Built on Zig's standard library with non-blocking I/O primitives (`poll`).

## Tech Stack
- **Language**: Zig (0.13.0 or compatible)
- **Networking**: `std.net` for TCP, `std.posix` for polling.
- **Cryptography**: `std.crypto` for SHA256, HMAC, and AES-256-CTR.
- **Build System**: Zig Build System (`build.zig`).

## Architecture

- `src/main.zig`: Entry point. Handles CLI arguments, configuration loading, and starts the proxy server.
- `src/config.zig`: Custom TOML-like configuration parser.
- `src/proxy/proxy.zig`: Core proxy logic, including the TCP accept loop, client handling, and bidirectional relay.
- `src/protocol/`:
    - `tls.zig`: Fake TLS 1.3 implementation and SNI extraction.
    - `obfuscation.zig`: MTProto handshake parsing and key derivation.
    - `constants.zig`: Telegram DC IP addresses and protocol constants.
- `src/crypto/crypto.zig`: Cryptographic utility wrappers.

## Building and Running

### Prerequisites
- Zig 0.15.0+

### Key Commands

- **Build**:
  ```bash
  zig build
  ```
- **Run**:
  ```bash
  zig build run -- [config.toml]
  ```
  *Note: Defaults to `config.toml` in the current directory if no path is provided.*

- **Test**:
  ```bash
  zig build test
  ```

### Configuration
The proxy uses a `config.toml` file. A basic example:
```toml
[server]
port = 443

[censorship]
tls_domain = "google.com"
mask = true

[access.users]
alice = "00112233445566778899aabbccddeeff"
```

## Development Conventions

- **Memory Management**: Always pass an `Allocator` to functions that need to allocate. Use `defer` for cleanup.
- **Error Handling**: Use Zig's error union types (`!T`) and try/catch patterns.
- **Testing**: Add unit tests at the bottom of the relevant `.zig` file in a `test` block.
- **Documentation**: Use `///` for doc comments on public symbols and `//!` for module-level documentation.
- **Naming**: Follow Zig's standard library naming conventions (camelCase for functions, PascalCase for types).
