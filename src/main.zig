//! MTProto Proxy — Zig implementation
//!
//! A production-grade Telegram MTProto proxy supporting TLS-fronted
//! obfuscated connections to Telegram datacenters.

const std = @import("std");
const constants = @import("protocol/constants.zig");
const crypto = @import("crypto/crypto.zig");
const obfuscation = @import("protocol/obfuscation.zig");
const tls = @import("protocol/tls.zig");
const config = @import("config.zig");
const proxy = @import("proxy/proxy.zig");

const log = std.log.scoped(.mtproto);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    log.info("mtproto-proxy v0.1.0", .{});

    // Parse config
    const cfg = config.Config.loadFromFile(allocator, "config.toml") catch |err| {
        log.err("Failed to load config: {}", .{err});
        log.err("Usage: mtproto-proxy [config.toml]", .{});
        return;
    };
    defer cfg.deinit(allocator);

    log.info("Loaded {d} user(s), listening on port {d}", .{
        cfg.users.count(),
        cfg.port,
    });

    // Create shared state (DI — no globals)
    var state = proxy.ProxyState.init(allocator, cfg);
    defer state.deinit();

    // Run the proxy
    try state.run();
}

test {
    _ = constants;
    _ = crypto;
    _ = obfuscation;
    _ = tls;
    _ = config;
    _ = proxy;
}
