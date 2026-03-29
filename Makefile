.PHONY: build run test clean fmt

# Build the proxy binary
build:
	zig build

# Build with release optimizations
release:
	zig build -Doptimize=ReleaseFast

# Run the proxy (pass CONFIG via: make run CONFIG=path/to/config.toml)
CONFIG ?= config.toml
run:
	zig build run -- $(CONFIG)

# Run unit tests
test:
	zig build test

# Remove build artifacts
clean:
	rm -rf .zig-cache zig-out

# Format all Zig source files
fmt:
	zig fmt src/
