# Binary Size Optimization Guide for TagIO

This document outlines techniques used to minimize the binary size of TagIO application binaries.

## Current Optimization Techniques

### Cargo.toml Optimizations

```toml
[profile.release]
opt-level = "z"     # Optimize for size, not speed
lto = true          # Enable Link Time Optimization
codegen-units = 1   # Use a single codegen unit for better optimization
strip = true        # Strip symbols from binary
panic = "abort"     # Remove panic unwinding code
overflow-checks = false  # Disable integer overflow checks
debug = false       # No debug info at all

# Optimize dependencies as well
[profile.release.package."*"]
opt-level = "z"     # Optimize all dependencies for size too
debug = false
```

### Dependency Optimization

1. **Selective Feature Flags**: Only enable features that are actually needed
   - Example: Trimmed down tokio to include only the minimal feature set

2. **Avoiding Heavy Dependencies**: Prefer lightweight alternatives when possible
   - For instance, using `log` with a simple implementation instead of more complex logging frameworks

### Code Organization

1. **Modular Structure**: Organized code into modules for better compilation and optimization
   - We've split large files into focused modules (e.g., nat_traversal, relay, p2p_tls)

2. **Reduced Code Duplication**: Consolidated duplicate code into shared utilities

## Post-Build Optimization

### Stripping Symbols

We set `strip = true` in Cargo.toml, but also provide `optimize_binary_size.ps1` script that applies:
- Additional symbol stripping with external tools if available
- UPX compression for further size reduction

### Binary Analysis

Use `analyze_binary_size.ps1` to:
- Identify largest dependencies
- Find functions consuming the most space
- Detect unused features

## Advanced Techniques

For extreme size optimization, consider:

1. **Disable Standard Library**: Use `#![no_std]` for extremely small binaries
   - Only appropriate for specialized use cases
   - Requires writing more unsafe code

2. **Custom Allocators**: Replace the default allocator with a size-optimized one

3. **Tree Shaking**: Manually exclude unused code from dependencies

## Monitoring Binary Size

Run `cargo bloat` regularly to track binary size during development:

```
cargo bloat --release --bin tagio-gui-eframe
```

## Additional Resources

- [Minimizing Rust Binary Size](https://github.com/johnthagen/min-sized-rust)
- [Rust Binary Size Working Group](https://github.com/rust-lang/wg-binary-size)
- [UPX Compression Tool](https://upx.github.io/) 