# AGENTS.md - Rust Tunnel Project Guidelines

## Build & Test Commands

### Build Commands
- `cargo build` - Standard build
- `cargo build --release` - Optimized release build
- `cargo check` - Fast syntax checking without building
- `cargo clippy` - Linting (if clippy available)

### Test Commands
- `cargo test` - Run all tests
- `cargo test --lib` - Run library tests only
- `cargo test --lib -- --exact` - Run tests with exact matching
- `cargo test --lib -- --test-threads=1` - Run tests with single thread
- `cargo test --test-threads=1` - Run all tests with single thread
- `cargo test [test_name]` - Run specific test (may need `--lib` flag)

### Running Binaries
- `cargo run --bin server` - Run server
- `cargo run --bin client` - Run client
- `cargo run --bin server --release` - Run optimized server

## Code Style Guidelines

### Imports
- **Standard Rust style**: Group imports logically
- **Use `use` statements** at module level, not inside functions
- **Re-export** public types from lib.rs when appropriate
- **Avoid glob imports** (`*`) except in tests or prelude modules
- **Format**: One import per line for clarity

```rust
// Good
use std::net::Ipv4Addr;
use std::io::{Error, ErrorKind};

// Also acceptable for related items
use std::{
    fmt::{self, Display, Formatter},
    io::{Error, ErrorKind},
};
```

### Formatting
- **Edition**: Rust 2024
- **Line length**: 100 characters maximum (soft limit)
- **Indentation**: 4 spaces (not tabs)
- **Brace style**: Same-line for control flow, next-line for type definitions
- **Match arms**: Use blocks for complex logic
- **Trailing commas**: Use consistently in structs, enums, and function signatures

```rust
// Good style
#[derive(Debug, Clone, PartialEq)]
pub struct PackageFrame {
    pub kind: FrameType,
    pub src: u32,
    pub dst: u32,
    pub data_len: u32,
    pub data: Option<Bytes>,
    pub checksum: u16,
}

// Function with clear structure
pub fn new(kind: FrameType, src: u32, dst: u32, data: Option<Bytes>) -> Self {
    let data = data.filter(|d| !d.is_empty());
    let data_len = data.as_ref().map_or(0, |d| d.len() as u32);
    // ...
}
```

### Naming Conventions
- **Types**: `UpperCamelCase` (structs, enums, traits, types)
- **Functions/Methods**: `snake_case`
- **Variables**: `snake_case`
- **Constants**: `SCREAMING_SNAKE_CASE`
- **Modules**: `snake_case`
- **Lifetimes**: `'a`, `'b` (short, conventional names)

### Error Handling
- **Use `Result`** with explicit error types where practical
- **Custom error types** using `thiserror` or `anyhow` crates for complex error handling
- **Avoid `unwrap()`** in production code - use proper error propagation
- **Context**: Provide meaningful error messages
- **Error kinds**: Match appropriate `std::io::ErrorKind` when using IO errors

```rust
// Good error handling
if bytes.len() < HEADER_SIZE + 2 {
    return Err(Error::new(
        ErrorKind::InvalidData,
        format!("Frame too short: need at least {} bytes", HEADER_SIZE + 2),
    ));
}
```

### Types and Safety
- **Avoid `unsafe`** unless absolutely necessary and well-documented
- **Use `Option`** instead of null pointers
- **Prefer `Result`** over exceptions/panics for error handling
- **Generic constraints**: Use `where` clauses for complex bounds
- **Type aliases**: Use for clarity, not to hide complexity

### Documentation
- **Public APIs**: Always document with `///` doc comments
- **Examples**: Include usage examples in doc comments
- **Panics**: Document if function can panic under what conditions
- **Safety**: Document unsafe code thoroughly
- **Module-level**: Use `//!` for module documentation

```rust
/// Creates a new PackageFrame with the given parameters.
///
/// # Arguments
/// * `kind` - The frame type (Data or Heartbeat)
/// * `src` - Source IP address as u32
/// * `dst` - Destination IP address as u32
/// * `data` - Optional payload data
///
/// # Returns
/// A new PackageFrame with calculated checksum
pub fn new(kind: FrameType, src: u32, dst: u32, data: Option<Bytes>) -> Self {
    // ...
}
```

### Async/Await Patterns
- **Use `tokio`** runtime (configured in Cargo.toml)
- **Avoid blocking operations** in async contexts
- **Spawn tasks** for concurrent operations
- **Use channels** for inter-task communication
- **Timeout handling**: Use `tokio::time::timeout` for operations that may hang

### Testing
- **Unit tests**: In same file as code, in `#[cfg(test)] mod tests`
- **Integration tests**: In `tests/` directory
- **Test naming**: `test_[behavior]_[expected_result]`
- **Coverage**: Aim for comprehensive test coverage
- **Panic on test failure**: Use `#[should_panic]` when appropriate
- **Mocking**: Use appropriate mocking strategies for external dependencies

### Project-Specific Patterns
- **Frame protocol**: Follow existing `PackageFrame` structure
- **Checksum calculation**: Use SHA256-based sum function
- **Byte ordering**: Use big-endian (`to_be_bytes`, `from_be_bytes`) for network protocol
- **Buffer management**: Use `Vec<u8>` with capacity pre-allocation
- **Async reading**: Use `BufReader` for efficient TCP reads
- **Sticky packet handling**: Implement proper frame parsing with remaining buffer management

### Linting
- Run `cargo clippy` regularly
- Address all clippy warnings
- **Allow** specific lints only with clear justification
- Follow Rust 2024 idioms

### Performance Considerations
- **Avoid unnecessary allocations** in hot paths
- **Use `Bytes`** for zero-copy data handling where appropriate
- **Pre-allocate vectors** with known capacity
- **Use `Cow`** for borrowed/owned data flexibility
- **Profile** performance-critical code sections

### Security
- **Validate all inputs** thoroughly
- **Check buffer bounds** before access
- **Use constant-time operations** for security-sensitive comparisons
- **Sanitize error messages** to avoid information leakage
- **Audit dependencies** for security vulnerabilities

### CI/CD Best Practices
- **Test on all supported platforms**
- **Build with `--release` flag** for performance testing
- **Run clippy** as part of CI pipeline
- **Check for dependency updates** regularly
- **Audit for security vulnerabilities** in dependencies

## Current Project Structure
```
src/
├── lib.rs          # Main library, re-exports shared module
├── bin/
│   ├── server.rs   # TCP server implementation
│   └── client.rs   # TCP client implementation
└── shared/
    ├── mod.rs      # Module declaration
    └── data.rs     # Frame protocol, serialization, tests
```

## Key Dependencies and Usage
- **tokio**: Async runtime for TCP networking
- **bytes**: Efficient byte handling with `Bytes` type
- **sha2**: SHA256 hashing for checksums
- **rand**: Random number generation
- **hex**: Hex encoding/decoding utilities
- **ipnet**: IP network address handling
- **tun-rs**: TUN/TAP interface support
- **quinn**: QUIC protocol support (for future extensions)
- **time**: Time utilities for timestamps