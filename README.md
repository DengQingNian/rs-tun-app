# Rust TUN Proxy

A high-performance TUN proxy system written in Rust for tunneling IP packets between clients over TCP.

## Overview

Rust TUN provides a transparent IP tunnel solution where clients can route traffic through a central server. Each client gets a unique virtual IP address, and the server routes packets between clients based on destination IP.

## Features

- **TCP-based tunneling**: Reliable packet delivery over TCP
- **Custom protocol**: Lightweight framing with heartbeat and data frames
- **TUN interface**: Native TUN/TAP support via `tun-rs`
- **Auto-reconnection**: Client automatically reconnects on disconnect
- **IPv4 support**: Full IPv4 packet tunneling
- **Checksum verification**: Data integrity checks on all frames

## Architecture

```
+-------------------+     TCP      +-------------------+
|   Client A        |-------------|     Server        |
| (TUN: 10.0.3.5)  |             | (Routes by IP)    |
+-------------------+             +-------------------+
        |                                  |
        | TUN                              | TUN
        v                                  v
   Local Network                     Remote Network
```

### Components

| Component | Description |
|-----------|-------------|
| `server` | Accepts client connections, registers IPs, routes packets |
| `client` | Creates TUN interface, tunnels packets to/from server |
| `shared::data` | Frame protocol (serialization, parsing, checksums) |
| `shared::config` | TOML configuration for server and client |

## Quick Start

### Prerequisites

- Rust 1.80+ with edition 2024
- Linux with TUN support (root privileges for TUN device)
- A Rust toolchain: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

### Build

```bash
# Clone and build
cargo build --release

# Or run directly
cargo run --bin server &
cargo run --bin client
```

### Running

#### Server

```bash
# With default config (binds 0.0.0.0:20264)
cargo run --bin server

# With custom config
./target/release/server
```

#### Client

```bash
# With default config (connects 127.0.0.1:20264, TUN IP 10.0.3.5)
cargo run --bin client

# With custom config
./target/release/client
```

## Configuration

### Server Config (`server.toml`)

```toml
# Server bind address
bind_addr = "0.0.0.0"

# Server listen port
bind_port = 20264

# Secret for heartbeat authentication
secret = "your-secret-key"

# Heartbeat check interval (seconds)
heartbeat_interval_secs = 10

# Client timeout (seconds)
client_timeout_secs = 30
```

### Client Config (`client.toml`)

```toml
# Server address
server_addr = "127.0.0.1"

# Server port
server_port = 20264

# TUN interface IP (must be unique per client)
tun_ip = "10.0.3.5"

# TUN netmask (CIDR prefix)
tun_netmask = 24

# Secret (must match server)
secret = "your-secret-key"

# Reconnect delay (seconds)
reconnect_delay_secs = 3

# Max reconnect attempts (0 = infinite)
max_reconnect_attempts = 0

# Heartbeat interval (seconds)
heartbeat_interval_secs = 5
```

## Protocol Details

### Frame Format

```
+--------+----------------+----------+----------+
| Header |     Data       | Checksum |
+--------+----------------+----------+----------+
1 byte   3 bytes padding  4 bytes    N bytes    2 bytes
-------- HEADER_SIZE = 8 bytes -----------------
```

- **Byte 0**: Frame type (1=Heartbeat, 2=Data)
- **Bytes 1-3**: Reserved/padding
- **Bytes 4-7**: Data length (big-endian u32)
- **Data**: Frame payload
- **Last 2 bytes**: Checksum (big-endian u16)

### Frame Types

| Type | Value | Purpose |
|------|-------|---------|
| Heartbeat | 1 | Client registration + keep-alive |
| Data | 2 | IP packet tunneling |

### Checksum

- **Heartbeat**: CRC32 with secret token (authentication)
- **Data**: Simple sum (performance)

## Usage Examples

### Basic Server-Client Setup

1. Start server:
   ```bash
   cargo run --bin server
   # Output: Server starting on 0.0.0.0:20264
   ```

2. Start client (in another terminal):
   ```bash
   cargo run --bin client
   # Output: [Attempt 1] Connecting to server 127.0.0.1:20264...
   ```

3. Test connectivity (from client):
   ```bash
   ping 10.0.3.1  # Server's virtual IP gateway
   ```

### Multi-Client Setup

Each client needs a unique `tun_ip`:

```toml
# client1.toml
tun_ip = "10.0.3.5"

# client2.toml  
tun_ip = "10.0.3.6"
```

## Development

### Code Structure

```
src/
├── lib.rs          # Main library, re-exports shared module
├── bin/
│   ├── server.rs   # TCP server implementation
│   └── client.rs   # TCP client implementation
└── shared/
    ├── mod.rs      # Module declaration
    ├── data.rs     # Frame protocol, serialization
    └── config.rs   # Configuration structures
```

### Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test --lib -- --exact test_heartbeat_frame

# Run with logging
RUST_LOG=debug cargo test
```

### Linting

```bash
cargo clippy
```

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| tokio | 1.50 | Async runtime |
| bytes | 1.11 | Efficient byte handling |
| tun-rs | 2.8 | TUN/TAP interface |
| crc32fast | 1.4 | CRC32 checksum |
| serde | 1.0 | Serialization |
| toml | 0.8 | TOML parsing |
| thiserror | 2 | Error handling |

## License

MIT License
