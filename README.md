# Rust TUN Proxy

A high-performance TUN proxy system written in Rust for tunneling IP packets between clients over TCP.

## Overview

Rust TUN provides a transparent IP tunnel solution where clients can route traffic through a central server. Each client gets a unique virtual IP address, and the server routes packets between clients based on destination IP extracted from the IP header.

## Features

- **TCP-based tunneling**: Reliable packet delivery over TCP with custom framing
- **Custom protocol**: Lightweight framing with heartbeat and data frames
- **TUN interface**: Native TUN/TAP support via `tun-rs` with async I/O
- **Auto-reconnection**: Client automatically reconnects on disconnect with configurable attempts
- **IPv4 support**: Full IPv4 packet tunneling
- **Checksum verification**: CRC32 authentication for heartbeats, simple sum for data frames
- **Lazy registration**: Server can register clients from first data packet if no heartbeat received
- **Concurrent routing**: Server handles multiple clients simultaneously with IP-based routing

## Architecture

```
+-------------------+     TCP      +-------------------+     TCP      +-------------------+
|   Client A        |-------------|     Server        |-------------|   Client B        |
| (TUN: 10.0.3.5)  |             | (Routes by IP)    |             | (TUN: 10.0.3.10) |
+-------------------+             +-------------------+             +-------------------+
        |                                  |                                  |
        | TUN                              | TUN                              | TUN
        v                                  v                                  v
   Local Network                       (Routing)                       Remote Network
```

### Components

| Component | Description |
|-----------|-------------|
| `server` | Accepts client connections, maintains IP registry, routes packets by destination IP |
| `client` | Creates TUN interface, tunnels packets to/from server, handles reconnection |
| `shared::data` | Frame protocol (serialization, parsing, sticky packet handling, checksums) |
| `shared::config` | TOML configuration for server and client |

### Data Flow

1. **Client connects** to server via TCP
2. **Client sends heartbeat** with its TUN IP for registration
3. **Server registers** (IP → writer) in client registry
4. **Client reads from TUN**, wraps packets in data frames, sends to server
5. **Server extracts destination IP** from IP header, routes to appropriate client
6. **Destination client** writes packet to its TUN interface

## Quick Start

### Prerequisites

- Rust 1.80+ with edition 2024
- Linux with TUN support (root privileges for TUN device)
- A Rust toolchain: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

### Build

```bash
cargo build --release
```

### Running

#### Server

```bash
# With default config (binds 0.0.0.0:20264)
cargo run --bin server

# With custom config (place server.toml in current directory)
./target/release/server
```

#### Client

```bash
# With default config (connects 127.0.0.1:20264, TUN IP 10.0.3.5)
cargo run --bin client

# With custom config (place client.toml in current directory)
./target/release/client
```

## Configuration

### Server Config (`server.toml`)

```toml
# Server bind address
bind_addr = "0.0.0.0"

# Server listen port
bind_port = 20264

# Secret for heartbeat authentication (must match clients)
secret = "your-secret-key"

# Heartbeat check interval (seconds)
heartbeat_interval_secs = 10

# Client timeout (seconds) - client removed if no heartbeat within this time
client_timeout_secs = 30

# Optional traffic statistics HTTP API and dashboard
[stats]
enabled = true
bind_addr = "127.0.0.1"
bind_port = 20265
username = "admin"
password = "change-me"
```

When `[stats]` is enabled, the server exposes:

- `GET /` - simple HTML traffic statistics dashboard
- `GET /api/stats` - JSON traffic statistics snapshot

Both endpoints require HTTP Basic Auth using the configured `username` and `password`. These
credentials must be set explicitly when `enabled = true`; the stats server will not start with
missing or empty credentials.

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

**Header breakdown:**
- **Byte 0**: Frame type (1 = Heartbeat, 2 = Data)
- **Bytes 1-3**: Reserved/padding (must be zero)
- **Bytes 4-7**: Data length (big-endian u32)
- **Data**: Frame payload
- **Last 2 bytes**: Checksum (big-endian u16)

### Frame Types

| Type | Value | Purpose | Checksum |
|------|-------|---------|----------|
| Heartbeat | 1 | Client registration + keep-alive | CRC32 with secret |
| Data | 2 | IP packet tunneling | Simple sum |

### Checksum Algorithms

**Heartbeat (CRC32 with secret):**
- Uses CRC32 algorithm with frame type, data length, payload, and secret token
- Truncated to 16 bits for protocol format
- Provides authentication - cannot forge heartbeats without knowing secret

**Data (Simple sum):**
- Iterates through data in 4-byte chunks, summing as u32 (little-endian)
- Handles remaining 1-3 bytes individually
- Uses wrapping add for overflow behavior
- Truncated to 16 bits
- Optimized for performance (hot path)

### Sticky Packet Handling

TCP may deliver multiple frames in a single read (sticky packets) or partial frames across reads. The parser handles this by:
- Parsing complete frame from buffer start
- Returning remaining bytes for subsequent parsing
- Validating frame boundaries before acceptance

## Technical Details

### TUN Interface Naming

Each client creates a TUN interface named `rs-tun-{third_octet}` based on its IP:
- IP `10.0.3.5` → interface `rs-tun-3`
- IP `10.0.3.10` → interface `rs-tun-3`

If the interface already exists, the client attempts to reopen it rather than create a new one.

### Server Routing

The server maintains a client registry mapping IP addresses to TCP writer handles:

```rust
type ClientRegistry = Arc<Mutex<HashMap<Ipv4Addr, ClientInfo>>>;
```

Routing logic:
1. Extract destination IP from IP header bytes 16-19
2. Lookup destination IP in registry
3. If found, forward frame bytes to that client's writer

### Lazy Registration

If a client sends data before registering via heartbeat, the server can extract the source IP from the IP packet header (bytes 12-15) and register the client automatically.

### Client Reconnection

On connection loss:
1. Client waits `reconnect_delay_secs`
2. Attempts to reconnect
3. Repeats up to `max_reconnect_attempts` times (0 = infinite)
4. Each reconnection creates fresh TUN interface

## Project Structure

```
src/
├── lib.rs              # Main library, re-exports shared module
├── bin/
│   ├── server.rs       # TCP server: client registry, packet routing
│   └── client.rs        # TCP client: TUN handler, heartbeat, reconnection
└── shared/
    ├── mod.rs          # Module declaration
    ├── data.rs         # Frame protocol, serialization, parsing, checksums
    └── config.rs       # TOML configuration structures
```

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| tokio | 1.50 | Async runtime, TCP networking |
| bytes | 1.11 | Efficient byte handling with `Bytes` type |
| tun-rs | 2.8 | TUN/TAP interface with async support |
| crc32fast | 1.4 | CRC32 checksum for heartbeat authentication |
| serde | 1.0 | Serialization for configuration |
| toml | 0.8 | TOML configuration parsing |
| thiserror | 2 | Error handling with custom error types |
| ipnet | 2.12 | IP network address handling |

## Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test --lib -- --exact test_heartbeat_frame

# Run with logging
RUST_LOG=debug cargo test
```

## License

MIT License
