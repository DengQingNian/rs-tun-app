//! # TUN Proxy Server
//!
//! This is the server component of the TUN proxy system. It listens for TCP
//! connections from clients, registers their TUN IP addresses, and forwards
//! IP packets between clients based on destination IP routing.
//!
//! ## Architecture
//!
//! **Server Design:**
//! - Single TCP listener accepts multiple client connections
//! - Each client connection runs in its own async task
//! - Client registry maps TUN IP addresses to writer handles
//! - Incoming packets are routed to the correct client based on destination IP
//!
//! **Data Flow:**
//! ```text
//! Client A (TUN IP 10.0.3.5) <--TCP--> Server <--TCP--> Client B (TUN IP 10.0.3.10)
//!                                        |
//!                                     (routing by dst IP)
//! ```
//!
//! **Registration Flow:**
//! 1. Client connects via TCP
//! 2. Client sends heartbeat frame with its TUN IP
//! 3. Server registers (IP -> writer) in client map
//! 4. Server forwards packets based on destination IP
//! 5. Client disconnects -> IP removed from registry

use rusttun::shared::config::ServerConfig;
use rusttun::shared::data::FrameType;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, Result};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Maximum buffer size to prevent memory exhaustion attacks.
/// 
/// WHY: If a client sends data faster than we can process it, the buffer grows
/// unbounded. This limit prevents a malicious or buggy client from consuming
/// all server memory.
const MAX_BUFFER_SIZE: usize = 1024 * 1024;

/// Client connection metadata.
///
/// WHY: We need to track the writer handle for each registered client IP.
/// This allows sending frames to that client when packets arrive for them.
struct ClientInfo {
    /// Write half of the TCP connection for sending frames to client.
    writer: Arc<Mutex<OwnedWriteHalf>>,
}

/// Type alias for the client registry.
/// 
/// WHY: The registry maps a client's TUN IP address to their connection metadata.
/// This enables O(1) lookup for packet routing.
type ClientRegistry = Arc<Mutex<HashMap<Ipv4Addr, ClientInfo>>>;


/// Server entry point.
///
/// # How It Works
/// 1. Load configuration (from file or defaults)
/// 2. Create TCP listener on bind address
/// 3. Accept client connections in a loop
/// 4. Spawn async task for each client
///
/// # Configuration
/// Looks for `server.toml` in current directory. If not found, uses hardcoded
/// defaults. This allows easy deployment without explicit path arguments.
#[tokio::main]
async fn main() {
    // Step 1: Load configuration
    let config = match ServerConfig::load_from_current_dir("server.toml") {
        Ok(c) => c,
        Err(_) => {
            // Fallback defaults for quick testing
            ServerConfig {
                bind_addr: "0.0.0.0".to_string(),
                bind_port: 20264,
                secret: "ttt".to_string(),
                heartbeat_interval_secs: 10,
                client_timeout_secs: 30,
            }
        }
    };

    // Step 2: Setup binding address
    let bind_addr = format!("{}:{}", config.bind_addr, config.bind_port);
    println!("Server starting on {}", bind_addr);

    // Step 3: Initialize client registry (shared across all connections)
    let clients: ClientRegistry = Arc::new(Mutex::new(HashMap::new()));
    let secret = config.secret.clone();

    // Step 4: Start TCP listener and accept connections
    match TcpListener::bind(&bind_addr).await {
        Result::Ok(listener) => loop {
            // Accept new client connection
            let client = listener.accept().await;
            match client {
                Result::Ok((socket, _peer_addr)) => {
                    // Disable Nagle's algorithm for lower latency
                    // WHY: We want each frame to be sent immediately without buffering
                    socket.set_nodelay(true).ok();
                    
                    // Clone references for the new client task
                    let clients_clone = clients.clone();
                    let secret_clone = secret.clone();
                    
                    // Spawn async handler for this client
                    // WHY: Each client gets its own task - they run concurrently
                    tokio::spawn(on_client_accepted(socket, clients_clone, secret_clone));
                }
                Result::Err(_) => {
                    // Log error but continue accepting other clients
                }
            }
        },
        Result::Err(_) => {
            // Failed to bind - nothing we can do
        }
    }
}


/// Handle a newly accepted client connection.
///
/// # Arguments
/// * `socket` - The TCP stream for this client
/// * `clients` - Shared client registry
/// * `secret` - Secret for heartbeat verification
///
/// # How It Works
/// 1. Get client address for logging
/// 2. Split socket into read and write halves
/// 3. Wrap writer in Arc<Mutex> for shared access
/// 4. Start the read loop
async fn on_client_accepted(
    socket: TcpStream,
    clients: ClientRegistry,
    secret: String,
) {
    // Log client connection for debugging
    let addr = socket.peer_addr().unwrap();
    println!("Client connected: {}", addr);

    // Split into read and write halves
    // WHY: We need independent access to read and write - they're used in different contexts
    let (r, w) = socket.into_split();
    
    // Wrap writer in Mutex for shared access (registry holds this)
    // WHY: The registry is shared, so the writer needs to be thread-safe
    let writer_arc = Arc::new(Mutex::new(w));
    
    // Start reading frames from this client
    read_loop(r, writer_arc, clients, secret).await
}


/// Main read loop for processing client frames.
///
/// This is the core of the server's client handling. It:
/// 1. Reads TCP data into a buffer
/// 2. Parses protocol frames from the buffer
/// 3. Handles heartbeat frames (client registration)
/// 4. Handles data frames (packet forwarding)
///
/// # Arguments
/// * `r` - Read half of TCP connection
/// * `writer` - Write half for sending frames to this client
/// * `clients` - Shared client registry
/// * `secret` - Secret for heartbeat verification
async fn read_loop(
    r: OwnedReadHalf,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    clients: ClientRegistry,
    secret: String,
) {
    // Wrap in BufReader for efficient reading
    // WHY: Reduces syscalls by buffering data internally
    let mut reader = BufReader::new(r);
    
    // Accumulate received data
    // WHY: TCP is a stream - data may arrive fragmented or combined
    let mut buffer = Vec::with_capacity(65536);
    
    // Track this client's registered IP
    let mut client_ip: Option<Ipv4Addr> = None;

    // Main read loop - runs until connection closes or error
    loop {
        // Read data from TCP stream
        let mut tmp_buffer = [0u8; 65536];
        match reader.read(&mut tmp_buffer).await {
            Ok(0) => {
                // Connection closed by client
                break;
            }
            Ok(n) => {
                // Add new data to buffer
                buffer.extend_from_slice(&tmp_buffer[..n]);
                
                // Security: prevent buffer overflow attacks
                if buffer.len() > MAX_BUFFER_SIZE {
                    buffer.clear();
                    break;
                }
            }
            Err(_) => {
                // Read error - terminate connection
                break;
            }
        }

        // Process all complete frames in buffer
        // HOW: parse_frame returns (frame, remaining) - loop until no more frames
        while !buffer.is_empty() {
            match rusttun::shared::data::parse_frame_with_secret(&buffer, &secret) {
                Ok((frame, remaining)) => {
                    buffer = remaining.to_vec();

                    // Handle frame based on type
                    match frame.kind {
                        FrameType::Heartbeat => {
                            // Registration frame - extract client IP
                            if let Some(reg_ip) = frame.get_heartbeat_ip() {
                                let client_ip_addr = Ipv4Addr::from_bits(reg_ip);
                                
                                // First heartbeat from this client - register them
                                if client_ip.is_none() {
                                    client_ip = Some(client_ip_addr);
                                    let mut client_map = clients.lock().await;
                                    client_map.insert(
                                        client_ip_addr,
                                        ClientInfo {
                                            writer: writer.clone(),
                                        },
                                    );
                                }
                            }
                        }
                        FrameType::Data => {
                            // Data frame - forward to destination client
                            
                            // First data frame may carry registration IP too
                            // HOW: Extract source IP from IP packet header
                            if client_ip.is_none() {
                                if let Some(src_ip) = extract_src_ip(&frame.data) {
                                    client_ip = Some(src_ip);
                                    let mut client_map = clients.lock().await;
                                    client_map.insert(
                                        src_ip,
                                        ClientInfo {
                                            writer: writer.clone(),
                                        },
                                    );
                                }
                            }

                            // Route packet to destination client based on dst IP
                            if let Some(dst_ip) = frame.get_dst_ip() {
                                let dst = Ipv4Addr::from_bits(dst_ip);
                                let frame_bytes = frame.to_bytes();
                                
                                // Lookup destination client in registry
                                let client_map = clients.lock().await;
                                if let Some(client_info) = client_map.get(&dst) {
                                    // Forward the packet
                                    let mut writer = client_info.writer.lock().await;
                                    let _ = writer.write_all(&frame_bytes).await;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    // Parse error handling
                    if e.kind() == ErrorKind::UnexpectedEof {
                        // Incomplete frame - wait for more data
                        break;
                    }
                    // Invalid frame - clear buffer and terminate
                    buffer.clear();
                    break;
                }
            }
        }
    }

    // Cleanup: remove client from registry on disconnect
    if let Some(ip) = client_ip {
        clients.lock().await.remove(&ip);
    }
}


/// Extract source IP address from IP packet data.
///
/// # Why
/// When a client sends its first data packet before registering via heartbeat,
/// we can extract their IP from the IP packet header. This enables "lazy registration"
/// where the IP is inferred from packet source rather than explicit heartbeat.
///
/// # How
/// IPv4 header structure:
/// - Bytes 0-3: Version (4), IHL, ToS, Total Length
/// - Bytes 12-15: Source IP Address
/// - Bytes 16-19: Destination IP Address
///
/// We verify it's IPv4 (version = 4) and extract bytes 12-15.
fn extract_src_ip(data: &[u8]) -> Option<Ipv4Addr> {
    if data.len() >= 20 {
        // Check IP version (high 4 bits of first byte)
        let version = (data[0] >> 4) & 0x0F;
        if version == 4 {
            // Extract source IP from bytes 12-15
            Some(Ipv4Addr::new(data[12], data[13], data[14], data[15]))
        } else {
            None
        }
    } else {
        None
    }
}
