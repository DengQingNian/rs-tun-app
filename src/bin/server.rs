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

use base64::Engine;
use rusttun::shared::config::ServerConfig;
use rusttun::shared::data::FrameType;
use rusttun::shared::stats::TrafficStats;
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
                stats: Default::default(),
            }
        }
    };

    // Step 2: Setup binding address
    let bind_addr = format!("{}:{}", config.bind_addr, config.bind_port);
    println!("Server starting on {}", bind_addr);

    // Step 3: Initialize client registry (shared across all connections)
    let clients: ClientRegistry = Arc::new(Mutex::new(HashMap::new()));
    let secret = config.secret.clone();
    let stats = Arc::new(TrafficStats::default());

    if config.stats.enabled {
        match validate_stats_config(&config.stats) {
            Ok(()) => {
                let stats_config = config.stats.clone();
                let stats_clone = stats.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_stats_server(stats_config, stats_clone).await {
                        eprintln!("Stats server stopped: {}", e);
                    }
                });
            }
            Err(message) => eprintln!("Stats server disabled: {}", message),
        }
    }

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
                    let stats_clone = stats.clone();

                    // Spawn async handler for this client
                    // WHY: Each client gets its own task - they run concurrently
                    tokio::spawn(on_client_accepted(
                        socket,
                        clients_clone,
                        secret_clone,
                        stats_clone,
                    ));
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
    stats: Arc<TrafficStats>,
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
    stats.record_connection_opened();

    // Start reading frames from this client
    read_loop(r, writer_arc, clients, secret, stats).await
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
    stats: Arc<TrafficStats>,
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
                stats.record_bytes_received(n);

                // Security: prevent buffer overflow attacks
                if buffer.len() > MAX_BUFFER_SIZE {
                    buffer.clear();
                    stats.record_parse_error();
                    break;
                }
            }
            Err(_) => {
                // Read error - terminate connection
                stats.record_read_error();
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
                            stats.record_heartbeat_frame();

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
                                    stats.set_registered_clients(client_map.len());
                                }
                            }
                        }
                        FrameType::Data => {
                            stats.record_data_frame();

                            // Data frame - forward to destination client

                            // First data frame may carry registration IP too
                            // HOW: Extract source IP from IP packet header
                            if client_ip.is_none()
                                && let Some(src_ip) = extract_src_ip(&frame.data)
                            {
                                client_ip = Some(src_ip);
                                let mut client_map = clients.lock().await;
                                client_map.insert(
                                    src_ip,
                                    ClientInfo {
                                        writer: writer.clone(),
                                    },
                                );
                                stats.set_registered_clients(client_map.len());
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
                                    match writer.write_all(&frame_bytes).await {
                                        Ok(()) => stats.record_forwarded_frame(frame_bytes.len()),
                                        Err(_) => stats.record_write_error(),
                                    }
                                } else {
                                    stats.record_dropped_frame();
                                }
                            } else {
                                stats.record_dropped_frame();
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
                    stats.record_parse_error();
                    buffer.clear();
                    break;
                }
            }
        }
    }

    // Cleanup: remove client from registry on disconnect
    if let Some(ip) = client_ip {
        let mut client_map = clients.lock().await;
        client_map.remove(&ip);
        stats.set_registered_clients(client_map.len());
    }

    stats.record_connection_closed();
}

/// Run the HTTP statistics API and dashboard.
async fn run_stats_server(
    config: rusttun::shared::config::StatsConfig,
    stats: Arc<TrafficStats>,
) -> Result<()> {
    let bind_addr = format!("{}:{}", config.bind_addr, config.bind_port);
    let listener = TcpListener::bind(&bind_addr).await?;
    println!("Stats dashboard listening on http://{}", bind_addr);

    let username = config.username.as_deref().unwrap_or_default();
    let password = config.password.as_deref().unwrap_or_default();
    let expected_auth = build_basic_auth_header(username, password);

    loop {
        let (socket, _) = listener.accept().await?;
        let stats_clone = stats.clone();
        let expected_auth_clone = expected_auth.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_stats_connection(socket, stats_clone, expected_auth_clone).await
            {
                eprintln!("Stats request failed: {}", e);
            }
        });
    }
}

/// Validate that enabled stats configuration is safe enough to start.
fn validate_stats_config(
    config: &rusttun::shared::config::StatsConfig,
) -> std::result::Result<(), &'static str> {
    if config.username.as_deref().is_none_or(str::is_empty) {
        return Err("[stats].username must be set when stats are enabled");
    }

    if config.password.as_deref().is_none_or(str::is_empty) {
        return Err("[stats].password must be set when stats are enabled");
    }

    Ok(())
}

/// Handle one HTTP request for the stats API or dashboard.
async fn handle_stats_connection(
    socket: TcpStream,
    stats: Arc<TrafficStats>,
    expected_auth: String,
) -> Result<()> {
    let mut reader = BufReader::new(socket);
    let mut request = Vec::with_capacity(4096);
    let mut tmp_buffer = [0u8; 1024];

    loop {
        let n = reader.read(&mut tmp_buffer).await?;
        if n == 0 {
            return Ok(());
        }

        request.extend_from_slice(&tmp_buffer[..n]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") || request.len() >= 8192 {
            break;
        }
    }

    let response = build_stats_response(&request, &stats, &expected_auth);
    let stream = reader.get_mut();
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

/// Build a complete HTTP response for a raw stats HTTP request.
fn build_stats_response(request: &[u8], stats: &TrafficStats, expected_auth: &str) -> String {
    let Ok(request_text) = std::str::from_utf8(request) else {
        return http_response(
            "400 Bad Request",
            "text/plain; charset=utf-8",
            "Bad request",
        );
    };

    if !is_authorized(request_text, expected_auth) {
        return unauthorized_response();
    }

    let path = request_text
        .lines()
        .next()
        .and_then(|request_line| request_line.split_whitespace().nth(1))
        .unwrap_or("/");

    match path {
        "/" | "/dashboard" => http_response("200 OK", "text/html; charset=utf-8", DASHBOARD_HTML),
        "/api/stats" | "/stats" => match serde_json::to_string_pretty(&stats.snapshot()) {
            Ok(body) => http_response("200 OK", "application/json; charset=utf-8", &body),
            Err(_) => http_response(
                "500 Internal Server Error",
                "text/plain; charset=utf-8",
                "Failed to serialize stats",
            ),
        },
        _ => http_response("404 Not Found", "text/plain; charset=utf-8", "Not found"),
    }
}

/// Check whether an HTTP request contains the expected Basic Auth header.
fn is_authorized(request_text: &str, expected_auth: &str) -> bool {
    request_text.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };

        name.eq_ignore_ascii_case("authorization") && value.trim() == expected_auth
    })
}

/// Return the expected HTTP Basic Auth header value.
fn build_basic_auth_header(username: &str, password: &str) -> String {
    let token =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password));
    format!("Basic {}", token)
}

/// Build an HTTP 401 response with the Basic Auth challenge header.
fn unauthorized_response() -> String {
    let body = "Authentication required";
    format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"rs-tun stats\"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body,
    )
}

/// Build a simple HTTP response.
fn http_response(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        body.len(),
        body,
    )
}

const DASHBOARD_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>rs-tun Traffic Stats</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; background: #0f172a; color: #e2e8f0; }
    h1 { margin-bottom: 0.25rem; }
    .muted { color: #94a3b8; margin-bottom: 1.5rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1rem; }
    .label { color: #94a3b8; font-size: 0.9rem; }
    .value { font-size: 1.8rem; font-weight: 700; margin-top: 0.25rem; }
    .error { color: #fca5a5; }
  </style>
</head>
<body>
  <h1>rs-tun Traffic Stats</h1>
  <div class="muted">Auto-refreshes every 2 seconds. JSON API: <code>/api/stats</code></div>
  <div id="status" class="muted">Loading...</div>
  <div id="stats" class="grid"></div>
  <script>
    const labels = {
      current_connections: 'Current Connections',
      total_connections: 'Total Connections',
      registered_clients: 'Registered Clients',
      bytes_received: 'Bytes Received',
      frames_received: 'Frames Received',
      heartbeat_frames: 'Heartbeat Frames',
      data_frames: 'Data Frames',
      bytes_forwarded: 'Bytes Forwarded',
      frames_forwarded: 'Frames Forwarded',
      frames_dropped: 'Frames Dropped',
      parse_errors: 'Parse Errors',
      read_errors: 'Read Errors',
      write_errors: 'Write Errors'
    };

    function render(stats) {
      document.getElementById('status').textContent = 'Last updated: ' + new Date().toLocaleTimeString();
      document.getElementById('stats').innerHTML = Object.entries(labels).map(([key, label]) => `
        <div class="card">
          <div class="label">${label}</div>
          <div class="value">${Number(stats[key] ?? 0).toLocaleString()}</div>
        </div>
      `).join('');
    }

    async function refresh() {
      try {
        const response = await fetch('/api/stats');
        if (!response.ok) throw new Error('HTTP ' + response.status);
        render(await response.json());
      } catch (error) {
        document.getElementById('status').innerHTML = '<span class="error">Failed to load stats: ' + error.message + '</span>';
      }
    }

    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>"#;

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
