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
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Unique TCP connection identifier that owns this registry slot.
    connection_id: u64,

    /// Write half of the TCP connection for sending frames to client.
    writer: Arc<Mutex<OwnedWriteHalf>>,
}

/// State tracked while one TCP connection is being read.
struct ConnectionContext {
    id: u64,
    ip: Option<Ipv4Addr>,
    peer_addr: SocketAddr,
    pending_received_bytes: u64,
}

/// Type alias for the client registry.
///
/// WHY: The registry maps a client's TUN IP address to their connection metadata.
/// This enables O(1) lookup for packet routing.
type ClientRegistry = Arc<Mutex<HashMap<Ipv4Addr, ClientInfo>>>;

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

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
    let stats = Arc::new(TrafficStats::new());

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
    let addr = socket
        .peer_addr()
        .expect("accepted socket has peer address");
    println!("Client connected: {}", addr);

    // Split into read and write halves
    // WHY: We need independent access to read and write - they're used in different contexts
    let (r, w) = socket.into_split();
    let connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);

    // Wrap writer in Mutex for shared access (registry holds this)
    // WHY: The registry is shared, so the writer needs to be thread-safe
    let writer_arc = Arc::new(Mutex::new(w));
    stats.record_connection_opened();

    // Start reading frames from this client
    read_loop(r, writer_arc, clients, secret, stats, addr, connection_id).await
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
    peer_addr: SocketAddr,
    connection_id: u64,
) {
    // Wrap in BufReader for efficient reading
    // WHY: Reduces syscalls by buffering data internally
    let mut reader = BufReader::new(r);

    // Accumulate received data
    // WHY: TCP is a stream - data may arrive fragmented or combined
    let mut buffer = Vec::with_capacity(65536);

    // Track this client's registered IP
    let mut connection = ConnectionContext {
        id: connection_id,
        ip: None,
        peer_addr,
        pending_received_bytes: 0,
    };

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
                if let Some(ip) = connection.ip {
                    stats.record_connection_bytes_received(ip, n);
                } else {
                    connection.pending_received_bytes += n as u64;
                }

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
                                register_client_if_needed(
                                    &mut connection,
                                    client_ip_addr,
                                    writer.clone(),
                                    &clients,
                                    &stats,
                                )
                                .await;
                            }
                        }
                        FrameType::Data => {
                            stats.record_data_frame();

                            // Data frame - forward to destination client

                            // First data frame may carry registration IP too
                            // HOW: Extract source IP from IP packet header
                            if connection.ip.is_none()
                                && let Some(src_ip) = extract_src_ip(&frame.data)
                            {
                                register_client_if_needed(
                                    &mut connection,
                                    src_ip,
                                    writer.clone(),
                                    &clients,
                                    &stats,
                                )
                                .await;
                            }

                            if let Some(ip) = connection.ip {
                                stats.record_connection_data_frame(ip);
                            }

                            // Route packet to destination client based on dst IP
                            if let Some(dst_ip) = frame.get_dst_ip() {
                                let dst = Ipv4Addr::from_bits(dst_ip);
                                let frame_bytes = frame.to_bytes();

                                // Lookup destination client in registry
                                let destination_writer = {
                                    let client_map = clients.lock().await;
                                    client_map
                                        .get(&dst)
                                        .map(|client_info| client_info.writer.clone())
                                };

                                if let Some(destination_writer) = destination_writer {
                                    // Forward the packet
                                    let mut writer = destination_writer.lock().await;
                                    match writer.write_all(&frame_bytes).await {
                                        Ok(()) => {
                                            stats.record_forwarded_frame(frame_bytes.len());
                                            stats.record_connection_forwarded_frame(
                                                dst,
                                                frame_bytes.len(),
                                            );
                                        }
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
    if let Some(ip) = connection.ip {
        let mut client_map = clients.lock().await;
        let owns_registry_slot = client_map
            .get(&ip)
            .is_some_and(|client_info| client_info.connection_id == connection.id);
        if owns_registry_slot {
            client_map.remove(&ip);
            stats.set_registered_clients(client_map.len());
            stats.unregister_connection(ip, connection.id);
        }
    }

    stats.record_connection_closed();
}

/// Register the client IP once and attach any bytes read before registration.
async fn register_client_if_needed(
    connection: &mut ConnectionContext,
    ip: Ipv4Addr,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    clients: &ClientRegistry,
    stats: &TrafficStats,
) {
    if connection.ip.is_some() {
        return;
    }

    connection.ip = Some(ip);
    let mut client_map = clients.lock().await;
    client_map.insert(
        ip,
        ClientInfo {
            connection_id: connection.id,
            writer,
        },
    );
    stats.set_registered_clients(client_map.len());
    stats.register_connection(ip, connection.id, &connection.peer_addr.to_string());

    if connection.pending_received_bytes > 0 {
        stats.record_connection_bytes_received(ip, connection.pending_received_bytes as usize);
        connection.pending_received_bytes = 0;
    }
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
    h2 { margin-top: 2rem; }
    .muted { color: #94a3b8; margin-bottom: 1.5rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }
    .card, .panel { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1rem; }
    .label { color: #94a3b8; font-size: 0.9rem; }
    .value { font-size: 1.8rem; font-weight: 700; margin-top: 0.25rem; }
    canvas { width: 100%; height: 260px; background: #0f172a; border-radius: 8px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 0.65rem; border-bottom: 1px solid #334155; text-align: left; }
    th { color: #94a3b8; font-size: 0.85rem; font-weight: 600; }
    .bar { height: 0.5rem; background: #334155; border-radius: 999px; overflow: hidden; min-width: 80px; }
    .bar > span { display: block; height: 100%; background: linear-gradient(90deg, #22c55e, #38bdf8); }
    .empty { color: #94a3b8; padding: 1rem 0; }
    .error { color: #fca5a5; }
  </style>
</head>
<body>
  <h1>rs-tun Traffic Stats</h1>
  <div class="muted">Auto-refreshes every 2 seconds. JSON API: <code>/api/stats</code></div>
  <div id="status" class="muted">Loading...</div>
  <div id="stats" class="grid"></div>
  <h2>Traffic Chart</h2>
  <div class="panel"><canvas id="traffic-chart" width="1000" height="260"></canvas></div>
  <h2>Active Connections</h2>
  <div id="connections" class="panel"></div>
  <script>
    const labels = {
      uptime_secs: 'Server Uptime',
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

    function formatBytes(bytes) {
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      let value = Number(bytes ?? 0);
      let unit = 0;
      while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
      }
      return value.toLocaleString(undefined, { maximumFractionDigits: unit === 0 ? 0 : 1 }) + ' ' + units[unit];
    }

    function formatDuration(seconds) {
      let remaining = Number(seconds ?? 0);
      const hours = Math.floor(remaining / 3600);
      remaining %= 3600;
      const minutes = Math.floor(remaining / 60);
      const secs = remaining % 60;
      return [hours, minutes, secs].map(value => String(value).padStart(2, '0')).join(':');
    }

    function render(stats) {
      document.getElementById('status').textContent = 'Last updated: ' + new Date().toLocaleTimeString();
      document.getElementById('stats').innerHTML = Object.entries(labels).map(([key, label]) => `
        <div class="card">
          <div class="label">${label}</div>
          <div class="value">${key.includes('bytes') ? formatBytes(stats[key]) : key.includes('uptime') ? formatDuration(stats[key]) : Number(stats[key] ?? 0).toLocaleString()}</div>
        </div>
      `).join('');
      renderConnections(stats.connections ?? []);
      renderTrafficChart(stats.traffic_series ?? []);
    }

    function renderConnections(connections) {
      if (connections.length === 0) {
        document.getElementById('connections').innerHTML = '<div class="empty">No registered connections yet.</div>';
        return;
      }

      document.getElementById('connections').innerHTML = `
        <table>
          <thead>
            <tr>
              <th>Client IP</th>
              <th>Peer</th>
              <th>Online</th>
              <th>Received</th>
              <th>Forwarded</th>
              <th>Frames RX/TX</th>
              <th>Traffic Share</th>
            </tr>
          </thead>
          <tbody>
            ${connections.map(connection => `
              <tr>
                <td>${connection.ip}</td>
                <td>${connection.peer_addr}</td>
                <td>${formatDuration(connection.online_secs)}</td>
                <td>${formatBytes(connection.bytes_received)}</td>
                <td>${formatBytes(connection.bytes_forwarded)}</td>
                <td>${Number(connection.frames_received).toLocaleString()} / ${Number(connection.frames_forwarded).toLocaleString()}</td>
                <td>
                  <div>${Number(connection.traffic_share_percent).toFixed(1)}%</div>
                  <div class="bar"><span style="width: ${Math.min(100, connection.traffic_share_percent)}%"></span></div>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderTrafficChart(series) {
      const canvas = document.getElementById('traffic-chart');
      const ctx = canvas.getContext('2d');
      const width = canvas.width;
      const height = canvas.height;
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = '#0f172a';
      ctx.fillRect(0, 0, width, height);

      const padding = 34;
      const points = series.slice(-60);
      if (points.length === 0) {
        ctx.fillStyle = '#94a3b8';
        ctx.fillText('Waiting for traffic samples...', padding, height / 2);
        return;
      }

      const maxValue = Math.max(1, ...points.map(point => Math.max(point.bytes_received, point.bytes_forwarded)));
      drawAxis(ctx, width, height, padding, maxValue);
      drawLine(ctx, points, 'bytes_received', '#38bdf8', maxValue, width, height, padding);
      drawLine(ctx, points, 'bytes_forwarded', '#22c55e', maxValue, width, height, padding);

      ctx.fillStyle = '#38bdf8';
      ctx.fillText('Received', width - 170, 24);
      ctx.fillStyle = '#22c55e';
      ctx.fillText('Forwarded', width - 90, 24);
    }

    function drawAxis(ctx, width, height, padding, maxValue) {
      ctx.strokeStyle = '#334155';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padding, padding);
      ctx.lineTo(padding, height - padding);
      ctx.lineTo(width - padding, height - padding);
      ctx.stroke();
      ctx.fillStyle = '#94a3b8';
      ctx.fillText(formatBytes(maxValue) + '/s', padding + 6, padding + 4);
      ctx.fillText('last 60s', width - 90, height - 10);
    }

    function drawLine(ctx, points, key, color, maxValue, width, height, padding) {
      const chartWidth = width - padding * 2;
      const chartHeight = height - padding * 2;
      ctx.strokeStyle = color;
      ctx.lineWidth = 3;
      ctx.beginPath();
      points.forEach((point, index) => {
        const x = padding + (points.length === 1 ? chartWidth : (chartWidth * index) / (points.length - 1));
        const y = height - padding - (Number(point[key] ?? 0) / maxValue) * chartHeight;
        if (index === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
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
