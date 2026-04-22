//! # TUN Proxy Client
//!
//! This is the client component of the TUN proxy system. It connects to the server,
//! creates a TUN interface, and bidirectionally tunnels IP packets between the local
//! TUN interface and the remote server.
//!
//! ## Architecture
//!
//! **Client Design:**
//! - Connects to server via TCP
//! - Creates a virtual TUN interface with specified IP
//! - Spawns concurrent tasks for:
//!   - Sending heartbeats (registration + keep-alive)
//!   - Reading from TUN and sending to server
//!   - Reading from server and writing to TUN
//!
//! **Data Flow:**
//! ```text
//! Local Network <--TUN--> Client <--TCP--> Server <--TUN--> Remote Network
//! ```
//!
//! **Startup Flow:**
//! 1. Load configuration (from file or defaults)
//! 2. Connect to server via TCP
//! 3. Create TUN interface with configured IP
//! 4. Spawn heartbeat task (periodically sends registration)
//! 5. Spawn TUN handler (reads IP packets from TUN)
//! 6. Spawn sender/receiver tasks (TCP bidirectional forwarding)
//! 7. Handle reconnection on disconnect

use bytes::Bytes;
use rusttun::shared::config::ClientConfig;
use rusttun::shared::data::{FrameType, PackageFrame};
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tun_rs::DeviceBuilder;

/// Maximum buffer size to prevent memory exhaustion.
///
/// HOW: If server sends data faster than we can process it, buffer grows.
/// This limit prevents a malicious server from consuming all client memory.
const MAX_BUFFER_SIZE: usize = 1024 * 1024;

/// Buffer size for reading from TUN interface.
///
/// HOW: TUN packets can be up to 65536 bytes (IPv4 max).
/// Using 64KB buffer handles most real-world packets.
const TUN_READ_BUF_SIZE: usize = 65536;

/// Batch size for writing to TUN interface.
///
/// HOW: When receiving multiple packets from server, batch them together
/// to reduce TUN write syscalls. Balance between latency and throughput.
const TUN_WRITE_BATCH_SIZE: usize = 64;

/// Client entry point with reconnection logic.
///
/// # How It Works
/// 1. Load configuration (from file or defaults)
/// 2. Enter reconnect loop
/// 3. Attempt to run client session
/// 4. On failure, wait and retry
/// 5. Exit after max attempts (if configured)
///
/// # Configuration
/// Looks for `client.toml` in current directory. If not found, uses hardcoded
/// defaults. This allows easy deployment without explicit path arguments.
#[tokio::main]
async fn main() {
    // Step 1: Load configuration
    let config = match ClientConfig::load_from_current_dir("client.toml") {
        Ok(c) => c,
        Err(_) => {
            // Fallback defaults for quick testing
            ClientConfig {
                server_addr: "127.0.0.1".to_string(),
                server_port: 20264,
                tun_ip: "10.0.3.5".to_string(),
                tun_netmask: 24,
                secret: "ttt".to_string(),
                reconnect_delay_secs: 3,
                max_reconnect_attempts: 0,
                heartbeat_interval_secs: 5,
            }
        }
    };

    // Setup server address for connection
    let server_addr = format!("{}:{}", config.server_addr, config.server_port);
    let mut attempt = 0;

    // Step 2: Reconnection loop
    loop {
        attempt += 1;

        // Check if we've exceeded max attempts (0 = infinite)
        if config.max_reconnect_attempts > 0 && attempt > config.max_reconnect_attempts {
            break;
        }

        println!(
            "[Attempt {}] Connecting to server {}...",
            attempt, server_addr
        );

        // Step 3: Attempt client session
        match run_client(&config, &server_addr).await {
            Ok(_) => break,
            Err(e) => {
                // Step 4: Handle connection failure
                println!(
                    "[Attempt {}] Connection failed: {}. Reconnecting in {}s...",
                    attempt, e, config.reconnect_delay_secs
                );
                sleep(Duration::from_secs(config.reconnect_delay_secs)).await;
            }
        }
    }
}

/// Run a single client session.
///
/// # Arguments
/// * `config` - Client configuration
/// * `server_addr` - Server address string
///
/// # Returns
/// Ok(()) on clean disconnect, Err(String) on error.
///
/// # How It Works
/// 1. Connect to server via TCP
/// 2. Create TUN interface
/// 3. Setup channels for message passing
/// 4. Spawn concurrent tasks:
///    - Heartbeat sender
///    - TUN packet handler
///    - TCP sender (server-bound)
///    - TCP receiver (from server)
/// 5. Wait for any task to complete
/// 6. Cleanup and return error (triggers reconnection)
async fn run_client(config: &ClientConfig, server_addr: &str) -> Result<(), String> {
    // Step 1: Connect to server
    let stream = TcpStream::connect(server_addr)
        .await
        .map_err(|e| format!("Failed to connect: {}", e))?;

    // Disable Nagle's algorithm for lower latency
    // HOW: Send frames immediately without waiting for more data
    stream.set_nodelay(true).ok();

    // Step 2: Create TUN interface
    let tun_ip = config.tun_ip_addr();
    let tun = create_tun_device(tun_ip, config.tun_netmask)
        .await
        .map_err(|e| e.to_string())?;

    // Step 3: Split TCP stream
    let (r, w) = stream.into_split();

    // Step 4: Setup channels for inter-task communication
    // HOW: mpsc (multi-producer single-consumer) channels pass frames between tasks
    // - tx/rx: For sending frames to server
    // - tun_write_tx/tun_write_rx: For sending packets to TUN
    let (tx, rx) = mpsc::channel::<Bytes>(8192);
    let (tun_write_tx, tun_write_rx) = mpsc::channel::<Bytes>(8192);

    // Step 5: Spawn heartbeat task
    // WHY: Periodically sends heartbeat frames for registration + keep-alive
    let tx_hb = tx.clone();
    let heartbeat_interval = config.heartbeat_interval_secs;
    let heartbeat_secret = config.secret.clone();
    tokio::spawn(async move {
        heartbeat_thread(tx_hb, tun_ip, heartbeat_interval, &heartbeat_secret).await;
    });

    // Step 6: Spawn TUN handler task
    // WHY: Reads IP packets from TUN interface and sends to server
    let tx_clone = tx.clone();
    let secret = config.secret.clone();
    tokio::spawn(async move {
        tun_handler(tun, tx_clone, tun_write_rx, secret).await;
    });

    // Step 7: Spawn TCP sender task (client -> server)
    let mut w = w;
    let sender_handle = tokio::spawn(async move {
        let mut rx = rx;

        loop {
            tokio::select! {
                data = rx.recv() => {
                    match data {
                        Some(d) => {
                            if w.write_all(&d).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    // Step 8: Spawn TCP receiver task (server -> client)
    let tun_write_tx_clone = tun_write_tx.clone();
    let secret_for_tcp = config.secret.clone();
    let mut r = r;
    let receiver_handle = tokio::spawn(async move {
        let mut buffer = Vec::with_capacity(65536);

        // Read loop with timeout for non-blocking checks
        loop {
            let mut tmp_buffer = vec![0u8; 65536];
            match timeout(Duration::from_millis(100), r.read(&mut tmp_buffer)).await {
                Ok(Ok(n)) => {
                    if n == 0 {
                        break;
                    }
                    buffer.extend_from_slice(&tmp_buffer[..n]);

                    // Security: limit buffer size
                    if buffer.len() > MAX_BUFFER_SIZE {
                        buffer.clear();
                        break;
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => continue,
            }

            // Process all complete frames
            while !buffer.is_empty() {
                match rusttun::shared::data::parse_frame_with_secret(&buffer, &secret_for_tcp) {
                    Ok((frame, remaining)) => {
                        // Send data frames to TUN
                        if !frame.data.is_empty() {
                            let _ = tun_write_tx_clone.send(frame.data.clone()).await;
                        }
                        buffer = remaining.to_vec();
                    }
                    Err(e) => {
                        if e.kind() == ErrorKind::UnexpectedEof {
                            break;
                        }
                        buffer.clear();
                        break;
                    }
                }
            }
        }
    });

    // Step 9: Wait for any task to complete
    // HOW: If either sender or receiver fails, the session ends
    tokio::select! {
        _ = sender_handle => {}
        _ = receiver_handle => {}
    }

    // Step 10: Cleanup
    drop(tx);
    drop(tun_write_tx);

    // Return error to trigger reconnection
    Err("Connection lost".to_string())
}

/// Create and configure a TUN interface.
///
/// # Arguments
/// * `tun_ip` - IP address for the TUN interface
/// * `tun_netmask` - Netmask/CIDR prefix length
///
/// # Returns
/// Ok(AsyncDevice) on success, Err(String) on failure.
///
/// # How It Works
/// 1. Generate TUN interface name based on IP (e.g., "rs-tun-3" for 10.0.3.x)
/// 2. Try to create new TUN device
/// 3. If name conflict, try to open existing device
/// 4. If already in use, return appropriate error
async fn create_tun_device(
    tun_ip: Ipv4Addr,
    tun_netmask: u8,
) -> Result<tun_rs::AsyncDevice, String> {
    // Generate name from IP: rs-tun-{third_octet}
    let name = format!("rs-tun-{}", tun_ip.octets()[2]);

    match DeviceBuilder::new()
        .name(&name)
        .ipv4(tun_ip, tun_netmask, None)
        .build_async()
    {
        Ok(dev) => Ok(dev),
        Err(e) => {
            let err_msg = e.to_string();
            // Handle name conflict - try to open existing device
            if err_msg.contains("对象已存在") || err_msg.contains("already exists") {
                match DeviceBuilder::new().name(&name).build_async() {
                    Ok(dev) => Ok(dev),
                    Err(e2) => {
                        let err2_msg = e2.to_string();
                        // Check if already in use
                        if err2_msg.contains("1247") || err2_msg.contains("初始化已完成") {
                            Err(format!("TUN interface '{}' is already in use", name))
                        } else {
                            Err(format!("Failed to open TUN interface '{}': {}", name, e2))
                        }
                    }
                }
            } else {
                Err(format!("Failed to create TUN device: {}", e))
            }
        }
    }
}

/// Heartbeat sending task.
///
/// # Why
/// Sends periodic heartbeat frames to:
/// 1. Register the client's TUN IP with the server
/// 2. Keep the connection alive (TCP keep-alive may not be enough)
/// 3. Allow server to detect disconnection
///
/// # How
/// Runs in an infinite loop, sending heartbeat at configured interval.
/// Exits when the channel is closed (client disconnecting).
async fn heartbeat_thread(
    tx: mpsc::Sender<Bytes>,
    tun_ip: Ipv4Addr,
    interval_secs: u64,
    secret: &str,
) {
    loop {
        // Create heartbeat frame with client's TUN IP
        let frame = PackageFrame::new_heartbeat(tun_ip.to_bits(), secret);
        let data = frame.into_bytes();

        // Send to server
        if tx.send(data).await.is_err() {
            break;
        }

        // Wait for next interval
        sleep(Duration::from_secs(interval_secs)).await;
    }
}

/// TUN interface handler.
///
/// # Why
/// Handles bidirectional packet flow between TUN interface and the server:
/// 1. Reads IP packets from TUN and sends to server
/// 2. Receives packets from server and writes to TUN
///
/// # How
/// Uses tokio::select! to concurrently handle:
/// - Incoming packets from TUN
/// - Incoming packets from server (via channel)
/// - Batch write deadline
async fn tun_handler(
    tun: tun_rs::AsyncDevice,
    tx: mpsc::Sender<Bytes>,
    mut tun_write_rx: mpsc::Receiver<Bytes>,
    secret: String,
) {
    let mut tun_buf = vec![0u8; TUN_READ_BUF_SIZE];
    let mut write_batch: Vec<Bytes> = Vec::with_capacity(TUN_WRITE_BATCH_SIZE);
    let mut batch_deadline = tokio::time::Instant::now() + Duration::from_millis(1);

    loop {
        tokio::select! {
            // Read from TUN interface
            result = tun.recv(&mut tun_buf) => {
                match result {
                    Ok(len) => {
                        // Skip very short packets (likely invalid)
                        if len < 20 {
                            continue;
                        }

                        // Verify IPv4 (version = 4)
                        let version = (tun_buf[0] >> 4) & 0x0F;
                        if version != 4 {
                            continue;
                        }

                        // Wrap in protocol frame and send to server
                        let packet = tun_buf[..len].to_vec();
                        let frame = PackageFrame::new_with_secret(
                            FrameType::Data,
                            packet.into(),
                            &secret,
                        );
                        if tx.send(frame.into_bytes()).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            // Receive packets from server
            data = tun_write_rx.recv() => {
                match data {
                    Some(d) => {
                        write_batch.push(d);

                        // Batch write when full or deadline reached
                        let now = tokio::time::Instant::now();
                        if write_batch.len() >= TUN_WRITE_BATCH_SIZE || now >= batch_deadline {
                            for pkt in write_batch.drain(..) {
                                if let Err(e) = tun.send(&pkt).await {
                                    eprintln!("TUN send error: {}", e);
                                    break;
                                }
                            }
                            batch_deadline = now + Duration::from_millis(1);
                        }
                    }
                    None => {
                        // Channel closed - flush remaining and exit
                        for pkt in write_batch.drain(..) {
                            let _ = tun.send(&pkt).await;
                        }
                        break;
                    }
                }
            }

            // Batch write deadline timer
            _ = tokio::time::sleep_until(batch_deadline), if !write_batch.is_empty() => {
                for pkt in write_batch.drain(..) {
                    if let Err(e) = tun.send(&pkt).await {
                        eprintln!("TUN send error: {}", e);
                        break;
                    }
                }
                batch_deadline = tokio::time::Instant::now() + Duration::from_millis(1);
            }
        }
    }
}
