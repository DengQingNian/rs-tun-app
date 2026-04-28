//! # Server Traffic Statistics
//!
//! This module stores server traffic counters in atomics so the TCP forwarding
//! path can update metrics cheaply while the HTTP panel reads a consistent
//! snapshot for display.

use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Number of per-second traffic samples kept for the dashboard chart.
const TRAFFIC_SERIES_WINDOW_SECS: u64 = 60;

/// Thread-safe traffic counters shared by the TCP server and stats API.
#[derive(Debug)]
pub struct TrafficStats {
    started_at_epoch_secs: AtomicU64,
    current_connections: AtomicU64,
    total_connections: AtomicU64,
    registered_clients: AtomicU64,
    bytes_received: AtomicU64,
    frames_received: AtomicU64,
    heartbeat_frames: AtomicU64,
    data_frames: AtomicU64,
    bytes_forwarded: AtomicU64,
    frames_forwarded: AtomicU64,
    frames_dropped: AtomicU64,
    parse_errors: AtomicU64,
    read_errors: AtomicU64,
    write_errors: AtomicU64,
    connections: Mutex<HashMap<Ipv4Addr, ConnectionStats>>,
    traffic_series: Mutex<Vec<TrafficSeriesPoint>>,
}

/// Mutable traffic counters for one registered client connection.
#[derive(Debug, Clone)]
struct ConnectionStats {
    ip: Ipv4Addr,
    connection_id: u64,
    peer_addr: String,
    connected_at_epoch_secs: u64,
    bytes_received: u64,
    bytes_forwarded: u64,
    frames_received: u64,
    frames_forwarded: u64,
}

/// Serializable point-in-time view of a registered client connection.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionStatsSnapshot {
    pub ip: String,
    pub connection_id: u64,
    pub peer_addr: String,
    pub connected_at_epoch_secs: u64,
    pub online_secs: u64,
    pub bytes_received: u64,
    pub bytes_forwarded: u64,
    pub frames_received: u64,
    pub frames_forwarded: u64,
    pub traffic_share_percent: f64,
}

/// Serializable traffic point used by the dashboard chart.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficSeriesPoint {
    pub epoch_secs: u64,
    pub bytes_received: u64,
    pub bytes_forwarded: u64,
}

/// Serializable point-in-time view of [`TrafficStats`].
#[derive(Debug, Clone, Serialize)]
pub struct TrafficStatsSnapshot {
    pub started_at_epoch_secs: u64,
    pub uptime_secs: u64,
    pub current_connections: u64,
    pub total_connections: u64,
    pub registered_clients: u64,
    pub bytes_received: u64,
    pub frames_received: u64,
    pub heartbeat_frames: u64,
    pub data_frames: u64,
    pub bytes_forwarded: u64,
    pub frames_forwarded: u64,
    pub frames_dropped: u64,
    pub parse_errors: u64,
    pub read_errors: u64,
    pub write_errors: u64,
    pub connections: Vec<ConnectionStatsSnapshot>,
    pub traffic_series: Vec<TrafficSeriesPoint>,
}

impl TrafficStats {
    /// Create a stats collector and capture the server start time.
    pub fn new() -> Self {
        Self {
            started_at_epoch_secs: AtomicU64::new(now_epoch_secs()),
            current_connections: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            registered_clients: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            frames_received: AtomicU64::new(0),
            heartbeat_frames: AtomicU64::new(0),
            data_frames: AtomicU64::new(0),
            bytes_forwarded: AtomicU64::new(0),
            frames_forwarded: AtomicU64::new(0),
            frames_dropped: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            read_errors: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            connections: Mutex::new(HashMap::new()),
            traffic_series: Mutex::new(Vec::new()),
        }
    }

    /// Record that a TCP client connection was accepted.
    pub fn record_connection_opened(&self) {
        self.current_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a TCP client connection ended.
    pub fn record_connection_closed(&self) {
        self.current_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_sub(1)
            })
            .ok();
    }

    /// Register or refresh metadata for one routed client IP.
    pub fn register_connection(&self, ip: Ipv4Addr, connection_id: u64, peer_addr: &str) {
        let mut connections = self.connections.lock().expect("connection stats poisoned");
        let connection = ConnectionStats {
            ip,
            connection_id,
            peer_addr: peer_addr.to_string(),
            connected_at_epoch_secs: now_epoch_secs(),
            bytes_received: 0,
            bytes_forwarded: 0,
            frames_received: 0,
            frames_forwarded: 0,
        };
        connections.insert(ip, connection);
    }

    /// Remove one registered client IP from per-connection statistics.
    pub fn unregister_connection(&self, ip: Ipv4Addr, connection_id: u64) {
        let mut connections = self.connections.lock().expect("connection stats poisoned");
        let owns_stats_slot = connections
            .get(&ip)
            .is_some_and(|connection| connection.connection_id == connection_id);
        if owns_stats_slot {
            connections.remove(&ip);
        }
    }

    /// Record the current number of clients registered in the routing table.
    pub fn set_registered_clients(&self, count: usize) {
        self.registered_clients
            .store(count as u64, Ordering::Relaxed);
    }

    /// Record raw TCP bytes read from clients.
    pub fn record_bytes_received(&self, bytes: usize) {
        self.bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.record_traffic_sample(bytes as u64, 0);
    }

    /// Record raw TCP bytes read for a registered client connection.
    pub fn record_connection_bytes_received(&self, ip: Ipv4Addr, bytes: usize) {
        let mut connections = self.connections.lock().expect("connection stats poisoned");
        if let Some(connection) = connections.get_mut(&ip) {
            connection.bytes_received += bytes as u64;
        }
    }

    /// Record a parsed heartbeat frame.
    pub fn record_heartbeat_frame(&self) {
        self.frames_received.fetch_add(1, Ordering::Relaxed);
        self.heartbeat_frames.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a parsed data frame.
    pub fn record_data_frame(&self) {
        self.frames_received.fetch_add(1, Ordering::Relaxed);
        self.data_frames.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a parsed data frame for a registered client connection.
    pub fn record_connection_data_frame(&self, ip: Ipv4Addr) {
        let mut connections = self.connections.lock().expect("connection stats poisoned");
        if let Some(connection) = connections.get_mut(&ip) {
            connection.frames_received += 1;
        }
    }

    /// Record a successfully forwarded data frame.
    pub fn record_forwarded_frame(&self, bytes: usize) {
        self.frames_forwarded.fetch_add(1, Ordering::Relaxed);
        self.bytes_forwarded
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.record_traffic_sample(0, bytes as u64);
    }

    /// Record forwarded bytes for the destination client connection.
    pub fn record_connection_forwarded_frame(&self, ip: Ipv4Addr, bytes: usize) {
        let mut connections = self.connections.lock().expect("connection stats poisoned");
        if let Some(connection) = connections.get_mut(&ip) {
            connection.bytes_forwarded += bytes as u64;
            connection.frames_forwarded += 1;
        }
    }

    /// Record a data frame that could not be routed to a connected client.
    pub fn record_dropped_frame(&self) {
        self.frames_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a frame parse error.
    pub fn record_parse_error(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a TCP read error.
    pub fn record_read_error(&self) {
        self.read_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a TCP write error.
    pub fn record_write_error(&self) {
        self.write_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Return a serializable snapshot of all counters.
    pub fn snapshot(&self) -> TrafficStatsSnapshot {
        let now = now_epoch_secs();
        let started_at_epoch_secs = self.started_at_epoch_secs.load(Ordering::Relaxed);
        let traffic_series = self
            .traffic_series
            .lock()
            .expect("traffic series poisoned")
            .clone();
        let total_connection_bytes = {
            let connections = self.connections.lock().expect("connection stats poisoned");
            connections
                .values()
                .map(|connection| connection.bytes_received + connection.bytes_forwarded)
                .sum::<u64>()
        };
        let mut connections = self.connection_snapshots(now, total_connection_bytes);
        connections.sort_by(|a, b| {
            b.bytes_received
                .cmp(&a.bytes_received)
                .then(a.ip.cmp(&b.ip))
        });

        TrafficStatsSnapshot {
            started_at_epoch_secs,
            uptime_secs: now.saturating_sub(started_at_epoch_secs),
            current_connections: self.current_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            registered_clients: self.registered_clients.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            frames_received: self.frames_received.load(Ordering::Relaxed),
            heartbeat_frames: self.heartbeat_frames.load(Ordering::Relaxed),
            data_frames: self.data_frames.load(Ordering::Relaxed),
            bytes_forwarded: self.bytes_forwarded.load(Ordering::Relaxed),
            frames_forwarded: self.frames_forwarded.load(Ordering::Relaxed),
            frames_dropped: self.frames_dropped.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            read_errors: self.read_errors.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            connections,
            traffic_series,
        }
    }

    fn connection_snapshots(
        &self,
        now: u64,
        total_connection_bytes: u64,
    ) -> Vec<ConnectionStatsSnapshot> {
        let connections = self.connections.lock().expect("connection stats poisoned");
        connections
            .values()
            .map(|connection| {
                let connection_bytes = connection.bytes_received + connection.bytes_forwarded;
                let traffic_share_percent = if total_connection_bytes == 0 {
                    0.0
                } else {
                    (connection_bytes as f64 / total_connection_bytes as f64) * 100.0
                };

                ConnectionStatsSnapshot {
                    ip: connection.ip.to_string(),
                    connection_id: connection.connection_id,
                    peer_addr: connection.peer_addr.clone(),
                    connected_at_epoch_secs: connection.connected_at_epoch_secs,
                    online_secs: now.saturating_sub(connection.connected_at_epoch_secs),
                    bytes_received: connection.bytes_received,
                    bytes_forwarded: connection.bytes_forwarded,
                    frames_received: connection.frames_received,
                    frames_forwarded: connection.frames_forwarded,
                    traffic_share_percent,
                }
            })
            .collect()
    }

    fn record_traffic_sample(&self, bytes_received: u64, bytes_forwarded: u64) {
        let now = now_epoch_secs();
        let mut series = self.traffic_series.lock().expect("traffic series poisoned");

        if let Some(point) = series.last_mut()
            && point.epoch_secs == now
        {
            point.bytes_received += bytes_received;
            point.bytes_forwarded += bytes_forwarded;
            return;
        }

        series.push(TrafficSeriesPoint {
            epoch_secs: now,
            bytes_received,
            bytes_forwarded,
        });

        let oldest_allowed = now.saturating_sub(TRAFFIC_SERIES_WINDOW_SECS - 1);
        series.retain(|point| point.epoch_secs >= oldest_allowed);
    }
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self::new()
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::TrafficStats;
    use std::net::Ipv4Addr;

    #[test]
    fn test_stats_snapshot_reflects_counter_updates() {
        let stats = TrafficStats::default();

        stats.record_connection_opened();
        stats.register_connection(Ipv4Addr::new(10, 0, 3, 5), 1, "127.0.0.1:20264");
        stats.record_connection_bytes_received(Ipv4Addr::new(10, 0, 3, 5), 128);
        stats.set_registered_clients(1);
        stats.record_bytes_received(128);
        stats.record_heartbeat_frame();
        stats.record_data_frame();
        stats.record_connection_data_frame(Ipv4Addr::new(10, 0, 3, 5));
        stats.record_forwarded_frame(64);
        stats.record_connection_forwarded_frame(Ipv4Addr::new(10, 0, 3, 5), 64);
        stats.record_dropped_frame();
        stats.record_parse_error();
        stats.record_read_error();
        stats.record_write_error();
        stats.record_connection_closed();

        let snapshot = stats.snapshot();

        assert_eq!(snapshot.current_connections, 0);
        assert_eq!(snapshot.total_connections, 1);
        assert_eq!(snapshot.registered_clients, 1);
        assert_eq!(snapshot.bytes_received, 128);
        assert_eq!(snapshot.frames_received, 2);
        assert_eq!(snapshot.heartbeat_frames, 1);
        assert_eq!(snapshot.data_frames, 1);
        assert_eq!(snapshot.bytes_forwarded, 64);
        assert_eq!(snapshot.frames_forwarded, 1);
        assert_eq!(snapshot.frames_dropped, 1);
        assert_eq!(snapshot.parse_errors, 1);
        assert_eq!(snapshot.read_errors, 1);
        assert_eq!(snapshot.write_errors, 1);
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.connections[0].ip, "10.0.3.5");
        assert_eq!(snapshot.connections[0].connection_id, 1);
        assert_eq!(snapshot.connections[0].peer_addr, "127.0.0.1:20264");
        assert_eq!(snapshot.connections[0].bytes_received, 128);
        assert_eq!(snapshot.connections[0].bytes_forwarded, 64);
        assert_eq!(snapshot.connections[0].frames_received, 1);
        assert_eq!(snapshot.connections[0].frames_forwarded, 1);
        assert_eq!(snapshot.traffic_series.len(), 1);
        assert_eq!(snapshot.traffic_series[0].bytes_received, 128);
        assert_eq!(snapshot.traffic_series[0].bytes_forwarded, 64);
    }

    #[test]
    fn test_connection_registration_refreshes_existing_ip() {
        let stats = TrafficStats::default();
        let ip = Ipv4Addr::new(10, 0, 3, 5);

        stats.register_connection(ip, 1, "127.0.0.1:20264");
        stats.record_connection_bytes_received(ip, 128);
        stats.register_connection(ip, 2, "127.0.0.1:30264");

        let snapshot = stats.snapshot();

        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.connections[0].connection_id, 2);
        assert_eq!(snapshot.connections[0].peer_addr, "127.0.0.1:30264");
        assert_eq!(snapshot.connections[0].bytes_received, 0);
    }

    #[test]
    fn test_unregister_ignores_stale_connection_id() {
        let stats = TrafficStats::default();
        let ip = Ipv4Addr::new(10, 0, 3, 5);

        stats.register_connection(ip, 1, "127.0.0.1:20264");
        stats.register_connection(ip, 2, "127.0.0.1:30264");
        stats.unregister_connection(ip, 1);

        let snapshot = stats.snapshot();

        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.connections[0].connection_id, 2);
    }
}
