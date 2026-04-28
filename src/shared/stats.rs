//! # Server Traffic Statistics
//!
//! This module stores server traffic counters in atomics so the TCP forwarding
//! path can update metrics cheaply while the HTTP panel reads a consistent
//! snapshot for display.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Thread-safe traffic counters shared by the TCP server and stats API.
#[derive(Debug, Default)]
pub struct TrafficStats {
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
}

/// Serializable point-in-time view of [`TrafficStats`].
#[derive(Debug, Clone, Serialize)]
pub struct TrafficStatsSnapshot {
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
}

impl TrafficStats {
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

    /// Record the current number of clients registered in the routing table.
    pub fn set_registered_clients(&self, count: usize) {
        self.registered_clients
            .store(count as u64, Ordering::Relaxed);
    }

    /// Record raw TCP bytes read from clients.
    pub fn record_bytes_received(&self, bytes: usize) {
        self.bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
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

    /// Record a successfully forwarded data frame.
    pub fn record_forwarded_frame(&self, bytes: usize) {
        self.frames_forwarded.fetch_add(1, Ordering::Relaxed);
        self.bytes_forwarded
            .fetch_add(bytes as u64, Ordering::Relaxed);
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
        TrafficStatsSnapshot {
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TrafficStats;

    #[test]
    fn test_stats_snapshot_reflects_counter_updates() {
        let stats = TrafficStats::default();

        stats.record_connection_opened();
        stats.set_registered_clients(1);
        stats.record_bytes_received(128);
        stats.record_heartbeat_frame();
        stats.record_data_frame();
        stats.record_forwarded_frame(64);
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
    }
}
