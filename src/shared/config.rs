//! # Configuration Module
//!
//! This module provides configuration structures for the TUN proxy server and client.
//! Both server and client use TOML configuration files for easy setup and modification.
//!
//! ## Design Rationale
//!
//! **Why TOML?**
//! TOML is a minimal configuration format that's easy to read and edit. It provides
//! better type safety than JSON and supports comments (unlike JSON). It's the standard
//! for Rust projects (used by Cargo).
//!
//! **Why separate configs?**
//! Server and client have different requirements:
//! - Server needs: bind address, port, heartbeat interval, client timeout
//! - Client needs: server address, port, TUN IP settings, reconnect behavior
//!
//! **Why with fallback defaults?**
//! The `load_from_current_dir()` method falls back to hardcoded defaults if the
//! config file doesn't exist. This allows quick testing without config files while
//! still supporting production configuration.

use serde::Deserialize;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use thiserror::Error;

/// Configuration-related errors.
///
/// WHY: Provides specific error types for different failure modes:
/// - Io errors: File not found, permission denied
/// - Parse errors: Invalid TOML syntax, wrong types
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Server configuration structure.
///
/// # Fields
/// - `bind_addr`: IP address to bind the server (default: "0.0.0.0")
/// - `bind_port`: TCP port to listen on (default: 20264)
/// - `secret`: Secret token for heartbeat authentication
/// - `heartbeat_interval_secs`: Interval between heartbeat checks (default: 10)
/// - `client_timeout_secs`: Client disconnection timeout (default: 30)
///
/// # Usage
/// Load from TOML file using `load()` or `load_from_current_dir()`.
/// The latter accepts a filename and looks for it in the current directory.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Address to bind the server socket.
    ///
    /// WHY: Allows binding to specific interfaces.
    /// "0.0.0.0" means all interfaces, "127.0.0.1" means localhost only.
    pub bind_addr: String,

    /// TCP port number to listen on.
    ///
    /// WHY: Must match the port clients connect to.
    /// Default 20264 is arbitrary but avoids well-known ports.
    pub bind_port: u16,

    /// Secret token for authenticating heartbeats.
    ///
    /// WHY: Clients must know this secret to register with the server.
    /// The secret is used in checksum calculation for heartbeat frames.
    pub secret: String,

    /// How often to check/update heartbeat timestamps (in seconds).
    ///
    /// HOW: Background task runs at this interval to check client timeouts.
    /// Actual timeout is `client_timeout_secs`, this is just the check interval.
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,

    /// Client timeout in seconds before disconnection.
    ///
    /// WHY: Cleans up clients that stop sending heartbeats.
    /// If no heartbeat received within this time, client is removed.
    #[serde(default = "default_client_timeout_secs")]
    pub client_timeout_secs: u64,
}

/// Default heartbeat interval: 10 seconds.
///
/// WHY: Frequent enough to detect disconnection quickly, but not too frequent
/// to cause unnecessary CPU usage.
fn default_heartbeat_interval_secs() -> u64 {
    10
}

/// Default client timeout: 30 seconds.
///
/// WHY: Allows for some network latency/buffering. Combined with 10s check
/// interval, gives 3x margin for heartbeat delays.
fn default_client_timeout_secs() -> u64 {
    30
}

impl ServerConfig {
    /// Load server configuration from a file path.
    ///
    /// # Arguments
    /// * `path` - Path to the TOML configuration file
    ///
    /// # Returns
    /// Ok(ServerConfig) on success, Err(ConfigError) on failure.
    ///
    /// # Why
    /// Standard way to load configuration from a specific file path.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: ServerConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Load server configuration from current directory.
    ///
    /// # Arguments
    /// * `filename` - Name of the config file (e.g., "server.toml")
    ///
    /// # Returns
    /// Ok(ServerConfig) if file exists and parses correctly,
    /// Err(ConfigError::Io(ErrorKind::NotFound)) if file doesn't exist.
    ///
    /// # Why
    /// Convenience method for simple deployments where config file
    /// is in the same directory as the binary.
    pub fn load_from_current_dir(filename: &str) -> Result<Self, ConfigError> {
        let path = Path::new(filename);
        if path.exists() {
            Self::load(path)
        } else {
            Err(ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Config file '{}' not found in current directory", filename),
            )))
        }
    }
}

/// Client configuration structure.
///
/// # Fields
/// - `server_addr`: Server IP address or hostname
/// - `server_port`: Server TCP port
/// - `tun_ip`: TUN interface IP address
/// - `tun_netmask`: TUN interface netmask (CIDR prefix)
/// - `secret`: Secret token for heartbeat authentication
/// - `reconnect_delay_secs`: Delay between reconnect attempts (default: 3)
/// - `max_reconnect_attempts`: Max reconnect attempts, 0=infinite (default: 0)
/// - `heartbeat_interval_secs`: Heartbeat sending interval (default: 5)
///
/// # Usage
/// Load from TOML file using `load()` or `load_from_current_dir()`.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// Server address (IP or hostname).
    ///
    /// WHY: The client needs to know where to connect.
    /// Can be IP address ("192.168.1.100") or hostname ("vpn.example.com").
    pub server_addr: String,

    /// Server TCP port number.
    ///
    /// WHY: Must match the server's bind_port configuration.
    pub server_port: u16,

    /// TUN interface IP address.
    ///
    /// WHY: Each client gets a unique virtual IP address.
    /// This is the IP that will be assigned to the TUN interface.
    pub tun_ip: String,

    /// TUN interface netmask (CIDR prefix length).
    ///
    /// HOW: 24 means 255.255.255.0, giving /24 network.
    /// This determines the local network configuration.
    pub tun_netmask: u8,

    /// Secret token for heartbeat authentication.
    ///
    /// WHY: Must match the server's secret for registration to work.
    pub secret: String,

    /// Delay between reconnect attempts (in seconds).
    ///
    /// HOW: After a connection failure, client waits this long before retrying.
    #[serde(default = "default_reconnect_delay_secs")]
    pub reconnect_delay_secs: u64,

    /// Maximum number of reconnect attempts (0 = infinite).
    ///
    /// WHY: Allows limiting retry attempts for batch jobs/scripts.
    /// 0 (default) means retry forever.
    #[serde(default = "default_max_reconnect_attempts")]
    pub max_reconnect_attempts: u32,

    /// How often to send heartbeat frames (in seconds).
    ///
    /// HOW: Client sends heartbeat at this interval to maintain registration.
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
}

/// Default reconnect delay: 3 seconds.
///
/// WHY: Short enough for quick recovery, long enough to avoid hammering
/// a failing server.
fn default_reconnect_delay_secs() -> u64 {
    3
}

/// Default max reconnect attempts: 0 (infinite).
///
/// WHY: Most clients want infinite retries for permanent connections.
/// Applications can set a limit if needed.
fn default_max_reconnect_attempts() -> u32 {
    0
} // 0 = infinite

impl ClientConfig {
    /// Get TUN IP address as Ipv4Addr.
    ///
    /// # Returns
    /// The parsed IP address, or default 10.0.3.5 if parsing fails.
    ///
    /// # Why
    /// Provides convenient access to the TUN IP as Ipv4Addr type
    /// (required by the TUN device builder).
    pub fn tun_ip_addr(&self) -> Ipv4Addr {
        self.tun_ip.parse().unwrap_or(Ipv4Addr::new(10, 0, 3, 5))
    }

    /// Load client configuration from a file path.
    ///
    /// # Arguments
    /// * `path` - Path to the TOML configuration file
    ///
    /// # Returns
    /// Ok(ClientConfig) on success, Err(ConfigError) on failure.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: ClientConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Load client configuration from current directory.
    ///
    /// # Arguments
    /// * `filename` - Name of the config file (e.g., "client.toml")
    ///
    /// # Returns
    /// Ok(ClientConfig) if file exists and parses correctly,
    /// Err(ConfigError::Io(ErrorKind::NotFound)) if file doesn't exist.
    pub fn load_from_current_dir(filename: &str) -> Result<Self, ConfigError> {
        let path = Path::new(filename);
        if path.exists() {
            Self::load(path)
        } else {
            Err(ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Config file '{}' not found in current directory", filename),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test: Server config loads with defaults
    #[test]
    fn test_server_config_defaults() {
        let toml_str = r#"
            bind_addr = "0.0.0.0"
            bind_port = 20264
            secret = "mysecret"
        "#;
        let config: ServerConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.bind_addr, "0.0.0.0");
        assert_eq!(config.bind_port, 20264);
        assert_eq!(config.heartbeat_interval_secs, 10);
    }

    // Test: Client config loads with defaults
    #[test]
    fn test_client_config_defaults() {
        let toml_str = r#"
            server_addr = "127.0.0.1"
            server_port = 20264
            tun_ip = "10.0.3.5"
            tun_netmask = 24
            secret = "mysecret"
        "#;
        let config: ClientConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server_addr, "127.0.0.1");
        assert_eq!(config.tun_ip_addr(), Ipv4Addr::new(10, 0, 3, 5));
        assert_eq!(config.max_reconnect_attempts, 0);
    }
}
