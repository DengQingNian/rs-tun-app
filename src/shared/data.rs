//! # Data Frame Protocol Module
//!
//! This module defines the packet frame protocol used for communication between
//! the TUN proxy server and clients. It implements a custom framing layer over
//! TCP to support two types of frames: heartbeat frames for client registration
//! and data frames for IP packet tunneling.
//!
//! ## Protocol Design Rationale
//!
//! **Why custom framing over TCP?**
//! TCP is a byte stream protocol with no built-in message boundaries. When multiple
//! IP packets are sent sequentially, they may be split or merged by the TCP layer.
//! This module adds a framing layer that:
//! - Provides clear frame boundaries for discrete IP packets
//! - Supports sticky packets (multiple frames in one TCP read)
//! - Includes integrity verification via checksums
//! - Differentiates between control messages (heartbeats) and data traffic
//!
//! **Why two checksum algorithms?**
//! - Heartbeat frames use CRC32 with a secret token for authentication
//! - Data frames use a simple checksum for performance (hot path)
//! This balances security for control messages with throughput for data.
//!
//! ## Frame Format
//!
//! ```text
//! +--------+----------------+----------+----------+
//! | Header |     Data       | Checksum |
//! +--------+----------------+----------+----------+
//! 1 byte   3 bytes padding  4 bytes    N bytes    2 bytes
//! -------- HEADER_SIZE = 8 bytes -----------------
//!
//! Header breakdown:
//! - Byte 0: Frame type (1=Heartbeat, 2=Data)
//! - Bytes 1-3: Reserved/padding (must be zero)
//! - Bytes 4-7: Data length (big-endian u32)
//! - Data: Frame payload
//! - Last 2 bytes: Checksum (big-endian u16)
//! ```

use bytes::Bytes;
use crc32fast::Hasher as Crc32;
use std::{
    fmt::{self, Display, Formatter},
    io::{Error, ErrorKind},
};

// ============================================================================
// CONSTANTS - Protocol Configuration
// ============================================================================

/// Maximum allowed frame size in bytes.
///
/// WHY: Prevents memory exhaustion attacks where an attacker sends frames with
/// exaggerated length values. 64MB is sufficient for any realistic IP packet while
/// providing reasonable bounds checking.
const MAX_FRAME_SIZE: usize = 65536 * 1024; // 64mB

/// Size of the frame header in bytes.
///
/// HOW: 1 byte (frame type) + 3 bytes (padding) + 4 bytes (data length) = 8 bytes
/// This header precedes the payload data and checksum.
const HEADER_SIZE: usize = 8; // 1 + 3(padding) + 4 = 8 bytes

// ============================================================================
// TYPE DEFINITIONS - Frame Semantics
// ============================================================================

/// Frame type enumeration defining the two types of protocol frames.
///
/// WHY: Different frame types serve different purposes in the proxy protocol:
/// - **Heartbeat**: Client registration + keep-alive mechanism
/// - **Data**: Actual IP packet tunneling
///
/// The protocol differentiates these to handle registration flow separately from
/// data traffic, enabling features like client IP tracking and authentication.
#[derive(Debug, Clone, PartialEq)]
pub enum FrameType {
    /// Heartbeat with registration info in data field.
    ///
    /// WHY: Heartbeats serve dual purposes:
    /// 1. **Registration**: First heartbeat carries the client's TUN IP address
    ///    so the server knows which virtual IP this client owns
    /// 2. **Keep-alive**: Periodic heartbeats detect if client is still connected
    ///    (server has a timeout mechanism to clean up disconnected clients)
    Heartbeat,

    /// Data packet containing IP packet.
    ///
    /// WHY: Data frames carry the actual IP packets being tunneled.
    /// These are the "hot path" - the core functionality of the proxy.
    /// They need minimal overhead for maximum throughput.
    Data,
}

/// Protocol frame structure representing a complete protocol message.
///
/// This is the main abstraction for the frame protocol. Each frame contains:
/// - A type indicating its purpose (heartbeat or data)
/// - Payload data (registration IP or raw IP packet)
/// - A checksum for integrity verification
///
/// # Serialization
///
/// Frames can be converted to bytes using `to_bytes()` or `into_bytes()`:
/// - `to_bytes()`: Returns `Vec<u8>` - use when you need ownership
/// - `into_bytes()`: Returns `Bytes` - zero-copy, more efficient for async I/O
///
/// # Deserialization
///
/// Parse bytes back using `from_bytes()` or `from_bytes_with_secret()`.
/// The latter allows custom secret for heartbeat verification.
#[derive(Debug, Clone, PartialEq)]
pub struct PackageFrame {
    /// Frame type (Heartbeat or Data).
    ///
    /// HOW: Determined by the first byte of the serialized frame.
    /// WHY: Different types require different handling logic.
    pub kind: FrameType,

    /// Frame data payload.
    ///
    /// HOW: Contents depend on frame type:
    /// - **Heartbeat**: 4 bytes containing client's TUN IP address (u32, big-endian)
    /// - **Data**: Raw IP packet bytes (typically 20+ bytes for IPv4 header)
    ///
    /// WHY: Embedding the IP in heartbeat data avoids a separate registration
    /// message, reducing protocol complexity. For data frames, this is the
    /// actual IP packet being tunneled.
    pub data: Bytes,

    /// Checksum for integrity verification.
    ///
    /// HOW: 16-bit checksum at the end of the frame (last 2 bytes).
    /// WHY: Detects data corruption during transmission. The receiver verifies
    /// the checksum before processing the frame - corrupted frames are rejected.
    pub checksum: u16,
}

/// Display implementation for debugging/logging.
///
/// WHY: Provides human-readable frame representation for debugging.
/// Shows frame type and a preview of data size (not contents - that would be
/// too verbose for logging).
impl Display for PackageFrame {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // HOW: For small data (like heartbeat IP), show the actual bytes.
        // For larger data (like IP packets), just show the byte count.
        let data_preview = if self.data.len() > 4 {
            format!("{} bytes", self.data.len())
        } else {
            format!("{:?}", self.data)
        };
        write!(
            f,
            "PackageFrame(kind={:?}, data={})",
            self.kind, data_preview
        )
    }
}

impl PackageFrame {
    // ------------------------------------------------------------------------
    // Constructor Methods - Creating New Frames
    // ------------------------------------------------------------------------

    /// Creates a new frame with the default secret token.
    ///
    /// # Arguments
    /// * `kind` - The frame type (Heartbeat or Data)
    /// * `data` - The payload data
    ///
    /// # Returns
    /// A new PackageFrame with calculated checksum using default secret "ttt".
    ///
    /// # Why
    /// Convenience constructor for simple use cases where the default secret
    /// is acceptable. For production, use `new_with_secret()` with a proper secret.
    ///
    /// # How
    /// Delegates to `new_with_secret()` with the default secret token.
    pub fn new(kind: FrameType, data: Bytes) -> Self {
        Self::new_with_secret(kind, data, "ttt")
    }

    /// Creates a new frame with a custom secret token.
    ///
    /// # Arguments
    /// * `kind` - The frame type (Heartbeat or Data)
    /// * `data` - The payload data
    /// * `secret` - Secret token for checksum calculation (heartbeat only)
    ///
    /// # Returns
    /// A new PackageFrame with calculated checksum.
    ///
    /// # Why
    /// Allows custom authentication secret for heartbeat frames. The secret
    /// is incorporated into the checksum calculation, making it impossible to
    /// forge heartbeats without knowing the secret.
    ///
    /// # How
    /// 1. Filters out empty data (treats as zero-length)
    /// 2. Calculates checksum based on frame type:
    ///    - Heartbeat: CRC32 with secret (authentication)
    ///    - Data: Simple sum (performance)
    /// 3. Constructs frame with computed checksum
    pub fn new_with_secret(kind: FrameType, data: Bytes, secret: &str) -> Self {
        // HOW: Empty data is normalized to empty Bytes (no difference in representation)
        let data = if data.is_empty() { Bytes::new() } else { data };

        // WHY: Different checksum algorithms based on frame type:
        // - Heartbeat uses authentication checksum (includes secret)
        // - Data uses simple checksum (performance in hot path)
        let checksum = if matches!(kind, FrameType::Heartbeat) {
            sum(&kind, &data, secret)
        } else {
            simple_sum(&data)
        };

        Self {
            kind,
            data,
            checksum,
        }
    }

    /// Create a heartbeat frame for registration.
    ///
    /// # Arguments
    /// * `client_ip` - The client's TUN interface IP address as u32
    /// * `secret` - Secret token for checksum authentication
    ///
    /// # Returns
    /// A heartbeat frame containing the client's registration IP.
    ///
    /// # Why
    /// Heartbeat frames serve as both registration messages and keep-alive signals.
    /// The first heartbeat from a client registers their virtual IP with the server.
    ///
    /// # How
    /// 1. Converts the IP address to 4 big-endian bytes
    /// 2. Creates a heartbeat frame with this as payload
    /// 3. Uses the secret for checksum authentication
    pub fn new_heartbeat(client_ip: u32, secret: &str) -> Self {
        // HOW: Convert u32 IP to 4 bytes (big-endian for network byte order)
        let data = client_ip.to_be_bytes().to_vec().into();
        Self::new_with_secret(FrameType::Heartbeat, data, secret)
    }

    // ------------------------------------------------------------------------
    // Accessor Methods - Extracting Information from Frames
    // ------------------------------------------------------------------------

    /// Get client IP from heartbeat data.
    ///
    /// # Returns
    /// Some(client_ip) if this is a heartbeat frame with valid 4-byte IP data,
    /// None otherwise.
    ///
    /// # Why
    /// The server needs to extract the client's registered IP from heartbeat
    /// frames to maintain the client registry (IP -> connection mapping).
    ///
    /// # How
    /// 1. Verifies frame is a Heartbeat type
    /// 2. Verifies data length is exactly 4 bytes (IPv4 address)
    /// 3. Converts 4 bytes back to u32 (big-endian)
    pub fn get_heartbeat_ip(&self) -> Option<u32> {
        if matches!(self.kind, FrameType::Heartbeat) && self.data.len() == 4 {
            Some(u32::from_be_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ]))
        } else {
            None
        }
    }

    /// Extract destination IP from IP packet in data.
    ///
    /// # Returns
    /// Some(dst_ip) if data contains a valid IPv4 packet header,
    /// None otherwise.
    ///
    /// # Why
    /// The server needs destination IP to route tunneled packets to the correct
    /// client. This is the core routing logic in the proxy.
    ///
    /// # How
    /// 1. Verifies data is at least 20 bytes (minimum IPv4 header)
    /// 2. Checks IP version field (must be 4 for IPv4)
    /// 3. Extracts destination IP from IP header bytes 16-19 (big-endian)
    ///
    /// # IP Header Reference
    /// ```text
    /// IPv4 Header (20 bytes minimum):
    /// +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    /// |Ver | IHL|  ToS |    Total Length   |         ID        |Flg|   Fragment Offset  |
    /// +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    /// | 0  |  1 |  2   |    3    -   4    |     5    -   6   | 7 |       8   -   9    |
    /// +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    /// |         TTL      |    Protocol     |           Header Checksum              |
    /// +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    /// | 10 | 11 | 12    |       13         |              14    -    15             |
    /// +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    /// |                        Source IP Address                                   |
    /// +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    /// | 16 | 17 | 18    |       19         |                                         |
    /// +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    /// |                     Destination IP Address                                  |
    /// +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    /// | 20 | 21 | 22    |       23         |                                         |
    /// +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    /// ```
    pub fn get_dst_ip(&self) -> Option<u32> {
        if self.data.len() >= 20 {
            // IP header: version/IHL at byte 0, destination at bytes 16-19
            // HOW: Version is the high 4 bits of first byte
            let version = (self.data[0] >> 4) & 0x0F;
            if version == 4 {
                Some(u32::from_be_bytes([
                    self.data[16],
                    self.data[17],
                    self.data[18],
                    self.data[19],
                ]))
            } else {
                None
            }
        } else {
            None
        }
    }

    // ------------------------------------------------------------------------
    // Serialization Methods - Converting Frames to Bytes
    // ------------------------------------------------------------------------

    /// Converts the frame to a Vec<u8>.
    ///
    /// # Returns
    /// A vector containing the serialized frame.
    ///
    /// # Why
    /// For sending frames over TCP or other byte-oriented channels.
    ///
    /// # How
    /// Frame layout: [type(1) + padding(3) + len(4)] + data + checksum(2)
    /// All multi-byte values use big-endian (network byte order).
    pub fn to_bytes(&self) -> Vec<u8> {
        let data_len = self.data.len() as u32;
        // HOW: Calculate total size: header + data + checksum
        let total_len = HEADER_SIZE + data_len as usize + 2;

        // Pre-allocate with exact capacity to avoid reallocation
        let mut buf = Vec::with_capacity(total_len);

        // Write frame type (1 = Heartbeat, 2 = Data)
        buf.push(match self.kind {
            FrameType::Heartbeat => 1,
            FrameType::Data => 2,
        });

        // Write 3 bytes of padding (reserved, must be zero)
        buf.extend_from_slice(&[0u8; 3]);

        // Write data length (big-endian u32)
        buf.extend_from_slice(&data_len.to_be_bytes());

        // Write the actual data payload
        buf.extend_from_slice(&self.data);

        // Write checksum (big-endian u16)
        buf.extend_from_slice(&self.checksum.to_be_bytes());

        buf
    }

    /// Converts the frame to Bytes (zero-copy when possible).
    ///
    /// # Returns
    /// A Bytes object containing the serialized frame.
    ///
    /// # Why
    /// More efficient than `to_bytes()` in async contexts - Bytes can be
    /// reference-counted without copying, reducing memory churn.
    ///
    /// # How
    /// Same as `to_bytes()` but returns Bytes instead of Vec<u8>.
    pub fn into_bytes(self) -> Bytes {
        let data_len = self.data.len() as u32;
        let total_len = HEADER_SIZE + data_len as usize + 2;

        let mut buf = Vec::with_capacity(total_len);
        buf.push(match self.kind {
            FrameType::Heartbeat => 1,
            FrameType::Data => 2,
        });
        buf.extend_from_slice(&[0u8; 3]);
        buf.extend_from_slice(&data_len.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf.extend_from_slice(&self.checksum.to_be_bytes());

        Bytes::from(buf)
    }

    // ------------------------------------------------------------------------
    // Deserialization Methods - Parsing Bytes into Frames
    // ------------------------------------------------------------------------

    /// Parses a frame from bytes using the default secret.
    ///
    /// # Arguments
    /// * `bytes` - Raw frame bytes
    ///
    /// # Returns
    /// Ok(PackageFrame) if valid, Err(io::Error) otherwise.
    ///
    /// # Why
    /// Entry point for parsing frames with default configuration.
    ///
    /// # How
    /// Validates frame structure and checksum, then constructs the frame.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes_with_secret(bytes, "ttt")
    }

    /// Parses a frame from bytes with a custom secret.
    ///
    /// # Arguments
    /// * `bytes` - Raw frame bytes
    /// * `secret` - Secret token for checksum verification
    ///
    /// # Returns
    /// Ok(PackageFrame) if valid and checksum matches, Err(io::Error) otherwise.
    ///
    /// # Why
    /// Allows custom secret for heartbeat authentication. Frame is rejected
    /// if checksum doesn't match, preventing tampered or forged frames.
    ///
    /// # How
    /// 1. **Length validation**: Frame must be at least HEADER_SIZE + 2 (checksum)
    /// 2. **Type parsing**: First byte determines Heartbeat (1) or Data (2)
    /// 3. **Data length parsing**: Bytes 4-7 contain data length (big-endian u32)
    /// 4. **Maximum size check**: Reject oversized frames (DoS prevention)
    /// 5. **Complete frame check**: Actual length must match expected
    /// 6. **Data extraction**: Slice the data portion
    /// 7. **Checksum extraction**: Last 2 bytes
    /// 8. **Checksum verification**: Recalculate and compare
    pub fn from_bytes_with_secret(bytes: &[u8], secret: &str) -> Result<Self, Error> {
        // Step 1: Basic length check - need at least header + checksum
        if bytes.len() < HEADER_SIZE + 2 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Frame too short: need at least {} bytes", HEADER_SIZE + 2),
            ));
        }

        // Step 2: Parse frame type from first byte
        let kind = match bytes[0] {
            1 => FrameType::Heartbeat,
            2 => FrameType::Data,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Invalid frame type: {}", bytes[0]),
                ));
            }
        };

        // Step 3: Parse data length from bytes 4-7 (big-endian u32)
        let data_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;

        // Step 4: Check for oversized frames (security: prevent memory exhaustion)
        if data_len > MAX_FRAME_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Data length {} exceeds maximum {}",
                    data_len, MAX_FRAME_SIZE
                ),
            ));
        }

        // Step 5: Verify complete frame: header + data + checksum(2)
        let expected_len = HEADER_SIZE + data_len + 2;
        if bytes.len() != expected_len {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Data length mismatch: expected {} bytes, got {}",
                    expected_len,
                    bytes.len()
                ),
            ));
        }

        // Step 6: Extract data payload
        let data = Bytes::copy_from_slice(&bytes[HEADER_SIZE..HEADER_SIZE + data_len]);

        // Step 7: Extract checksum (last 2 bytes)
        let checksum = u16::from_be_bytes([bytes[expected_len - 2], bytes[expected_len - 1]]);

        // Step 8: Verify checksum matches
        let expected_checksum = if matches!(kind, FrameType::Heartbeat) {
            sum(&kind, &data, secret)
        } else {
            simple_sum(&data)
        };
        if checksum != expected_checksum {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Checksum verification failed (expected {:x}, got {:x})",
                    expected_checksum, checksum
                ),
            ));
        }

        Ok(Self {
            kind,
            data,
            checksum,
        })
    }
}

// ============================================================================
// STREAM PARSING FUNCTIONS - Handling Sticky Packets
// ============================================================================

/// Parses a frame from a byte stream, handling sticky packets.
///
/// # Arguments
/// * `bytes` - Input buffer containing zero or more frames
/// * `secret` - Secret token for checksum verification
///
/// # Returns
/// Ok((parsed_frame, remaining_bytes)) or error.
///
/// # Why
/// TCP may deliver multiple frames concatenated in a single read (sticky packets)
/// or partial frames across reads. This function handles the first case by:
/// - Attempting to parse a complete frame from the buffer start
/// - Returning the remaining bytes for subsequent parsing
///
/// # How
/// 1. Check minimum length (header + checksum)
/// 2. Extract data length from header
/// 3. Check if complete frame is available
/// 4. Parse the frame and return with remaining buffer
pub fn parse_frame_with_secret<'a>(
    bytes: &'a [u8],
    secret: &str,
) -> Result<(PackageFrame, &'a [u8]), Error> {
    // Step 1: Minimum length check
    if bytes.len() < HEADER_SIZE + 2 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "Incomplete header or checksum",
        ));
    }

    // Step 2: Extract data length
    let data_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;

    // Security check: reject oversized
    if data_len > MAX_FRAME_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Data length {} exceeds maximum", data_len),
        ));
    }

    // Step 3: Check if complete frame is available
    let total_len = HEADER_SIZE + data_len + 2;
    if bytes.len() < total_len {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            format!(
                "Incomplete frame: need {} bytes, got {}",
                total_len,
                bytes.len()
            ),
        ));
    }

    // Step 4: Parse frame
    let frame = PackageFrame::from_bytes_with_secret(&bytes[0..total_len], secret)
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

    // Return parsed frame + remaining bytes (for sticky packet handling)
    Ok((frame, &bytes[total_len..]))
}

/// Parses a frame from a byte stream using default secret.
///
/// # Why
/// Convenience wrapper for common case with default configuration.
pub fn parse_frame(bytes: &[u8]) -> Result<(PackageFrame, &[u8]), Error> {
    if bytes.len() < HEADER_SIZE + 2 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "Incomplete header or checksum",
        ));
    }

    let data_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    if data_len > MAX_FRAME_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "Data length {} exceeds maximum {}",
                data_len, MAX_FRAME_SIZE
            ),
        ));
    }

    let total_len = HEADER_SIZE + data_len + 2;
    if bytes.len() < total_len {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            format!(
                "Incomplete frame: need {} bytes, got {}",
                total_len,
                bytes.len()
            ),
        ));
    }

    let frame = PackageFrame::from_bytes(&bytes[0..total_len])
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

    Ok((frame, &bytes[total_len..]))
}

// ============================================================================
// TESTS - Protocol Verification
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // Test: Valid data frame round-trip serialization/deserialization
    #[test]
    fn test_valid_data_frame() {
        // IPv4 packet with source 10.0.3.5, destination 10.0.3.1
        let ip_packet = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0x0a, 0x00,
            0x03, 0x05, 0x0a, 0x00, 0x03, 0x01,
        ]; // 20 bytes IP header
        let frame = PackageFrame::new(FrameType::Data, Bytes::copy_from_slice(&ip_packet));

        let bytes = frame.to_bytes();
        let parsed = PackageFrame::from_bytes(&bytes).unwrap();

        assert!(matches!(parsed.kind, FrameType::Data));
        assert_eq!(parsed.data.len(), 20);
        let dst = parsed.get_dst_ip();
        assert_eq!(dst, Some(Ipv4Addr::new(10, 0, 3, 1).to_bits()));
    }

    // Test: Heartbeat frame carries registration IP
    #[test]
    fn test_heartbeat_frame() {
        let client_ip: u32 = Ipv4Addr::new(10, 0, 3, 5).to_bits();
        let frame = PackageFrame::new_heartbeat(client_ip, "secret");

        let bytes = frame.to_bytes();
        assert_eq!(bytes.len(), 8 + 4 + 2); // header + 4-byte IP + checksum

        let parsed = PackageFrame::from_bytes_with_secret(&bytes, "secret").unwrap();
        assert!(matches!(parsed.kind, FrameType::Heartbeat));

        let reg_ip = parsed.get_heartbeat_ip();
        assert_eq!(reg_ip, Some(client_ip));
    }

    // Test: Destination IP extraction from various packets
    #[test]
    fn test_get_dst_ip() {
        let ip_packet = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0x0a, 0x00,
            0x03, 0x05, 0x0a, 0x00, 0x03, 0x01,
        ]; // src=10.0.3.5, dst=10.0.3.1
        let frame = PackageFrame::new(FrameType::Data, Bytes::copy_from_slice(&ip_packet));

        let dst = frame.get_dst_ip();
        assert_eq!(dst, Some(Ipv4Addr::new(10, 0, 3, 1).to_bits()));
    }

    // Test: Invalid frame type is rejected
    #[test]
    fn test_invalid_frame_type() {
        let mut bytes = vec![0u8; 10]; // valid header size
        bytes[0] = 99; // invalid type
        let result = PackageFrame::from_bytes(&bytes);
        assert!(result.is_err());
    }

    // Test: Full frame serialization round-trip
    #[test]
    fn test_frame_serialization_roundtrip() {
        let ip_packet = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xac, 0x0a,
            0x03, 0x02, 0xac, 0x0a, 0x03, 0x03, // src=172.10.3.2, dst=172.10.3.3
        ];

        let frame = PackageFrame::new(FrameType::Data, Bytes::copy_from_slice(&ip_packet));

        let encoded = frame.to_bytes();
        let parsed = PackageFrame::from_bytes(&encoded).unwrap();

        assert!(matches!(parsed.kind, FrameType::Data));
        assert_eq!(parsed.data.len(), 20);
        let dst = parsed.get_dst_ip();
        assert_eq!(dst, Some(Ipv4Addr::new(172, 10, 3, 3).to_bits()));
    }

    // Test: Heartbeat registration format
    #[test]
    fn test_heartbeat_registration_format() {
        let client_ip = Ipv4Addr::new(172, 10, 3, 2).to_bits();

        let frame = PackageFrame::new_heartbeat(client_ip, "ttt");

        let encoded = frame.to_bytes();
        let parsed = PackageFrame::from_bytes(&encoded).unwrap();

        assert!(matches!(parsed.kind, FrameType::Heartbeat));
        assert_eq!(parsed.get_heartbeat_ip(), Some(client_ip));
        assert_eq!(
            parsed.get_heartbeat_ip(),
            Some(Ipv4Addr::new(172, 10, 3, 2).to_bits())
        );
    }

    // Test: IP header destination extraction from various addresses
    #[test]
    fn test_ip_header_dst_extraction() {
        let test_cases = vec![
            // Test case 1: 10.0.3.1 destination
            (
                vec![
                    0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0x0a,
                    0x00, 0x03, 0x05, 0x0a, 0x00, 0x03, 0x01,
                ],
                Ipv4Addr::new(10, 0, 3, 1),
            ),
            // Test case 2: 172.10.3.3 destination
            (
                vec![
                    0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xac,
                    0x0a, 0x03, 0x02, 0xac, 0x0a, 0x03, 0x03,
                ],
                Ipv4Addr::new(172, 10, 3, 3),
            ),
            // Test case 3: 192.168.1.1 destination
            (
                vec![
                    0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xc0,
                    0xa8, 0x01, 0x64, 0xc0, 0xa8, 0x01, 0x01,
                ],
                Ipv4Addr::new(192, 168, 1, 1),
            ),
        ];

        for (packet, expected_dst) in test_cases {
            let frame = PackageFrame::new(FrameType::Data, Bytes::copy_from_slice(&packet));
            let dst = frame.get_dst_ip();
            assert_eq!(
                dst,
                Some(expected_dst.to_bits()),
                "Failed for IP: {}",
                expected_dst
            );
        }
    }

    // Test: Client registration from heartbeat
    #[test]
    fn test_client_registration_from_heartbeat() {
        let client_ip = Ipv4Addr::new(172, 10, 3, 2).to_bits();

        let frame = PackageFrame::new_heartbeat(client_ip, "secret");
        let encoded = frame.to_bytes();

        let parsed = PackageFrame::from_bytes_with_secret(&encoded, "secret").unwrap();

        assert!(matches!(parsed.kind, FrameType::Heartbeat));
        let registered_ip = parsed.get_heartbeat_ip();
        assert_eq!(registered_ip, Some(client_ip));
    }

    // Test: Full frame format verification
    #[test]
    fn test_full_frame_format() {
        let ip_packet = vec![0u8; 64];
        let frame = PackageFrame::new(FrameType::Data, Bytes::copy_from_slice(&ip_packet));

        let bytes = frame.to_bytes();

        assert_eq!(bytes[0], 2); // FrameType::Data = 2
        assert_eq!(bytes[1], 0); // padding
        assert_eq!(bytes[2], 0);
        assert_eq!(bytes[3], 0);

        let data_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(data_len, 64);

        let total_len = 8 + 64 + 2;
        assert_eq!(bytes.len(), total_len);
    }

    // Test: Sticky packet parsing for multiple clients
    #[test]
    fn test_parse_sticky_packets_multiple_clients() {
        let frame_client1 = PackageFrame::new(
            FrameType::Data,
            Bytes::copy_from_slice(&vec![
                0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xac, 0x0a,
                0x03, 0x02, 0xac, 0x0a, 0x03, 0x03,
            ]),
        );

        let frame_client2 = PackageFrame::new(
            FrameType::Data,
            Bytes::copy_from_slice(&vec![
                0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xac, 0x0a,
                0x03, 0x03, 0xac, 0x0a, 0x03, 0x02,
            ]),
        );

        // Combine two frames into one buffer (sticky packets)
        let mut combined = frame_client1.to_bytes();
        combined.extend_from_slice(&frame_client2.to_bytes());

        // Parse first frame
        let (parsed1, remaining) = parse_frame(&combined).unwrap();
        let dst1 = parsed1.get_dst_ip();
        assert_eq!(dst1, Some(Ipv4Addr::new(172, 10, 3, 3).to_bits()));

        // Parse second frame from remaining
        let (parsed2, _) = parse_frame(&remaining).unwrap();
        let dst2 = parsed2.get_dst_ip();
        assert_eq!(dst2, Some(Ipv4Addr::new(172, 10, 3, 2).to_bits()));
    }

    // Test: Secret mismatch is rejected
    #[test]
    fn test_secret_mismatch_rejected() {
        let frame =
            PackageFrame::new_heartbeat(Ipv4Addr::new(10, 0, 0, 1).to_bits(), "correct_secret");

        let bytes = frame.to_bytes();

        // Wrong secret should fail
        let result = PackageFrame::from_bytes_with_secret(&bytes, "wrong_secret");
        assert!(result.is_err());

        // Correct secret should succeed
        let result = PackageFrame::from_bytes_with_secret(&bytes, "correct_secret");
        assert!(result.is_ok());
    }

    // Test: Checksum is validated during parsing
    #[test]
    fn test_checksum_in_validation() {
        let frame = PackageFrame::new(
            FrameType::Data,
            Bytes::copy_from_slice(&vec![1, 2, 3, 4, 5]),
        );

        let bytes = frame.to_bytes();

        // Modify a data byte to corrupt checksum
        let mut modified = bytes.clone();
        modified[12] ^= 0xFF;

        // Parsing should fail due to checksum mismatch
        let result = PackageFrame::from_bytes(&modified);
        assert!(result.is_err());
    }

    // Test: Heartbeat with data carries registration IP
    #[test]
    fn test_heartbeat_with_data_carries_registration() {
        let client_ip = Ipv4Addr::new(172, 10, 3, 2);
        let frame = PackageFrame::new_heartbeat(client_ip.to_bits(), "test_secret");

        let bytes = frame.to_bytes();

        assert_eq!(bytes[0], 1);

        // Verify the IP is encoded at data start
        let data_start = 8;
        let reg_ip = u32::from_be_bytes([
            bytes[data_start],
            bytes[data_start + 1],
            bytes[data_start + 2],
            bytes[data_start + 3],
        ]);
        assert_eq!(reg_ip, client_ip.to_bits());

        let parsed = PackageFrame::from_bytes_with_secret(&bytes, "test_secret").unwrap();
        assert_eq!(parsed.get_heartbeat_ip(), Some(client_ip.to_bits()));
    }
}

// ============================================================================
// CHECKSUM CALCULATION FUNCTIONS
// ============================================================================

/// Calculate checksum for heartbeat frames (with authentication).
///
/// # Why
/// Heartbeat frames need stronger integrity verification because they carry
/// client registration information. The secret is included in the calculation
/// to prevent forging heartbeats without knowing the secret.
///
/// # How
/// Uses CRC32 algorithm which provides:
/// - Stronger collision resistance than simple sum
/// - The secret is incorporated into the hash, creating authentication
/// Result is truncated to 16 bits for the protocol format.
fn sum(kind: &FrameType, data: &Bytes, token: &str) -> u16 {
    let mut hasher = Crc32::new();

    // Include frame type in checksum (different types = different checksum)
    hasher.update(match kind {
        FrameType::Heartbeat => &[1u8],
        FrameType::Data => &[2u8],
    });

    // Include data length (prevents length extension attacks)
    hasher.update(&(data.len() as u32).to_be_bytes());

    // Include actual data
    hasher.update(data);

    // Include secret token (provides authentication)
    hasher.update(token.as_bytes());

    // Truncate to 16 bits for protocol
    (hasher.finalize() & 0xFFFF) as u16
}

/// Calculate checksum for data frames (simple, fast).
///
/// # Why
/// Data frames are the "hot path" - every tunneled packet goes through this.
/// A simple checksum provides adequate integrity checking with minimal overhead.
/// CRC32 would work but is slower for this use case.
///
/// # How
/// Computes a simple sum:
/// - Iterates through data in 4-byte chunks, summing as u32 (little-endian)
/// - Handles remaining 1-3 bytes individually
/// - Uses wrapping add to handle overflow (matches UDP/IP checksum behavior)
/// - Truncates to 16 bits
fn simple_sum(data: &Bytes) -> u16 {
    let len = data.len();
    if len == 0 {
        return 0;
    }
    let mut s: u32 = 0;
    let mut i = 0;

    // Process 4-byte chunks (faster than byte-by-byte)
    while i + 4 <= len {
        s = s.wrapping_add(u32::from_le_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
        ]));
        i += 4;
    }

    // Handle remaining bytes (1-3 bytes)
    while i < len {
        s = s.wrapping_add(data[i] as u32);
        i += 1;
    }

    (s & 0xFFFF) as u16
}
