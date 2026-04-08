//! # Rust TUN - TUN Proxy System
//!
//! This crate provides a TUN proxy system for tunneling IP packets between
//! clients over TCP. It consists of:
//!
//! - **Server** (`bin/server`): Accepts client connections, routes packets by IP
//! - **Client** (`bin/client`): Creates TUN interface, tunnels packets to server
//! - **Shared** (`shared`): Protocol frames, configuration
//!
//! ## Quick Start
//!
//! ### Running the Server
//! ```bash
//! cargo run --bin server
//! ```
//!
//! ### Running the Client
//! ```bash
//! cargo run --bin client
//! ```
//!
//! ## Architecture
//!
//! ```text
//! +-------------------+     TCP      +-------------------+
//! |   Client A        |-------------|     Server        |
//! | (TUN: 10.0.3.5)  |             | (Routes by IP)    |
//! +-------------------+             +-------------------+
//!         |                                  |
//!         | TUN                              | TUN
//!         v                                  v
//!    Local Network                     Remote Network
//! ```
//!
//! ## Protocol
//!
//! The proxy uses a custom frame protocol over TCP:
//! - **Heartbeat**: Client registration + keep-alive (type=1)
//! - **Data**: IP packet tunneling (type=2)
//!
//! See `shared::data` module for protocol details.

pub mod shared;
