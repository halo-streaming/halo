//! HALO peer-to-peer video streaming crate over Media over QUIC (MoQ).
//!
//! This crate provides:
//! - Node identity management via Ed25519 keypairs ([`Keypair`]).
//! - Ticket encoding and decoding for joining streams ([`encode_ticket`], [`decode_ticket`], [`parse_ticket`]).
//! - Publishing local video files over MoQ/QUIC ([`Publisher`]).
//! - Subscribing to a published stream and writing fMP4 bytes to any async sink ([`subscribe`]).
//!
//! # Examples
//!
//! Encode and parse a join ticket:
//! ```
//! use std::net::{IpAddr, Ipv6Addr};
//! use halo::{decode_ticket, encode_ticket, parse_ticket};
//!
//! let node_id = [42u8; 32];
//! let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
//! let ticket = encode_ticket(&node_id, ip);
//!
//! let decoded = decode_ticket(&ticket).unwrap();
//! assert_eq!(decoded.node_id, node_id);
//! assert_eq!(decoded.ip, ip);
//! assert_eq!(parse_ticket(&ticket).unwrap().ip(), ip);
//! ```
//!
//! Publish a file (requires `ffmpeg` on `PATH` and an active Tokio runtime):
//! ```no_run
//! # async fn run() -> anyhow::Result<()> {
//! let keypair = halo::Keypair::new()?;
//! let publisher = halo::Publisher::bind("video.mp4", keypair.node_id())?;
//! println!("Join ticket: {}", publisher.ticket());
//! publisher.run().await
//! # }
//! ```
//!
//! Subscribe to a stream and write the fMP4 output to any [`tokio::io::AsyncWrite`]:
//! ```no_run
//! # async fn run(ticket: &str) -> anyhow::Result<()> {
//! let addr = halo::parse_ticket(ticket)?;
//! halo::subscribe(addr, tokio::io::stdout()).await
//! # }
//! ```

pub mod halo_core;
pub mod halo_protocol;

pub use halo_core::keypair::Keypair;
pub use halo_core::publisher::Publisher;
pub use halo_core::subscriber::subscribe;
pub use halo_protocol::node::{Ticket, decode_ticket, encode_ticket, parse_ticket};
