pub mod halo_core;
pub mod halo_protocol;

pub use halo_core::discovery::discover_external_addr;
pub use halo_core::keypair::Keypair;
pub use halo_core::publisher::Publisher;
pub use halo_core::subscriber::subscribe;
pub use halo_core::thief_socket::{ThiefHandle, ThiefSocket, thief_socket_pair};
pub use halo_protocol::discovery::{
    DEFAULT_DISCOVERY_PORT, DISCOVERY_ALPN, decode_observed_addr, encode_observed_addr,
};
pub use halo_protocol::node::{Ticket, decode_ticket, encode_ticket, parse_ticket};
pub use halo_protocol::punch::{PUNCH_MAGIC, PunchPacket, encode_punch, parse_punch};
