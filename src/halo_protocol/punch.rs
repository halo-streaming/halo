use std::net::SocketAddr;

pub const PUNCH_MAGIC: &[u8] = b"HALO_PUNCH";

/// A firewall hole-punching datagram intercepted by `ThiefSocket`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchPacket {
    pub from: SocketAddr,
    pub node_id: Option<[u8; 32]>,
}

/// Encode a `HALO_PUNCH` datagram: `HALO_PUNCH` (10 bytes) + `node_id` (32 bytes).
pub fn encode_punch(node_id: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PUNCH_MAGIC.len() + node_id.len());
    buf.extend_from_slice(PUNCH_MAGIC);
    buf.extend_from_slice(node_id);
    buf
}

/// Parse a UDP datagram if it starts with `HALO_PUNCH`.
/// Returns `None` for non-punch datagrams (e.g. QUIC traffic).
pub fn parse_punch(from: SocketAddr, data: &[u8]) -> Option<PunchPacket> {
    let rest = data.strip_prefix(PUNCH_MAGIC)?;
    let node_id = rest
        .get(..32)
        .and_then(|slice| <[u8; 32]>::try_from(slice).ok());
    Some(PunchPacket { from, node_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    #[test]
    fn punch_round_trip_and_non_punch_ignored() {
        let from = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4443);
        let node_id = [9u8; 32];
        let encoded = encode_punch(&node_id);

        assert_eq!(
            parse_punch(from, &encoded),
            Some(PunchPacket {
                from,
                node_id: Some(node_id),
            })
        );
        assert_eq!(
            parse_punch(from, PUNCH_MAGIC),
            Some(PunchPacket {
                from,
                node_id: None,
            })
        );
        assert_eq!(parse_punch(from, b"\xc0\x00\x00\x00\x01quic"), None);
    }
}
