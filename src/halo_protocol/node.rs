//! HALO join ticket encoding and decoding.

use anyhow::{Context, Result};
use base32::Alphabet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Default QUIC port used by HALO publishers and subscribers.
pub const DEFAULT_PORT: u16 = 4443;

/// Decoded contents of a HALO join ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    /// Ticket wire format version (currently `1`).
    pub version: u8,
    /// 32-byte Ed25519 public key identifying the publisher node.
    pub node_id: [u8; 32],
    /// IP address of the publisher node.
    pub ip: IpAddr,
}

/// Encodes a HALO join ticket as a z-base32 string.
///
/// Wire format: version (1 byte), NodeID (32 bytes), IP version (1 byte: `4` or `6`),
/// and the IP address bytes (4 bytes for IPv4 or 16 bytes for IPv6).
///
/// # Examples
/// ```
/// use std::net::{IpAddr, Ipv6Addr};
/// use halo::halo_protocol::node::{decode_ticket, encode_ticket};
///
/// let node_id = [1u8; 32];
/// let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
/// let encoded = encode_ticket(&node_id, ip);
/// let decoded = decode_ticket(&encoded).unwrap();
/// assert_eq!(decoded.node_id, node_id);
/// assert_eq!(decoded.ip, ip);
/// ```
pub fn encode_ticket(node_id: &[u8; 32], ip: IpAddr) -> String {
    let mut bytes = Vec::with_capacity(50);
    bytes.push(1);
    bytes.extend_from_slice(node_id);
    match ip {
        IpAddr::V4(ip) => {
            bytes.push(4);
            bytes.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(6);
            bytes.extend_from_slice(&ip.octets());
        }
    }
    base32::encode(Alphabet::Z, &bytes)
}

/// Decodes a z-base32 HALO join ticket into a [`Ticket`].
pub fn decode_ticket(ticket: &str) -> Result<Ticket> {
    let bytes = base32::decode(Alphabet::Z, ticket).context("failed to decode ticket")?;
    anyhow::ensure!(bytes.len() >= 34, "ticket is too short");

    let version = bytes[0];
    anyhow::ensure!(version == 1, "unsupported ticket version: {version}");

    let node_id: [u8; 32] = bytes[1..33]
        .try_into()
        .context("failed to extract NodeID")?;

    let ip = match bytes[33] {
        4 => {
            anyhow::ensure!(bytes.len() >= 38, "IPv4 ticket is too short");
            let octets: [u8; 4] = bytes[34..38]
                .try_into()
                .context("failed to extract IPv4 address")?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        6 => {
            anyhow::ensure!(bytes.len() >= 50, "IPv6 ticket is too short");
            let octets: [u8; 16] = bytes[34..50]
                .try_into()
                .context("failed to extract IPv6 address")?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        version => anyhow::bail!("unsupported IP version: {version}"),
    };

    Ok(Ticket {
        version,
        node_id,
        ip,
    })
}

/// Decodes a HALO join ticket and returns the publisher [`SocketAddr`] on [`DEFAULT_PORT`].
pub fn parse_ticket(ticket: &str) -> Result<SocketAddr> {
    let ticket = decode_ticket(ticket)?;
    Ok(SocketAddr::new(ticket.ip, DEFAULT_PORT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_round_trip_ipv4() {
        let node_id = [7u8; 32];
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        let ticket = encode_ticket(&node_id, ip);
        let decoded = decode_ticket(&ticket).unwrap();

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.node_id, node_id);
        assert_eq!(decoded.ip, ip);
        assert_eq!(
            parse_ticket(&ticket).unwrap(),
            SocketAddr::new(ip, DEFAULT_PORT)
        );
    }

    #[test]
    fn ticket_round_trip_ipv6() {
        let node_id = [11u8; 32];
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let ticket = encode_ticket(&node_id, ip);
        let decoded = decode_ticket(&ticket).unwrap();

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.node_id, node_id);
        assert_eq!(decoded.ip, ip);
        assert_eq!(
            parse_ticket(&ticket).unwrap(),
            SocketAddr::new(ip, DEFAULT_PORT)
        );
    }

    #[test]
    fn rejects_invalid_tickets() {
        assert!(decode_ticket("!!!not-base32!!!").is_err());

        // Too short
        let short = base32::encode(Alphabet::Z, &[1u8; 10]);
        assert!(decode_ticket(&short).is_err());

        // Unsupported ticket version
        let mut bad_version = vec![2u8];
        bad_version.extend_from_slice(&[0u8; 32]);
        bad_version.push(6);
        bad_version.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        assert!(decode_ticket(&base32::encode(Alphabet::Z, &bad_version)).is_err());

        // Unsupported IP version
        let mut bad_ip_ver = vec![1u8];
        bad_ip_ver.extend_from_slice(&[0u8; 32]);
        bad_ip_ver.push(5);
        bad_ip_ver.extend_from_slice(&[0u8; 16]);
        assert!(decode_ticket(&base32::encode(Alphabet::Z, &bad_ip_ver)).is_err());

        // Truncated IPv6 payload
        let mut short_v6 = vec![1u8];
        short_v6.extend_from_slice(&[0u8; 32]);
        short_v6.push(6);
        short_v6.extend_from_slice(&[0u8; 8]);
        assert!(decode_ticket(&base32::encode(Alphabet::Z, &short_v6)).is_err());
    }
}
