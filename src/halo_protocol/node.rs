use anyhow::{Context, Result};
use base32::Alphabet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const DEFAULT_PORT: u16 = 4443;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub version: u8,
    pub node_id: [u8; 32],
    pub ip: IpAddr,
}

/// Encode a HALO join ticket.
///
/// format: version (1 byte), NodeID (32 bytes), IP version (1 byte) as defined in the HALO protocol, 
/// and the IP address (4 bytes for IPv4 or 16 bytes for IPv6).
pub fn encode_ticket(node_id: &[u8; 32], ip: IpAddr) -> String {
    let mut bytes = Vec::with_capacity(38);
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

/// Decode a HALO join ticket.
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

/// Decode a ticket and produce the publisher SocketAddr.
pub fn parse_ticket(ticket: &str) -> Result<SocketAddr> {
    let ticket = decode_ticket(ticket)?;
    Ok(SocketAddr::new(ticket.ip, DEFAULT_PORT))
}

/// Transform an IP/PORT string to a SocketAddr structure.
pub fn parse_ip_port(s: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = s
        .rsplit_once('/')
        .ok_or_else(|| "expected IP/PORT".to_string())?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ip: IpAddr = host
        .parse()
        .map_err(|e| format!("invalid IP address {host:?}: {e}"))?;
    let port: u16 = port
        .parse()
        .map_err(|e| format!("invalid port {port:?}: {e}"))?;
    Ok(SocketAddr::new(ip, port))
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

        assert_eq!(decoded.node_id, node_id);
        assert_eq!(decoded.ip, ip);
    }
}
