use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const DISCOVERY_ALPN: &[u8] = b"halo-discovery/1";
pub const DEFAULT_DISCOVERY_PORT: u16 = 4444;

/// Encode an observed external SocketAddr:
/// `[ip_version: 1B (4 or 6)][ip_bytes: 4B or 16B][port: 2B BE]`.
pub fn encode_observed_addr(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V6(v6) => {
            let mut buf = Vec::with_capacity(19);
            buf.push(6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
            buf
        }
        SocketAddr::V4(v4) => {
            let mut buf = Vec::with_capacity(7);
            buf.push(4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
            buf
        }
    }
}

/// Decode an observed external SocketAddr sent by the discovery server.
pub fn decode_observed_addr(bytes: &[u8]) -> Result<SocketAddr> {
    anyhow::ensure!(!bytes.is_empty(), "empty discovery response");
    match bytes[0] {
        6 => {
            anyhow::ensure!(bytes.len() == 19, "invalid IPv6 discovery response length");
            let octets: [u8; 16] = bytes[1..17]
                .try_into()
                .context("failed to read IPv6 address")?;
            let port = u16::from_be_bytes([bytes[17], bytes[18]]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        4 => {
            anyhow::ensure!(bytes.len() == 7, "invalid IPv4 discovery response length");
            let octets: [u8; 4] = bytes[1..5]
                .try_into()
                .context("failed to read IPv4 address")?;
            let port = u16::from_be_bytes([bytes[5], bytes[6]]);
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        v => anyhow::bail!("unsupported IP version in discovery response: {v}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_addr_round_trip() {
        let v6 = SocketAddr::new(IpAddr::V6("2a01:cb00::42".parse().unwrap()), 51234);
        assert_eq!(decode_observed_addr(&encode_observed_addr(v6)).unwrap(), v6);

        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 4443);
        assert_eq!(decode_observed_addr(&encode_observed_addr(v4)).unwrap(), v4);
    }
}
