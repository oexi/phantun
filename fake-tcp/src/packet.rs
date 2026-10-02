use bytes::{Bytes, BytesMut};
use internet_checksum::Checksum;
use pnet::packet::Packet;
use pnet::packet::{ip, ipv4, ipv6, tcp};
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr};

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
pub const MAX_PACKET_LEN: usize = 1500;

pub enum IPPacket<'p> {
    V4(ipv4::Ipv4Packet<'p>),
    V6(ipv6::Ipv6Packet<'p>),
}

impl IPPacket<'_> {
    pub fn get_source(&self) -> IpAddr {
        match self {
            IPPacket::V4(p) => IpAddr::V4(p.get_source()),
            IPPacket::V6(p) => IpAddr::V6(p.get_source()),
        }
    }

    pub fn get_destination(&self) -> IpAddr {
        match self {
            IPPacket::V4(p) => IpAddr::V4(p.get_destination()),
            IPPacket::V6(p) => IpAddr::V6(p.get_destination()),
        }
    }
}

/// Room to leave in front of a payload for the IP and TCP headers of a data packet, which have no
/// options, see [`write_tcp_headers`]
pub const MAX_HEADER_LEN: usize = IPV6_HEADER_LEN + TCP_HEADER_LEN;

/// The length of the IP and TCP headers of a packet from `local_addr` with `flags`
pub fn header_len(local_addr: SocketAddr, flags: u8) -> usize {
    let ip_header_len = match local_addr {
        SocketAddr::V4(_) => IPV4_HEADER_LEN,
        SocketAddr::V6(_) => IPV6_HEADER_LEN,
    };
    let wscale = (flags & tcp::TcpFlags::SYN) != 0;
    ip_header_len + TCP_HEADER_LEN + if wscale { 4 } else { 0 } // nop + wscale
}

pub fn build_tcp_packet(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: Option<&[u8]>,
) -> Bytes {
    let header_len = header_len(local_addr, flags);
    let payload = payload.unwrap_or_default();
    let mut buf = BytesMut::zeroed(header_len + payload.len());
    buf[header_len..].copy_from_slice(payload);
    write_tcp_headers(&mut buf, local_addr, remote_addr, seq, ack, flags);
    buf.freeze()
}

/// Writes the IP and TCP headers of a packet to the start of `buf`, which holds the whole packet:
/// the headers are [`header_len`] bytes long and followed by the payload, which is left as it is.
pub fn write_tcp_headers(
    buf: &mut [u8],
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
) {
    let ip_header_len = match local_addr {
        SocketAddr::V4(_) => IPV4_HEADER_LEN,
        SocketAddr::V6(_) => IPV6_HEADER_LEN,
    };
    let wscale = (flags & tcp::TcpFlags::SYN) != 0;
    let total_len = buf.len();
    let tcp_total_len = total_len - ip_header_len;
    // the buffer may hold anything where the headers go
    buf[..header_len(local_addr, flags)].fill(0);
    let (ip_buf, tcp_buf) = buf.split_at_mut(ip_header_len);

    match (local_addr, remote_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
            let mut v4 = ipv4::MutableIpv4Packet::new(ip_buf).unwrap();
            v4.set_version(4);
            v4.set_header_length(IPV4_HEADER_LEN as u8 / 4);
            v4.set_next_level_protocol(ip::IpNextHeaderProtocols::Tcp);
            v4.set_ttl(64);
            v4.set_source(*local.ip());
            v4.set_destination(*remote.ip());
            v4.set_total_length(total_len.try_into().unwrap());
            v4.set_flags(ipv4::Ipv4Flags::DontFragment);
            let mut cksm = Checksum::new();
            cksm.add_bytes(v4.packet());
            v4.set_checksum(u16::from_be_bytes(cksm.checksum()));
        }
        (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
            let mut v6 = ipv6::MutableIpv6Packet::new(ip_buf).unwrap();
            v6.set_version(6);
            v6.set_payload_length(tcp_total_len.try_into().unwrap());
            v6.set_next_header(ip::IpNextHeaderProtocols::Tcp);
            v6.set_hop_limit(64);
            v6.set_source(*local.ip());
            v6.set_destination(*remote.ip());
        }
        _ => unreachable!(),
    };

    let mut tcp = tcp::MutableTcpPacket::new(tcp_buf).unwrap();
    tcp.set_window(0xffff);
    tcp.set_source(local_addr.port());
    tcp.set_destination(remote_addr.port());
    tcp.set_sequence(seq);
    tcp.set_acknowledgement(ack);
    tcp.set_flags(flags);
    tcp.set_data_offset(TCP_HEADER_LEN as u8 / 4 + if wscale { 1 } else { 0 });
    if wscale {
        let wscale = tcp::TcpOption::wscale(14);
        tcp.set_options(&[tcp::TcpOption::nop(), wscale]);
    }

    let mut cksm = Checksum::new();
    let ip::IpNextHeaderProtocol(tcp_protocol) = ip::IpNextHeaderProtocols::Tcp;

    match (local_addr, remote_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
            cksm.add_bytes(&local.ip().octets());
            cksm.add_bytes(&remote.ip().octets());

            let mut pseudo = [0u8, tcp_protocol, 0, 0];
            pseudo[2..].copy_from_slice(&(tcp_total_len as u16).to_be_bytes());
            cksm.add_bytes(&pseudo);
        }
        (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
            cksm.add_bytes(&local.ip().octets());
            cksm.add_bytes(&remote.ip().octets());

            let mut pseudo = [0u8, 0, 0, 0, 0, 0, 0, tcp_protocol];
            pseudo[0..4].copy_from_slice(&(tcp_total_len as u32).to_be_bytes());
            cksm.add_bytes(&pseudo);
        }
        _ => unreachable!(),
    };

    cksm.add_bytes(tcp.packet());
    tcp.set_checksum(u16::from_be_bytes(cksm.checksum()));
}

/// Parses a TCP packet, `None` if it is something else or malformed
pub fn parse_ip_packet(buf: &Bytes) -> Option<(IPPacket<'_>, tcp::TcpPacket<'_>)> {
    let version = buf.first()? >> 4;
    if version == 4 {
        let v4 = ipv4::Ipv4Packet::new(buf)?;
        if v4.get_next_level_protocol() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        // the header may have options
        let header_len = v4.get_header_length() as usize * 4;
        if header_len < IPV4_HEADER_LEN {
            return None;
        }
        let tcp = tcp::TcpPacket::new(buf.get(header_len..)?)?;
        Some((IPPacket::V4(v4), tcp))
    } else if version == 6 {
        let v6 = ipv6::Ipv6Packet::new(buf)?;
        if v6.get_next_header() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        let tcp = tcp::TcpPacket::new(buf.get(IPV6_HEADER_LEN..)?)?;
        Some((IPPacket::V6(v6), tcp))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_options() {
        let local = "192.168.201.2:4567".parse().unwrap();
        let remote = "10.0.0.1:40000".parse().unwrap();
        let packet = build_tcp_packet(local, remote, 123, 456, tcp::TcpFlags::ACK, Some(b"data"));

        // insert 4 bytes of options (NOP, NOP, NOP, EOL) into the IPv4 header
        let mut buf = packet[..IPV4_HEADER_LEN].to_vec();
        buf.extend_from_slice(&[1, 1, 1, 0]);
        buf.extend_from_slice(&packet[IPV4_HEADER_LEN..]);
        buf[0] = 0x46;
        let total_len = (buf.len() as u16).to_be_bytes();
        buf[2..4].copy_from_slice(&total_len);
        let buf = Bytes::from(buf);

        let (ip, tcp) = parse_ip_packet(&buf).unwrap();
        assert_eq!(ip.get_source(), local.ip());
        assert_eq!(ip.get_destination(), remote.ip());
        assert_eq!(tcp.get_source(), local.port());
        assert_eq!(tcp.get_destination(), remote.port());
        assert_eq!(tcp.get_sequence(), 123);
        assert_eq!(tcp.get_acknowledgement(), 456);
        assert_eq!(tcp.payload(), b"data");
    }

    #[test]
    fn write_headers_in_place() {
        for (local, remote) in [
            ("192.168.201.2:4567", "10.0.0.1:40000"),
            ("[fcc9::2]:4567", "[2001:db8::1]:40000"),
        ] {
            let local: SocketAddr = local.parse().unwrap();
            let remote: SocketAddr = remote.parse().unwrap();
            for flags in [tcp::TcpFlags::ACK, tcp::TcpFlags::PSH | tcp::TcpFlags::ACK] {
                let packet = build_tcp_packet(local, remote, 123, 456, flags, Some(b"data"));

                // whatever is in front of the payload is overwritten
                let mut buf = [0xa5u8; MAX_HEADER_LEN + 4];
                buf[MAX_HEADER_LEN..].copy_from_slice(b"data");
                let start = MAX_HEADER_LEN - header_len(local, flags);
                write_tcp_headers(&mut buf[start..], local, remote, 123, 456, flags);
                assert_eq!(buf[start..], packet[..]);
            }
        }
    }

    #[test]
    fn parse_malformed() {
        let local = "192.168.201.2:4567".parse().unwrap();
        let remote = "10.0.0.1:40000".parse().unwrap();
        let packet = build_tcp_packet(local, remote, 123, 456, tcp::TcpFlags::ACK, None);

        // truncated anywhere, or with a header length beyond the packet
        for len in 0..packet.len() {
            assert!(
                parse_ip_packet(&packet.slice(..len)).is_none(),
                "{len} bytes"
            );
        }
        let mut buf = packet.to_vec();
        buf[0] = 0x4f;
        assert!(parse_ip_packet(&Bytes::from(buf)).is_none());
    }
}

#[cfg(all(test, feature = "benchmark"))]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::{Bencher, black_box};

    #[bench]
    fn bench_build_tcp_packet_1460(b: &mut Bencher) {
        let local_addr = "127.0.0.1:1234".parse().unwrap();
        let remote_addr = "127.0.0.2:1234".parse().unwrap();
        let payload = black_box([123u8; 1460]);
        b.iter(|| {
            build_tcp_packet(
                local_addr,
                remote_addr,
                123,
                456,
                tcp::TcpFlags::ACK,
                Some(&payload),
            )
        });
    }

    #[bench]
    fn bench_build_tcp_packet_512(b: &mut Bencher) {
        let local_addr = "127.0.0.1:1234".parse().unwrap();
        let remote_addr = "127.0.0.2:1234".parse().unwrap();
        let payload = black_box([123u8; 512]);
        b.iter(|| {
            build_tcp_packet(
                local_addr,
                remote_addr,
                123,
                456,
                tcp::TcpFlags::ACK,
                Some(&payload),
            )
        });
    }

    #[bench]
    fn bench_build_tcp_packet_128(b: &mut Bencher) {
        let local_addr = "127.0.0.1:1234".parse().unwrap();
        let remote_addr = "127.0.0.2:1234".parse().unwrap();
        let payload = black_box([123u8; 128]);
        b.iter(|| {
            build_tcp_packet(
                local_addr,
                remote_addr,
                123,
                456,
                tcp::TcpFlags::ACK,
                Some(&payload),
            )
        });
    }
}
