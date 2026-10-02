use log::debug;
use neli::{
    consts::{
        nl::NlmF,
        rtnl::{Ifa, IfaF, RtAddrFamily, RtScope, Rtm},
        socket::NlFamily,
    },
    nl::{NlPayload, NlmsghdrBuilder},
    rtnl::{IfaddrmsgBuilder, RtattrBuilder},
    socket::synchronous::NlSocketHandle,
    types::RtBuffer,
    utils::Groups,
};
use nix::sys::socket::{
    CmsgIterator, ControlMessageOwned, MsgFlags, SockaddrLike, SockaddrStorage, cmsg_space,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// A UDP socket bound to `local_addr` with SO_REUSEPORT, which receives the datagrams of new UDP
/// peers. It fails like any socket would, e.g. when the process has as many file descriptors open
/// as it may.
pub fn new_udp_reuseport(local_addr: SocketAddr) -> io::Result<UdpSocket> {
    let udp_sock = new_udp(local_addr, true)?;

    // enable IP_PKTINFO/IPV6_PKTINFO delivery so we know the destination address of incoming
    // packets
    if local_addr.is_ipv4() {
        nix::sys::socket::setsockopt(&udp_sock, nix::sys::socket::sockopt::Ipv4PacketInfo, &true)?;
    } else {
        nix::sys::socket::setsockopt(
            &udp_sock,
            nix::sys::socket::sockopt::Ipv6RecvPacketInfo,
            &true,
        )?;
    }

    udp_sock.bind(&socket2::SockAddr::from(local_addr))?;
    let udp_sock: std::net::UdpSocket = udp_sock.into();
    udp_sock.try_into()
}

/// The UDP socket of a connection, bound to `local_addr` and connected to `remote_addr`. With
/// `reuseport`, it shares the port of `local_addr` with the socket from [`new_udp_reuseport`],
/// which then no longer receives the datagrams of `remote_addr`.
///
/// A connection has a single one: the kernel only balances datagrams between the sockets of a
/// port that are not connected, so only one of several connected to the same address would
/// receive them.
pub async fn connect_udp(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    reuseport: bool,
) -> io::Result<UdpSocket> {
    let udp_sock = new_udp(local_addr, reuseport)?;
    udp_sock.bind(&socket2::SockAddr::from(local_addr))?;
    let udp_sock: std::net::UdpSocket = udp_sock.into();
    let udp_sock: UdpSocket = udp_sock.try_into()?;
    udp_sock.connect(remote_addr).await?;
    Ok(udp_sock)
}

/// A non-blocking UDP socket for `local_addr`, not bound yet
fn new_udp(local_addr: SocketAddr, reuseport: bool) -> io::Result<socket2::Socket> {
    let udp_sock = socket2::Socket::new(
        if local_addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        None,
    )?;
    if reuseport {
        udp_sock.set_reuse_port(true)?;
    }
    raise_recv_buffer(&udp_sock);
    // from tokio-rs/mio/blob/master/src/sys/unix/net.rs
    udp_sock.set_cloexec(true)?;
    udp_sock.set_nonblocking(true)?;
    Ok(udp_sock)
}

/// Raises the limit of open file descriptors to the most the process may have, as each connection
/// takes a UDP socket.
pub fn raise_fd_limit() {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};

    match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok((soft, hard)) if soft < hard => match setrlimit(Resource::RLIMIT_NOFILE, hard, hard) {
            Ok(()) => debug!("Raised the limit of open files from {soft} to {hard}"),
            Err(e) => debug!("Unable to raise the limit of open files from {soft}: {e}"),
        },
        Ok(_) => {}
        Err(e) => debug!("Unable to get the limit of open files: {e}"),
    }
}

/// The receive buffer size of the UDP sockets. Applications such as kernel WireGuard send
/// datagrams in bursts, which overflow the default buffer of about 200 KiB before Phantun gets to
/// read them. The losses this causes make TCP inside the tunnel retransmit a lot and slow down.
/// A larger buffer only queues more while Phantun cannot keep up, which adds up to about 15 ms of
/// latency at 500 Mbit/s.
const UDP_RECV_BUFFER: usize = 1024 * 1024;

/// Raises the receive buffer of `sock` to `UDP_RECV_BUFFER`, beyond net.core.rmem_max if
/// permitted, which CAP_NET_ADMIN does
fn raise_recv_buffer(sock: &socket2::Socket) {
    use nix::sys::socket::{setsockopt, sockopt};

    // the kernel doubles the requested size to account for its overhead
    if sock
        .recv_buffer_size()
        .is_ok_and(|size| size >= 2 * UDP_RECV_BUFFER)
    {
        return;
    }
    if setsockopt(sock, sockopt::RcvBufForce, &UDP_RECV_BUFFER).is_err() {
        let _ = setsockopt(sock, sockopt::RcvBuf, &UDP_RECV_BUFFER);
    }
}

/// Similiar to `UdpSocket::recv_from()`, but returns a 3rd value `IPAddr`
/// which corresponds to where the UDP datagram was destined to, this is useful
/// for disambigous when socket can receive on multiple IP address
/// or interfaces.
pub async fn udp_recv_pktinfo(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, IpAddr)> {
    sock.async_io(Interest::READABLE, || {
        const CONTROL_MESSAGE_BUFFER_SIZE: usize = max_usize(
            cmsg_space::<nix::libc::in_pktinfo>(),
            cmsg_space::<nix::libc::in6_pktinfo>(),
        );
        let mut control_message_buffer = [0u8; CONTROL_MESSAGE_BUFFER_SIZE];
        let iov = &mut [std::io::IoSliceMut::new(buf)];
        let res = nix::sys::socket::recvmsg::<SockaddrStorage>(
            sock.as_raw_fd(),
            iov,
            Some(&mut control_message_buffer),
            MsgFlags::empty(),
        )?;

        let src_addr = res.address.expect("missing source address");
        let src_addr: SocketAddr = {
            if let Some(inaddr) = src_addr.as_sockaddr_in() {
                SocketAddrV4::new(inaddr.ip(), inaddr.port()).into()
            } else if let Some(in6addr) = src_addr.as_sockaddr_in6() {
                SocketAddrV6::new(
                    in6addr.ip(),
                    in6addr.port(),
                    in6addr.flowinfo(),
                    in6addr.scope_id(),
                )
                .into()
            } else {
                panic!("unexpected source address family {:#?}", src_addr.family());
            }
        };

        let dst_addr = dst_addr_from_cmsgs(res.cmsgs()?).expect("didn't receive pktinfo");

        Ok((res.bytes, src_addr, dst_addr))
    })
    .await
}

fn dst_addr_from_cmsgs(cmsgs: CmsgIterator) -> Option<IpAddr> {
    for cmsg in cmsgs {
        if let ControlMessageOwned::Ipv4PacketInfo(pktinfo) = cmsg {
            return Some(Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_ne_bytes()).into());
        }
        if let ControlMessageOwned::Ipv6PacketInfo(pktinfo) = cmsg {
            return Some(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr).into());
        }
    }

    None
}

pub fn assign_ipv6_address(device_name: &str, local: Ipv6Addr, peer: Ipv6Addr) {
    let index = nix::net::if_::if_nametoindex(device_name).unwrap();

    let rtnl = NlSocketHandle::connect(NlFamily::Route, None, Groups::empty()).unwrap();
    let mut rtattrs = RtBuffer::new();
    rtattrs.push(
        RtattrBuilder::default()
            .rta_type(Ifa::Local)
            .rta_payload(&local.octets()[..])
            .build()
            .unwrap(),
    );
    rtattrs.push(
        RtattrBuilder::default()
            .rta_type(Ifa::Address)
            .rta_payload(&peer.octets()[..])
            .build()
            .unwrap(),
    );

    let ifaddrmsg = IfaddrmsgBuilder::default()
        .ifa_family(RtAddrFamily::Inet6)
        .ifa_prefixlen(128)
        .ifa_flags(IfaF::empty())
        .ifa_scope(RtScope::Universe)
        .ifa_index(index)
        .rtattrs(rtattrs)
        .build()
        .unwrap();
    let nl_header = NlmsghdrBuilder::default()
        .nl_type(Rtm::Newaddr)
        .nl_flags(NlmF::REQUEST)
        .nl_payload(NlPayload::Payload(ifaddrmsg))
        .build()
        .unwrap();
    rtnl.send(&nl_header).unwrap();
}

const fn max_usize(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// Completes when the process receives SIGINT or SIGTERM
pub async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("unable to listen for SIGTERM");
    tokio::select! {
        _ = term.recv() => {},
        _ = tokio::signal::ctrl_c() => {},
    }
}
