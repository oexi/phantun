//! Forwards the datagrams of a connection between its UDP socket and its fake TCP connection

use crate::UDP_TTL;
use crate::fec::{self, Fec, SEND_HEADROOM};
use crate::offload;
use fake_tcp::Socket;
use fake_tcp::packet::MAX_PACKET_LEN;
use log::{debug, error, info};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::time;
use tokio_util::sync::CancellationToken;

/// Forwards datagrams between `udp_sock`, which is connected to `udp_peer`, and `sock`, until
/// either fails or no traffic is seen for `UDP_TTL`, at which point the connection should be
/// closed. Packets converted by eBPF, as registered in `offloaded`, count as traffic as well.
///
/// Each direction has a task of its own, so that both can make progress at the same time while
/// the datagrams of each stay in order.
pub async fn forward(
    sock: Arc<Socket>,
    udp_sock: Arc<UdpSocket>,
    udp_peer: SocketAddr,
    fec: Option<Arc<Fec>>,
    offloaded: Option<Arc<offload::Connection>>,
) {
    let quit = CancellationToken::new();
    // stops the tasks however this returns
    let _quit = quit.clone().drop_guard();
    let active = Arc::new(AtomicBool::new(false));

    if let Some(ref fec) = fec {
        let sock = sock.clone();
        let fec = fec.clone();
        let quit = quit.clone();

        tokio::spawn(async move {
            tokio::select! {
                _ = fec.run_flusher(&sock) => quit.cancel(),
                _ = quit.cancelled() => {},
            }
        });
    }

    tokio::spawn(udp_to_tcp(
        sock.clone(),
        udp_sock.clone(),
        fec.clone(),
        active.clone(),
        quit.clone(),
    ));
    tokio::spawn(tcp_to_udp(
        sock,
        udp_sock,
        udp_peer,
        fec,
        active.clone(),
        quit.clone(),
    ));

    // Checked once per UDP_TTL rather than reset by every packet, so a connection is closed after
    // UDP_TTL to twice that without traffic
    let mut offloaded_packets = offloaded.as_ref().map_or(0, |c| c.packets());
    loop {
        tokio::select! {
            _ = time::sleep(UDP_TTL) => {},
            _ = quit.cancelled() => return,
        }

        let packets = offloaded.as_ref().map_or(0, |c| c.packets());
        if !active.swap(false, Ordering::Relaxed) && packets == offloaded_packets {
            info!(
                "No traffic seen in the last {:?}, closing connection",
                UDP_TTL
            );
            return;
        }
        offloaded_packets = packets;
    }
}

/// Notes that a packet passed, which only writes to the memory shared with the other tasks of the
/// connection once per check
fn mark_active(active: &AtomicBool) {
    if !active.load(Ordering::Relaxed) {
        active.store(true, Ordering::Relaxed);
    }
}

async fn udp_to_tcp(
    sock: Arc<Socket>,
    udp_sock: Arc<UdpSocket>,
    fec: Option<Arc<Fec>>,
    active: Arc<AtomicBool>,
    quit: CancellationToken,
) {
    let mut buf = [0u8; SEND_HEADROOM + MAX_PACKET_LEN];

    loop {
        let size = tokio::select! {
            res = udp_sock.recv(&mut buf[SEND_HEADROOM..]) => match res {
                Ok(size) => size,
                // e.g. ECONNREFUSED when nothing listens on the other end yet
                Err(e) => {
                    debug!("Unable to receive from the UDP socket of {}: {}", sock, e);
                    continue;
                }
            },
            _ = quit.cancelled() => return,
        };

        if fec::send_datagram(&sock, fec.as_deref(), &mut buf[..SEND_HEADROOM + size])
            .await
            .is_none()
        {
            quit.cancel();
            return;
        }
        mark_active(&active);
    }
}

async fn tcp_to_udp(
    sock: Arc<Socket>,
    udp_sock: Arc<UdpSocket>,
    udp_peer: SocketAddr,
    fec: Option<Arc<Fec>>,
    active: Arc<AtomicBool>,
    quit: CancellationToken,
) {
    let mut recovered = Vec::new();

    loop {
        let datagram = tokio::select! {
            res = sock.recv_bytes() => match res {
                Some(datagram) => datagram,
                None => {
                    quit.cancel();
                    return;
                }
            },
            _ = quit.cancelled() => return,
        };

        if !datagram.is_empty()
            && let Err(e) =
                fec::forward_to_udp(&udp_sock, fec.as_deref(), &datagram, &mut recovered).await
        {
            error!(
                "Unable to send UDP packet to {}: {}, closing connection",
                udp_peer, e
            );
            quit.cancel();
            return;
        }
        mark_active(&active);
    }
}
