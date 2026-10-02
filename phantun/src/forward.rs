//! Forwards the datagrams of a connection between its UDP socket and its fake TCP connection

use crate::UDP_TTL;
use crate::fec::{self, Fec, HEADROOM};
use crate::offload;
use crate::udp;
use clap::{Arg, ArgAction, ArgMatches};
use fake_tcp::Socket;
use log::{debug, error, info};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::time;
use tokio_util::sync::CancellationToken;

pub fn args() -> [Arg; 1] {
    [Arg::new("no_gso")
        .long("no-gso")
        .required(false)
        .help(
            "Have the kernel neither split nor merge packets for Phantun. By default, the Tun \
             interface and the UDP sockets pass packets in batches: the kernel splits those that \
             Phantun writes together (GSO), and merges those it receives (GRO), if the kernel \
             supports it and, for fake TCP packets, the other end takes merged packets",
        )
        .action(ArgAction::SetTrue)]
}

/// Whether the kernel splits and merges packets, see [`args`]
pub fn gso(matches: &ArgMatches) -> bool {
    !matches.get_flag("no_gso")
}

/// Forwards datagrams between `udp_sock`, which is connected to `udp_peer`, and `sock`, until
/// either fails or no traffic is seen for `UDP_TTL`, at which point the connection should be
/// closed. Packets converted by eBPF, as registered in `offloaded`, count as traffic as well.
///
/// Each direction has a task of its own, so that both can make progress at the same time while
/// the datagrams of each stay in order. With `gso`, datagrams of the same length are sent to
/// `udp_sock` at once.
pub async fn forward(
    sock: Arc<Socket>,
    udp_sock: Arc<UdpSocket>,
    udp_peer: SocketAddr,
    fec: Option<Arc<Fec>>,
    offloaded: Option<Arc<offload::Connection>>,
    gso: bool,
) {
    match (sock.peer_merges(), sock.merges()) {
        (true, true) => info!("Packets of {sock} pass in batches both ways"),
        (true, false) => info!("Packets sent on {sock} pass in batches"),
        (false, true) => info!("Packets received on {sock} pass in batches"),
        (false, false) => {}
    }

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
        udp::Sender::new(gso),
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
    let mut receiver = udp::Receiver::new(HEADROOM);

    loop {
        let mut bufs = tokio::select! {
            res = receiver.recv(&udp_sock) => match res {
                Ok(bufs) => bufs,
                // e.g. ECONNREFUSED when nothing listens on the other end yet
                Err(e) => {
                    debug!("Unable to receive from the UDP socket of {}: {}", sock, e);
                    continue;
                }
            },
            _ = quit.cancelled() => return,
        };

        if fec::send_datagrams(&sock, fec.as_deref(), &mut bufs)
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
    mut sender: udp::Sender,
    active: Arc<AtomicBool>,
    quit: CancellationToken,
) {
    let mut recovered = Vec::new();

    loop {
        let datagrams = tokio::select! {
            res = sock.recv_batch() => match res {
                Some(datagrams) => datagrams,
                None => {
                    quit.cancel();
                    return;
                }
            },
            _ = quit.cancelled() => return,
        };

        let res = match fec {
            None => {
                sender
                    .send_segments(&udp_sock, datagrams.payload(), datagrams.segment_len())
                    .await
            }
            Some(ref fec) => {
                for frame in datagrams.iter() {
                    fec::decode(fec, frame, &mut recovered, |d| sender.push(d));
                }
                sender.flush(&udp_sock).await
            }
        };
        if let Err(e) = res {
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
