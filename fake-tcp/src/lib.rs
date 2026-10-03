//! A minimum, userspace TCP based datagram stack
//!
//! # Overview
//!
//! `fake-tcp` is a reusable library that implements a minimum TCP stack in
//! user space using the Tun interface. It allows programs to send datagrams
//! as if they are part of a TCP connection. `fake-tcp` has been tested to
//! be able to pass through a variety of NAT and stateful firewalls while
//! fully preserves certain desirable behavior such as out of order delivery
//! and no congestion/flow controls.
//!
//! # Core Concepts
//!
//! The core of the `fake-tcp` crate compose of two structures. [`Stack`] and
//! [`Socket`].
//!
//! ## [`Stack`]
//!
//! [`Stack`] represents a virtual TCP stack that operates at
//! Layer 3. It is responsible for:
//!
//! * TCP active and passive open and handshake
//! * `RST` handling
//! * Interact with the Tun interface at Layer 3
//! * Distribute incoming datagrams to corresponding [`Socket`]
//!
//! ## [`Socket`]
//!
//! [`Socket`] represents a TCP connection. It registers the identifying
//! tuple `(src_ip, src_port, dest_ip, dest_port)` inside the [`Stack`] so
//! so that incoming packets can be distributed to the right [`Socket`] with
//! using a channel. It is also what the client should use for
//! sending/receiving datagrams.
//!
//! # Examples
//!
//! Please see [`client.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/client.rs)
//! and [`server.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/server.rs) files
//! from the `phantun` crate for how to use this library in client/server mode, respectively.

#![cfg_attr(feature = "benchmark", feature(test))]

pub mod packet;
pub mod tun;

use bytes::{Bytes, BytesMut};
use log::{error, info, trace, warn};
use packet::*;
use pnet::packet::{Packet, tcp};
use rand::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::IoSlice;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicU32, Ordering},
};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::time;
use tun::*;

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 6;
const MPMC_BUFFER_LEN: usize = 512;
const MPSC_BUFFER_LEN: usize = 128;
/// Size of the buffers that the reader tasks read packets into, one after the other, so that a
/// buffer only has to be allocated every few packets. The packets keep their buffer alive until
/// they are all dropped.
const READ_BUF_LEN: usize = 256 * 1024;
// Also in phantun/src/bpf/offload.bpf.c
const MAX_UNACKED_LEN: u32 = 128 * 1024 * 1024; // 128MB
/// The most segments written at once for the kernel to split
const MAX_SEGMENTS: usize = 64;
/// The most payload written at once for the kernel to split, which the length fields of the IP
/// headers limit
const MAX_SEGMENTS_LEN: usize = u16::MAX as usize - MAX_HEADER_LEN;
/// How far the acknowledgement number of data packets may lag behind when the other end merges
/// packets, see [`FLAG_MERGE`]. Stateful firewalls, such as conntrack, accept 66000 bytes at the
/// least. Also in phantun/src/bpf/offload.bpf.c.
const ACK_HOLD: u32 = 32 * 1024;
/// The window of the SYN or SYN + ACK of an end that takes packets merged by GRO, which the other
/// end sees as [`FLAG_MERGE`]. Any other window, such as [`WINDOW`] from older versions, means
/// that it does not. It is the usual window of a SYN from Linux.
pub const MERGE_WINDOW: u16 = 64240;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct AddrTuple {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl AddrTuple {
    fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> AddrTuple {
        AddrTuple {
            local_addr,
            remote_addr,
        }
    }
}

struct Shared {
    tuples: RwLock<HashMap<AddrTuple, flume::Sender<Received>>>,
    listening: RwLock<HashSet<u16>>,
    tun: Vec<Arc<Tun>>,
    ready: mpsc::Sender<Socket>,
    tuples_purge: broadcast::Sender<AddrTuple>,
    merge: Merge,
}

/// When an end tells the other end that it takes packets merged by GRO, see [`MERGE_WINDOW`]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Merge {
    Never,
    Always,
    /// Only if the other end said so first, which only a server sees, in the SYN. With it, the
    /// other end can write several packets at once, see [`Socket::send_many`], and this end can
    /// read them merged. This suits an end that converts its packets with eBPF, which it cannot do
    /// for merged ones, so that an end without eBPF can do with less work.
    WithPeer,
}

/// A packet read from the Tun interface for a connection
#[derive(Clone)]
struct Received {
    packet: Bytes,
    /// The length of the payload of each segment, but the last, if the kernel merged several
    segment_len: Option<usize>,
}

/// Datagrams received at once, one after the other, see [`Socket::recv_batch`]
pub struct Datagrams {
    payload: Bytes,
    len: usize,
}

impl Datagrams {
    /// The datagrams, one after the other
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// The length of each datagram, but the last, which may be shorter
    pub fn segment_len(&self) -> usize {
        self.len
    }

    /// The datagrams
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.payload.chunks(self.len.max(1))
    }

    /// Takes the first datagram
    fn split_first(&mut self) -> Bytes {
        self.payload.split_to(self.len.min(self.payload.len()))
    }
}

pub struct Stack {
    shared: Arc<Shared>,
    local_ip: Ipv4Addr,
    local_ip6: Option<Ipv6Addr>,
    ready: mpsc::Receiver<Socket>,
}

pub enum State {
    Idle,
    SynSent,
    SynReceived,
    Established,
}

/// The sequence and acknowledgement numbers of a connection
#[repr(C)]
#[derive(Default)]
pub struct Numbers {
    pub seq: AtomicU32,
    pub ack: AtomicU32,
    /// The acknowledgement number most recently sent
    pub last_ack: AtomicU32,
    /// `FLAG_*`
    pub flags: AtomicU32,
    /// The IP ID of the next data packet over IPv4, of which the lower 16 bits are used. It goes
    /// up by one for each, as the receiving kernel only merges packets with GRO when their IDs go
    /// up one by one, or stay the same, and only passes merged packets with the same IDs to a Tun
    /// interface after splitting them again.
    pub ip_id: AtomicU32,
}

/// Set in [`Numbers::flags`] once the other end is known to have completed the handshake, after
/// which data packets carry PSH. PSH stops the receiving kernel from merging the packets with GRO,
/// which would keep them from the eBPF data path of Phantun. Until then, data packets only carry
/// ACK, as older versions also take the first one as the end of the handshake if its ACK was lost.
/// Never set with [`FLAG_MERGE`].
pub const FLAG_PSH: u32 = 1;

/// Set in [`Numbers::flags`] if the other end takes packets merged by GRO, as it said with
/// [`MERGE_WINDOW`] during the handshake. Data packets then never carry PSH, their
/// acknowledgement number only moves on every [`ACK_HOLD`] bytes, as GRO only merges packets
/// with the same one, and several of the same length may be written at once for the kernel to
/// split.
pub const FLAG_MERGE: u32 = 2;

/// Memory holding the [`Numbers`] of a connection that is shared with something else sending and
/// receiving on its behalf, such as an eBPF program. See [`Socket::share_numbers`].
pub trait SharedNumbers: Send + Sync {
    fn numbers(&self) -> &Numbers;
}

enum NumbersStorage {
    Owned(Numbers),
    Shared(Arc<dyn SharedNumbers>),
}

impl NumbersStorage {
    fn get(&self) -> &Numbers {
        match self {
            NumbersStorage::Owned(n) => n,
            NumbersStorage::Shared(s) => s.numbers(),
        }
    }
}

pub struct Socket {
    shared: Arc<Shared>,
    tun: Arc<Tun>,
    /// Whether this end said it takes packets merged by GRO
    merges: bool,
    incoming: flume::Receiver<Received>,
    /// Datagrams received but not returned yet by [`Socket::recv`]
    leftover: Mutex<Option<Datagrams>>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    numbers: NumbersStorage,
    state: State,
}

/// A socket that represents a unique TCP connection between a server and client.
///
/// The `Socket` object itself satisfies `Sync` and `Send`, which means it can
/// be safely called within an async future.
///
/// To close a TCP connection that is no longer needed, simply drop this object
/// out of scope.
impl Socket {
    fn new(
        shared: Arc<Shared>,
        tun: Arc<Tun>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        ack: Option<u32>,
        merges: bool,
        peer_merges: bool,
    ) -> (Socket, flume::Sender<Received>) {
        let (incoming_tx, incoming_rx) = flume::bounded(MPMC_BUFFER_LEN);

        (
            Socket {
                shared,
                tun,
                merges,
                incoming: incoming_rx,
                leftover: Mutex::new(None),
                local_addr,
                remote_addr,
                numbers: NumbersStorage::Owned(Numbers {
                    seq: AtomicU32::new(0),
                    ack: AtomicU32::new(ack.unwrap_or(0)),
                    last_ack: AtomicU32::new(ack.unwrap_or(0)),
                    flags: AtomicU32::new(if peer_merges { FLAG_MERGE } else { 0 }),
                    ip_id: AtomicU32::new(rand::random::<u16>().into()),
                }),
                state: State::Idle,
            },
            incoming_tx,
        )
    }

    fn numbers(&self) -> &Numbers {
        self.numbers.get()
    }

    fn build_tcp_packet(&self, flags: u8, payload: Option<&[u8]>) -> Bytes {
        self.build_tcp_packet_with_seq(self.numbers().seq.load(Ordering::Relaxed), flags, payload)
    }

    fn build_tcp_packet_with_seq(&self, seq: u32, flags: u8, payload: Option<&[u8]>) -> Bytes {
        let numbers = self.numbers();
        let ack = numbers.ack.load(Ordering::Relaxed);
        numbers.last_ack.store(ack, Ordering::Relaxed);

        build_tcp_packet(self.local_addr, self.remote_addr, seq, ack, flags, payload)
    }

    /// The SYN or SYN + ACK of this end
    fn build_handshake_packet(&self, flags: u8) -> Bytes {
        let numbers = self.numbers();
        let ack = numbers.ack.load(Ordering::Relaxed);
        numbers.last_ack.store(ack, Ordering::Relaxed);
        let window = if self.merges { MERGE_WINDOW } else { WINDOW };

        build_tcp_packet_with_window(
            self.local_addr,
            self.remote_addr,
            numbers.seq.load(Ordering::Relaxed),
            ack,
            flags,
            window,
            None,
        )
    }

    /// Whether this end told the other end that it takes packets merged by GRO, see
    /// [`MERGE_WINDOW`]. Those that are merged and those that are not then have to take the same
    /// path to stay in order.
    pub fn merges(&self) -> bool {
        self.merges
    }

    /// Whether the other end takes packets merged by GRO, see [`FLAG_MERGE`]
    pub fn peer_merges(&self) -> bool {
        self.numbers().flags.load(Ordering::Relaxed) & FLAG_MERGE != 0
    }

    /// The local address of the connection, as seen on the Tun interface
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The address of the other end
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Moves the sequence and acknowledgement numbers into `shared`, so that whatever else uses
    /// them can send and receive data on this connection as well. `shared` is kept until the
    /// socket is dropped.
    pub fn share_numbers(&mut self, shared: Arc<dyn SharedNumbers>) {
        let (old, new) = (self.numbers(), shared.numbers());
        for (o, n) in [
            (&old.seq, &new.seq),
            (&old.ack, &new.ack),
            (&old.last_ack, &new.last_ack),
            (&old.flags, &new.flags),
            (&old.ip_id, &new.ip_id),
        ] {
            n.store(o.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        self.numbers = NumbersStorage::Shared(shared);
    }

    /// Sends a datagram to the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the Tun socket returned an error
    /// and this socket must be closed.
    pub async fn send(&self, payload: &[u8]) -> Option<()> {
        self.send_many(&[payload]).await
    }

    /// Sends `datagrams` to the other end, in order, like [`Socket::send`]. If the other end takes
    /// packets merged by GRO, see [`FLAG_MERGE`], and the Tun interface has virtio-net headers,
    /// datagrams of the same length are written at once, for the kernel to split into packets.
    pub async fn send_many(&self, datagrams: &[&[u8]]) -> Option<()> {
        match self.state {
            State::Established => {
                let batch = self.tun.vnet_hdr() && self.peer_merges();
                let mut rest = datagrams;
                while !rest.is_empty() {
                    let (run, tail) = rest.split_at(if batch { segments(rest) } else { 1 });
                    rest = tail;
                    self.send_segments(run).await?;
                }
                Some(())
            }
            _ => unreachable!(),
        }
    }

    /// Writes one packet with `datagrams` as its payload, which the kernel splits into one packet
    /// per datagram if there are several
    async fn send_segments(&self, datagrams: &[&[u8]]) -> Option<()> {
        let payload_len = datagrams.iter().map(|d| d.len()).sum();
        let (seq, flags) = self.take_seq(payload_len);
        let headers = Headers {
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
            ip_id: self
                .numbers()
                .ip_id
                .fetch_add(datagrams.len() as u32, Ordering::Relaxed) as u16,
            seq,
            ack: self.data_ack(),
            flags,
            window: WINDOW,
        };
        let header_len = header_len(self.local_addr, flags);

        let mut buf = [0u8; VNET_HDR_LEN + MAX_HEADER_LEN];
        let header = if self.tun.vnet_hdr() {
            // the kernel computes the checksum, and splits the packet if needed
            let (ip_header_len, gso_type) = match self.local_addr {
                SocketAddr::V4(_) => (IPV4_HEADER_LEN, VIRTIO_NET_HDR_GSO_TCPV4),
                SocketAddr::V6(_) => (IPV6_HEADER_LEN, VIRTIO_NET_HDR_GSO_TCPV6),
            };
            let segments = datagrams.len() > 1;
            VnetHdr {
                flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
                gso_type: if segments {
                    gso_type
                } else {
                    VIRTIO_NET_HDR_GSO_NONE
                },
                hdr_len: header_len as u16,
                gso_size: if segments {
                    datagrams[0].len() as u16
                } else {
                    0
                },
                csum_start: ip_header_len as u16,
                csum_offset: 16,
            }
            .write(&mut buf);
            let header = &mut buf[..VNET_HDR_LEN + header_len];
            write_headers(&mut header[VNET_HDR_LEN..], headers, payload_len, None);
            header
        } else {
            let header = &mut buf[..header_len];
            write_headers(header, headers, payload_len, Some(datagrams));
            header
        };

        let mut iov = [IoSlice::new(&[]); 1 + MAX_SEGMENTS];
        iov[0] = IoSlice::new(header);
        for (iov, datagram) in iov[1..].iter_mut().zip(datagrams) {
            *iov = IoSlice::new(datagram);
        }
        self.tun
            .send_vectored(&iov[..1 + datagrams.len()])
            .await
            .ok()
            .and(Some(()))
    }

    /// Takes the sequence number for a data packet with `len` bytes of payload, and returns it with
    /// the flags of the packet
    fn take_seq(&self, len: usize) -> (u32, u8) {
        // Take the sequence number atomically, as other threads or an eBPF program may send at the
        // same time
        let seq = self.numbers().seq.fetch_add(len as u32, Ordering::Relaxed);
        let flags = if self.numbers().flags.load(Ordering::Relaxed) & FLAG_PSH != 0 {
            tcp::TcpFlags::PSH | tcp::TcpFlags::ACK
        } else {
            tcp::TcpFlags::ACK
        };
        (seq, flags)
    }

    /// The acknowledgement number for a data packet, which lags behind if the other end merges
    /// packets, see [`FLAG_MERGE`]
    fn data_ack(&self) -> u32 {
        let numbers = self.numbers();
        let ack = numbers.ack.load(Ordering::Relaxed);
        if numbers.flags.load(Ordering::Relaxed) & FLAG_MERGE != 0 {
            let last_ack = numbers.last_ack.load(Ordering::Relaxed);
            // also when it went back, as reordered packets do
            if (ack.wrapping_sub(last_ack) as i32) < ACK_HOLD as i32 {
                return last_ack;
            }
        }
        numbers.last_ack.store(ack, Ordering::Relaxed);
        ack
    }

    /// Attempt to receive a datagram from the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the TCP connection is broken
    /// and this socket must be closed.
    pub async fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        let leftover = self.leftover.lock().unwrap().take();
        let mut datagrams = match leftover {
            Some(datagrams) => datagrams,
            None => self.recv_batch().await?,
        };
        let datagram = datagrams.split_first();
        if !datagrams.payload.is_empty() {
            *self.leftover.lock().unwrap() = Some(datagrams);
        }
        buf[..datagram.len()].copy_from_slice(&datagram);
        Some(datagram.len())
    }

    /// Like [`Socket::recv`], but returns all datagrams that were received at once, which are
    /// several if the kernel merged their packets, without copying them. Do not mix with
    /// [`Socket::recv`], which keeps those it has not returned yet.
    pub async fn recv_batch(&self) -> Option<Datagrams> {
        match self.state {
            State::Established => {
                let received = self.incoming.recv_async().await.ok()?;
                let (_v4_packet, tcp_packet) = parse_ip_packet(&received.packet).unwrap();

                if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                    info!("Connection {} reset by peer", self);
                    return None;
                }

                let payload = tcp_packet.payload();

                let new_ack = tcp_packet.get_sequence().wrapping_add(payload.len() as u32);
                let numbers = self.numbers();
                let last_ask = numbers.last_ack.load(Ordering::Relaxed);
                numbers.ack.store(new_ack, Ordering::Relaxed);
                // only sent once the handshake is complete on the other end, and never to an end
                // that merges packets
                if !payload.is_empty()
                    && numbers.flags.load(Ordering::Relaxed) & (FLAG_PSH | FLAG_MERGE) == 0
                {
                    numbers.flags.fetch_or(FLAG_PSH, Ordering::Relaxed);
                }

                if new_ack.overflowing_sub(last_ask).0 > MAX_UNACKED_LEN {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                    if let Err(e) = self.tun.try_send(&buf) {
                        // This should not really happen as we have not sent anything for
                        // quite some time...
                        info!("Connection {} unable to send idling ACK back: {}", self, e)
                    }
                }

                Some(Datagrams {
                    len: received.segment_len.unwrap_or(payload.len()),
                    payload: received.packet.slice_ref(payload),
                })
            }
            _ => unreachable!(),
        }
    }

    async fn accept(mut self) {
        for _ in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_handshake_packet(tcp::TcpFlags::SYN | tcp::TcpFlags::ACK);
                    // ACK set by constructor
                    self.tun.send(&buf).await.unwrap();
                    self.state = State::SynReceived;
                    info!("Sent SYN + ACK to client");
                }
                State::SynReceived => {
                    let res = time::timeout(TIMEOUT, self.incoming.recv_async()).await;
                    if let Ok(received) = res {
                        let received = received.unwrap();
                        let (_v4_packet, tcp_packet) = parse_ip_packet(&received.packet).unwrap();

                        if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                            return;
                        }

                        // a lost ACK may be replaced by the first data packet, which carries PSH
                        if tcp_packet.get_flags() & !tcp::TcpFlags::PSH == tcp::TcpFlags::ACK
                            && tcp_packet.get_acknowledgement()
                                == self.numbers().seq.load(Ordering::Relaxed) + 1
                        {
                            // found our ACK
                            self.numbers().seq.fetch_add(1, Ordering::Relaxed);
                            if !self.peer_merges() {
                                self.numbers().flags.fetch_or(FLAG_PSH, Ordering::Relaxed);
                            }
                            self.state = State::Established;

                            // The window of the SYN + ACK cannot be scaled, so stateful firewalls
                            // such as conntrack only let 64 KB through from the client, and no
                            // longer NAT what follows, until they see another packet from here
                            // with the scaled window. Send one now, as otherwise the next one may
                            // only be the ACK after MAX_UNACKED_LEN if traffic only goes one way.
                            let ack = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                            if let Err(e) = self.tun.send(&ack).await {
                                warn!("Unable to send ACK to {}: {}", self.remote_addr, e);
                            }

                            // When a data packet replaced the ACK, its datagram is still passed
                            // on, after the packets queued behind it
                            if !tcp_packet.payload().is_empty() {
                                let tuple = AddrTuple::new(self.local_addr, self.remote_addr);
                                let incoming =
                                    self.shared.tuples.read().unwrap().get(&tuple).cloned();
                                if let Some(incoming) = incoming
                                    && incoming.try_send(received.clone()).is_err()
                                {
                                    trace!("Queue of {} full, dropping first packet", self);
                                }
                            }

                            info!("Connection from {:?} established", self.remote_addr);
                            let ready = self.shared.ready.clone();
                            if let Err(e) = ready.send(self).await {
                                error!("Unable to send accepted socket to ready queue: {}", e);
                            }
                            return;
                        }
                    } else {
                        info!("Waiting for client ACK timed out");
                        self.state = State::Idle;
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    async fn connect(&mut self) -> Option<()> {
        for _ in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_handshake_packet(tcp::TcpFlags::SYN);
                    self.tun.send(&buf).await.unwrap();
                    self.state = State::SynSent;
                    info!("Sent SYN to server");
                }
                State::SynSent => {
                    match time::timeout(TIMEOUT, self.incoming.recv_async()).await {
                        Ok(received) => {
                            let received = received.unwrap();
                            let (_v4_packet, tcp_packet) =
                                parse_ip_packet(&received.packet).unwrap();

                            if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                                return None;
                            }

                            if tcp_packet.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK
                                && tcp_packet.get_acknowledgement()
                                    == self.numbers().seq.load(Ordering::Relaxed) + 1
                            {
                                // found our SYN + ACK
                                self.numbers().seq.fetch_add(1, Ordering::Relaxed);
                                self.numbers()
                                    .ack
                                    .store(tcp_packet.get_sequence() + 1, Ordering::Relaxed);
                                if tcp_packet.get_window() == MERGE_WINDOW {
                                    self.numbers().flags.fetch_or(FLAG_MERGE, Ordering::Relaxed);
                                }

                                // send ACK to finish handshake
                                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                                self.tun.send(&buf).await.unwrap();

                                self.state = State::Established;

                                info!("Connection to {:?} established", self.remote_addr);
                                return Some(());
                            }
                        }
                        Err(_) => {
                            info!("Waiting for SYN + ACK timed out");
                            self.state = State::Idle;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        None
    }
}

/// How many of `datagrams` from the start can be written at once for the kernel to split: those of
/// the length of the first, and a shorter one at the end
fn segments(datagrams: &[&[u8]]) -> usize {
    let len = datagrams[0].len();
    let mut total = len;
    let mut count = 1;
    if len == 0 {
        return count;
    }
    while let Some(next) = datagrams.get(count).map(|d| d.len()) {
        if next > len || next == 0 || count == MAX_SEGMENTS || total + next > MAX_SEGMENTS_LEN {
            break;
        }
        total += next;
        count += 1;
        if next < len {
            break;
        }
    }
    count
}

impl Drop for Socket {
    /// Drop the socket and close the TCP connection
    fn drop(&mut self) {
        let tuple = AddrTuple::new(self.local_addr, self.remote_addr);
        // dissociates ourself from the dispatch map
        assert!(self.shared.tuples.write().unwrap().remove(&tuple).is_some());
        // purge cache, which fails if no reader task is left, e.g. when shutting down
        let _ = self.shared.tuples_purge.send(tuple);

        let buf = build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.numbers().seq.load(Ordering::Relaxed),
            0,
            tcp::TcpFlags::RST,
            None,
        );
        if let Err(e) = self.tun.try_send(&buf) {
            warn!("Unable to send RST to remote end: {}", e);
        }

        info!("Fake TCP connection to {} closed", self);
    }
}

impl fmt::Display for Socket {
    /// User-friendly string representation of the socket
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(Fake TCP connection from {} to {})",
            self.local_addr, self.remote_addr
        )
    }
}

/// A userspace TCP state machine
impl Stack {
    /// Create a new stack, `tun` is an array of [`Tun`].
    /// When more than one [`Tun`] object is passed in, same amount
    /// of reader will be spawned later. This allows user to utilize the performance
    /// benefit of Multiqueue Tun support on machines with SMP.
    ///
    /// `merge` says when the other ends are told that this end takes packets merged by GRO, see
    /// [`MERGE_WINDOW`], which is only worth it if the Tun interface passes them on as they are,
    /// see [`Tun::gro`].
    pub fn new(
        tun: Vec<Tun>,
        local_ip: Ipv4Addr,
        local_ip6: Option<Ipv6Addr>,
        merge: Merge,
    ) -> Stack {
        let tun: Vec<Arc<Tun>> = tun.into_iter().map(Arc::new).collect();
        let (ready_tx, ready_rx) = mpsc::channel(MPSC_BUFFER_LEN);
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            tun: tun.clone(),
            listening: RwLock::new(HashSet::new()),
            ready: ready_tx,
            tuples_purge: tuples_purge_tx.clone(),
            merge,
        });

        for t in tun {
            tokio::spawn(Stack::reader_task(
                t,
                shared.clone(),
                tuples_purge_tx.subscribe(),
            ));
        }

        Stack {
            shared,
            local_ip,
            local_ip6,
            ready: ready_rx,
        }
    }

    /// Listens for incoming connections on the given `port`.
    pub fn listen(&mut self, port: u16) {
        assert!(self.shared.listening.write().unwrap().insert(port));
    }

    /// Accepts an incoming connection.
    pub async fn accept(&mut self) -> Socket {
        self.ready.recv().await.unwrap()
    }

    /// Connects to the remote end. `None` returned means
    /// the connection attempt failed.
    pub async fn connect(&mut self, addr: SocketAddr) -> Option<Socket> {
        self.connect_merging(addr, self.shared.merge == Merge::Always)
            .await
    }

    /// Like [`Stack::connect`], but `merges` says whether the other end is told that this end
    /// takes packets merged by GRO, rather than the `merge` of [`Stack::new`]
    pub async fn connect_merging(&mut self, addr: SocketAddr, merges: bool) -> Option<Socket> {
        let mut rng = SmallRng::from_os_rng();
        for local_port in rng.random_range(32768..=60999)..=60999 {
            let local_addr = SocketAddr::new(
                if addr.is_ipv4() {
                    IpAddr::V4(self.local_ip)
                } else {
                    IpAddr::V6(self.local_ip6.expect("IPv6 local address undefined"))
                },
                local_port,
            );
            let tuple = AddrTuple::new(local_addr, addr);
            let mut sock;

            {
                let mut tuples = self.shared.tuples.write().unwrap();
                if tuples.contains_key(&tuple) {
                    trace!(
                        "Fake TCP connection to {}, local port number {} already in use, trying another one",
                        addr, local_port
                    );
                    continue;
                }

                let incoming;
                (sock, incoming) = Socket::new(
                    self.shared.clone(),
                    self.shared.tun.choose(&mut rng).unwrap().clone(),
                    local_addr,
                    addr,
                    None,
                    // the server has not said anything yet
                    merges,
                    false,
                );

                assert!(tuples.insert(tuple, incoming).is_none());
            }

            return sock.connect().await.map(|_| sock);
        }

        error!(
            "Fake TCP connection to {} failed, emphemeral port number exhausted",
            addr
        );
        None
    }

    async fn reader_task(
        tun: Arc<Tun>,
        shared: Arc<Shared>,
        mut tuples_purge: broadcast::Receiver<AddrTuple>,
    ) {
        let mut tuples: HashMap<AddrTuple, flume::Sender<Received>> = HashMap::new();
        let mut read_buf = BytesMut::new();
        let vnet_hdr_len = if tun.vnet_hdr() { VNET_HDR_LEN } else { 0 };
        // packets merged by GRO are up to the largest IP packet
        let max_len = vnet_hdr_len
            + if tun.gro() {
                u16::MAX as usize
            } else {
                MAX_PACKET_LEN
            };

        loop {
            if read_buf.len() < max_len {
                read_buf = BytesMut::zeroed(READ_BUF_LEN);
            }

            tokio::select! {
                size = tun.recv(&mut read_buf[..max_len]) => {
                    let size = size.unwrap();
                    let mut buf = read_buf.split_to(size);
                    if size < vnet_hdr_len {
                        continue;
                    }
                    let segment_len = (vnet_hdr_len > 0)
                        .then(|| VnetHdr::read(&buf.split_to(vnet_hdr_len)).tcp_segment_len())
                        .flatten();
                    let buf = buf.freeze();
                    let received = Received {
                        packet: buf.clone(),
                        segment_len,
                    };

                    match parse_ip_packet(&buf) {
                        Some((ip_packet, tcp_packet)) => {
                            let local_addr =
                                SocketAddr::new(ip_packet.get_destination(), tcp_packet.get_destination());
                            let remote_addr = SocketAddr::new(ip_packet.get_source(), tcp_packet.get_source());

                            let tuple = AddrTuple::new(local_addr, remote_addr);
                            if let Some(c) = tuples.get(&tuple) {
                                if c.send_async(received.clone()).await.is_ok() {
                                    continue;
                                }

                                // The connection is closed but its purge has not been seen yet, and a
                                // new connection may already use the same tuple, so fall through to
                                // the slow path below
                                trace!("Cache hit, but receiver already closed, removing cached tuple");
                                tuples.remove(&tuple);
                            }

                            trace!("Cache miss, checking the shared tuples table for connection");
                            let sender = {
                                let tuples = shared.tuples.read().unwrap();
                                tuples.get(&tuple).cloned()
                            };

                            if let Some(c) = sender {
                                trace!("Storing connection information into local tuples");
                                tuples.insert(tuple, c.clone());
                                if c.send_async(received).await.is_err() {
                                    trace!("Connection closed while dispatching, dropping packet");
                                }
                                continue;
                            }

                            if tcp_packet.get_flags() == tcp::TcpFlags::SYN
                                && shared
                                    .listening
                                    .read()
                                    .unwrap()
                                    .contains(&tcp_packet.get_destination())
                            {
                                // SYN seen on listening socket
                                if tcp_packet.get_sequence() == 0 {
                                    let peer_merges = tcp_packet.get_window() == MERGE_WINDOW;
                                    let (sock, incoming) = Socket::new(
                                        shared.clone(),
                                        tun.clone(),
                                        local_addr,
                                        remote_addr,
                                        Some(tcp_packet.get_sequence() + 1),
                                        match shared.merge {
                                            Merge::Never => false,
                                            Merge::Always => true,
                                            Merge::WithPeer => peer_merges,
                                        },
                                        peer_merges,
                                    );
                                    assert!(shared
                                        .tuples
                                        .write()
                                        .unwrap()
                                        .insert(tuple, incoming)
                                        .is_none());
                                    tokio::spawn(sock.accept());
                                } else {
                                    trace!("Bad TCP SYN packet from {}, sending RST", remote_addr);
                                    let buf = build_tcp_packet(
                                        local_addr,
                                        remote_addr,
                                        0,
                                        tcp_packet.get_sequence().wrapping_add(tcp_packet.payload().len() as u32 + 1), // +1 because of SYN flag set
                                        tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
                                        None,
                                    );
                                    if let Err(e) = shared.tun[0].try_send(&buf) {
                                        warn!("Unable to send RST to {}: {}", remote_addr, e);
                                    }
                                }
                            } else if (tcp_packet.get_flags() & tcp::TcpFlags::RST) == 0 {
                                info!("Unknown TCP packet from {}, sending RST", remote_addr);
                                let buf = build_tcp_packet(
                                    local_addr,
                                    remote_addr,
                                    tcp_packet.get_acknowledgement(),
                                    tcp_packet.get_sequence().wrapping_add(tcp_packet.payload().len() as u32),
                                    tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
                                    None,
                                );
                                if let Err(e) = shared.tun[0].try_send(&buf) {
                                    warn!("Unable to send RST to {}: {}", remote_addr, e);
                                }
                            }
                        }
                        None => {
                            continue;
                        }
                    }
                },
                tuple = tuples_purge.recv() => {
                    match tuple {
                        Ok(tuple) => {
                            tuples.remove(&tuple);
                            trace!("Removed cached tuple: {:?}", tuple);
                        }
                        // The channel only holds so many purges, and this task does not read it while
                        // a connection's queue is full. The cache only mirrors `shared.tuples`, so it
                        // can simply be rebuilt.
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            info!("Missed {} cached tuple purges, clearing the cache", skipped);
                            tuples.clear();
                        }
                        // `shared` holds a sender, so the channel is never closed
                        Err(broadcast::error::RecvError::Closed) => unreachable!(),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runs(lens: &[usize]) -> Vec<usize> {
        let bufs: Vec<Vec<u8>> = lens.iter().map(|&len| vec![0; len]).collect();
        let datagrams: Vec<&[u8]> = bufs.iter().map(Vec::as_slice).collect();
        let mut rest = &datagrams[..];
        let mut runs = Vec::new();
        while !rest.is_empty() {
            let n = segments(rest);
            runs.push(n);
            rest = &rest[n..];
        }
        runs
    }

    #[test]
    fn segments_of_the_same_length() {
        // a shorter one ends a run, a longer one starts another
        assert_eq!(runs(&[100, 100, 100, 50, 100, 200, 200]), [4, 1, 2]);
        // empty ones go on their own
        assert_eq!(runs(&[100, 0, 0, 100]), [1, 1, 1, 1]);
        // up to MAX_SEGMENTS, and up to MAX_SEGMENTS_LEN bytes
        assert_eq!(runs(&[10; MAX_SEGMENTS + 1]), [MAX_SEGMENTS, 1]);
        let n = MAX_SEGMENTS_LEN / 1400;
        assert_eq!(runs(&vec![1400; n + 1]), [n, 1]);
    }

    #[test]
    fn datagrams_of_a_merged_packet() {
        let mut datagrams = Datagrams {
            payload: Bytes::from_static(b"aaabbbcc"),
            len: 3,
        };
        let all: Vec<&[u8]> = datagrams.iter().collect();
        assert_eq!(all, [&b"aaa"[..], b"bbb", b"cc"]);
        assert_eq!(datagrams.split_first(), &b"aaa"[..]);
        assert_eq!(datagrams.split_first(), &b"bbb"[..]);
        assert_eq!(datagrams.split_first(), &b"cc"[..]);
        assert!(datagrams.payload.is_empty());

        let empty = Datagrams {
            payload: Bytes::new(),
            len: 0,
        };
        assert_eq!(empty.iter().count(), 0);
    }
}
