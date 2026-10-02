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

use bytes::{Bytes, BytesMut};
use log::{error, info, trace, warn};
use packet::*;
use pnet::packet::{Packet, tcp};
use rand::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU32, Ordering},
};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::time;
use tokio_tun::Tun;

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 6;
const MPMC_BUFFER_LEN: usize = 512;
const MPSC_BUFFER_LEN: usize = 128;
/// Size of the buffers that the reader tasks read packets into, one after the other, so that a
/// buffer only has to be allocated every few packets. The packets keep their buffer alive until
/// they are all dropped.
const READ_BUF_LEN: usize = 16 * 1024;
// Also in phantun/src/bpf/offload.bpf.c
const MAX_UNACKED_LEN: u32 = 128 * 1024 * 1024; // 128MB

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
    tuples: RwLock<HashMap<AddrTuple, flume::Sender<Bytes>>>,
    listening: RwLock<HashSet<u16>>,
    tun: Vec<Arc<Tun>>,
    ready: mpsc::Sender<Socket>,
    tuples_purge: broadcast::Sender<AddrTuple>,
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
}

/// Set in [`Numbers::flags`] once the other end is known to have completed the handshake, after
/// which data packets carry PSH. PSH stops the receiving kernel from merging the packets with GRO,
/// which would keep them from the eBPF data path of Phantun. Until then, data packets only carry
/// ACK, as older versions also take the first one as the end of the handshake if its ACK was lost.
pub const FLAG_PSH: u32 = 1;

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
    incoming: flume::Receiver<Bytes>,
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
        state: State,
    ) -> (Socket, flume::Sender<Bytes>) {
        let (incoming_tx, incoming_rx) = flume::bounded(MPMC_BUFFER_LEN);

        (
            Socket {
                shared,
                tun,
                incoming: incoming_rx,
                local_addr,
                remote_addr,
                numbers: NumbersStorage::Owned(Numbers {
                    seq: AtomicU32::new(0),
                    ack: AtomicU32::new(ack.unwrap_or(0)),
                    last_ack: AtomicU32::new(ack.unwrap_or(0)),
                    flags: AtomicU32::new(0),
                }),
                state,
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
        match self.state {
            State::Established => {
                let (seq, flags) = self.take_seq(payload.len());
                let buf = self.build_tcp_packet_with_seq(seq, flags, Some(payload));
                self.tun.send(&buf).await.ok().and(Some(()))
            }
            _ => unreachable!(),
        }
    }

    /// Sends the datagram `buf[offset..]` like [`Socket::send`], but writes the headers in front
    /// of it, to the end of `buf[..offset]`, instead of copying it. `offset` has to be at least
    /// [`MAX_HEADER_LEN`].
    pub async fn send_in_place(&self, buf: &mut [u8], offset: usize) -> Option<()> {
        match self.state {
            State::Established => {
                let (seq, flags) = self.take_seq(buf.len() - offset);
                let numbers = self.numbers();
                let ack = numbers.ack.load(Ordering::Relaxed);
                numbers.last_ack.store(ack, Ordering::Relaxed);

                let packet = &mut buf[offset - header_len(self.local_addr, flags)..];
                write_tcp_headers(packet, self.local_addr, self.remote_addr, seq, ack, flags);
                self.tun.send(packet).await.ok().and(Some(()))
            }
            _ => unreachable!(),
        }
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

    /// Attempt to receive a datagram from the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the TCP connection is broken
    /// and this socket must be closed.
    pub async fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        let payload = self.recv_bytes().await?;
        buf[..payload.len()].copy_from_slice(&payload);
        Some(payload.len())
    }

    /// Like [`Socket::recv`], but returns the datagram where it was received rather than copying
    /// it
    pub async fn recv_bytes(&self) -> Option<Bytes> {
        match self.state {
            State::Established => {
                let raw_buf = self.incoming.recv_async().await.ok()?;
                let (_v4_packet, tcp_packet) = parse_ip_packet(&raw_buf).unwrap();

                if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                    info!("Connection {} reset by peer", self);
                    return None;
                }

                let payload = tcp_packet.payload();

                let new_ack = tcp_packet.get_sequence().wrapping_add(payload.len() as u32);
                let numbers = self.numbers();
                let last_ask = numbers.last_ack.load(Ordering::Relaxed);
                numbers.ack.store(new_ack, Ordering::Relaxed);
                // only sent once the handshake is complete on the other end
                if !payload.is_empty() && numbers.flags.load(Ordering::Relaxed) & FLAG_PSH == 0 {
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

                Some(raw_buf.slice_ref(payload))
            }
            _ => unreachable!(),
        }
    }

    async fn accept(mut self) {
        for _ in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None);
                    // ACK set by constructor
                    self.tun.send(&buf).await.unwrap();
                    self.state = State::SynReceived;
                    info!("Sent SYN + ACK to client");
                }
                State::SynReceived => {
                    let res = time::timeout(TIMEOUT, self.incoming.recv_async()).await;
                    if let Ok(buf) = res {
                        let buf = buf.unwrap();
                        let (_v4_packet, tcp_packet) = parse_ip_packet(&buf).unwrap();

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
                            self.numbers().flags.fetch_or(FLAG_PSH, Ordering::Relaxed);
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
                                    && incoming.try_send(buf.clone()).is_err()
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
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN, None);
                    self.tun.send(&buf).await.unwrap();
                    self.state = State::SynSent;
                    info!("Sent SYN to server");
                }
                State::SynSent => {
                    match time::timeout(TIMEOUT, self.incoming.recv_async()).await {
                        Ok(buf) => {
                            let buf = buf.unwrap();
                            let (_v4_packet, tcp_packet) = parse_ip_packet(&buf).unwrap();

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
    /// Create a new stack, `tun` is an array of [`Tun`](tokio_tun::Tun).
    /// When more than one [`Tun`](tokio_tun::Tun) object is passed in, same amount
    /// of reader will be spawned later. This allows user to utilize the performance
    /// benefit of Multiqueue Tun support on machines with SMP.
    pub fn new(tun: Vec<Tun>, local_ip: Ipv4Addr, local_ip6: Option<Ipv6Addr>) -> Stack {
        let tun: Vec<Arc<Tun>> = tun.into_iter().map(Arc::new).collect();
        let (ready_tx, ready_rx) = mpsc::channel(MPSC_BUFFER_LEN);
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            tun: tun.clone(),
            listening: RwLock::new(HashSet::new()),
            ready: ready_tx,
            tuples_purge: tuples_purge_tx.clone(),
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
                    State::Idle,
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
        let mut tuples: HashMap<AddrTuple, flume::Sender<Bytes>> = HashMap::new();
        let mut read_buf = BytesMut::new();

        loop {
            if read_buf.len() < MAX_PACKET_LEN {
                read_buf = BytesMut::zeroed(READ_BUF_LEN);
            }

            tokio::select! {
                size = tun.recv(&mut read_buf[..MAX_PACKET_LEN]) => {
                    let size = size.unwrap();
                    let buf = read_buf.split_to(size).freeze();

                    match parse_ip_packet(&buf) {
                        Some((ip_packet, tcp_packet)) => {
                            let local_addr =
                                SocketAddr::new(ip_packet.get_destination(), tcp_packet.get_destination());
                            let remote_addr = SocketAddr::new(ip_packet.get_source(), tcp_packet.get_source());

                            let tuple = AddrTuple::new(local_addr, remote_addr);
                            if let Some(c) = tuples.get(&tuple) {
                                if c.send_async(buf.clone()).await.is_ok() {
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
                                if c.send_async(buf).await.is_err() {
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
                                    let (sock, incoming) = Socket::new(
                                        shared.clone(),
                                        tun.clone(),
                                        local_addr,
                                        remote_addr,
                                        Some(tcp_packet.get_sequence() + 1),
                                        State::Idle,
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
