//! Converts the packets of established connections in the kernel with eBPF, so that they do not
//! pass through Phantun. See src/bpf/offload.bpf.c for how it works.
//!
//! It is used when available: the kernel has to support the programs and Phantun needs the
//! privileges to load them (CAP_BPF and CAP_NET_ADMIN, or root). Otherwise, or with --no-ebpf,
//! every packet goes through Phantun as before.
//!
//! The packets are converted on the network interface the fake TCP connection uses, bypassing the
//! Tun interface, routing and netfilter. Connections for which that is not possible, e.g. those
//! whose application is on another host, as the programs only deliver datagrams locally, pass
//! through Phantun, which passes their packets to the kernel in batches.
//!
//! With FEC, the programs convert data shards and pass a copy of them to Phantun, which computes
//! the parity shards and recovers lost data shards.

use crate::fec::Fec;
use clap::{Arg, ArgAction, ArgMatches};
use fake_tcp::Socket;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

pub fn args() -> [Arg; 1] {
    [Arg::new("no_ebpf")
        .long("no-ebpf")
        .required(false)
        .help(
            "Do not convert packets in the kernel with eBPF. By default, the packets of a \
                 connection whose UDP peer is on this host are converted between UDP and fake \
                 TCP by eBPF programs on the network interface the connection uses, bypassing \
                 the Tun interface, routing and netfilter, when the kernel and permissions allow \
                 it",
        )
        .action(ArgAction::SetTrue)]
}

/// Sets up the eBPF data path for the Tun interface `tun`, unless it is disabled or not possible,
/// which is logged. `remote` is the address of Phantun on the Tun interface and that of the
/// remote end, where all connections go to.
pub fn start(
    matches: &ArgMatches,
    tun: &str,
    fec: bool,
    remote: Option<(IpAddr, IpAddr)>,
) -> Option<Arc<Offload>> {
    if matches.get_flag("no_ebpf") {
        log::info!("eBPF data path disabled by --no-ebpf");
        return None;
    }
    match Offload::new(tun, fec, remote) {
        Ok(offload) => {
            log::info!("eBPF data path enabled");
            let offload = Arc::new(offload);
            offload.start_records();
            Some(offload)
        }
        Err(e) => {
            log::info!("eBPF data path unavailable, every packet passes through Phantun: {e}");
            None
        }
    }
}

/// Whether a connection from `tcp_local` to `tcp_remote` on the Tun interface for `udp_peer` is
/// likely to be converted, before it is made. A client uses this to tell the server whether it takes
/// packets merged by GRO, which it can only do for connections that pass through Phantun.
pub fn may_convert(
    offload: Option<&Arc<Offload>>,
    udp_peer: SocketAddr,
    tcp_local: IpAddr,
    tcp_remote: IpAddr,
) -> bool {
    offload.is_some_and(|o| o.may_convert(udp_peer, tcp_local, tcp_remote).is_ok())
}

/// Prepares `sock` for conversion in the kernel, where `udp_local` is the address Phantun uses
/// to exchange its datagrams with `udp_peer`. Without `offload`, or when the connection does not
/// qualify, which is logged, it does nothing. Conversion starts with [`start_connection`].
pub fn register(
    offload: Option<&Arc<Offload>>,
    sock: &mut Socket,
    udp_local: SocketAddr,
    udp_peer: SocketAddr,
) -> Option<Arc<Connection>> {
    let offload = offload?;
    match offload.register(sock, udp_local, udp_peer) {
        Ok(conn) => Some(conn),
        Err(e) => {
            log::info!("Packets of {sock} pass through Phantun: {e}");
            None
        }
    }
}

/// Starts converting the packets of `sock` registered as `conn`. With FEC, `udp_sock` sends the
/// datagrams recovered from what the eBPF programs pass on.
pub fn start_connection(
    conn: Option<&Arc<Connection>>,
    sock: &Arc<Socket>,
    fec: Option<&Arc<Fec>>,
    udp_sock: &Arc<tokio::net::UdpSocket>,
) {
    let Some(conn) = conn else {
        return;
    };
    match conn.start(sock, fec.map(|fec| (fec, udp_sock.clone()))) {
        Ok(()) => {
            let fec = if fec.is_some() {
                ", with FEC computed by Phantun"
            } else {
                ""
            };
            if sock.merges() {
                log::info!(
                    "Packets sent on {sock} are converted by eBPF on {}, those received pass \
                     through Phantun, as the other end sends them merged{fec}",
                    conn.nic()
                );
            } else {
                log::info!(
                    "Packets of {sock} are converted by eBPF on {}{fec}",
                    conn.nic()
                );
            }
        }
        Err(e) => log::info!("Packets of {sock} pass through Phantun: {e}"),
    }
}

#[cfg(ebpf)]
mod netlink;

#[cfg(ebpf)]
mod imp;
#[cfg(ebpf)]
pub use imp::{Connection, Offload};

#[cfg(not(ebpf))]
mod imp {
    use crate::fec::Fec;
    use fake_tcp::Socket;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;

    pub enum Offload {}

    impl Offload {
        pub fn new(
            _tun: &str,
            _fec: bool,
            _remote: Option<(IpAddr, IpAddr)>,
        ) -> Result<Offload, String> {
            Err("Phantun was built without eBPF support".to_string())
        }

        pub fn may_convert(
            &self,
            _udp_peer: SocketAddr,
            _tcp_local: IpAddr,
            _tcp_remote: IpAddr,
        ) -> Result<(), String> {
            match *self {}
        }

        pub fn start_records(self: &Arc<Self>) {
            match **self {}
        }

        pub fn register(
            &self,
            _sock: &mut Socket,
            _udp_local: SocketAddr,
            _udp_peer: SocketAddr,
        ) -> Result<Arc<Connection>, String> {
            match *self {}
        }

        pub fn detach(&self) {
            match *self {}
        }
    }

    pub enum Connection {}

    impl Connection {
        pub fn start(
            &self,
            _sock: &Arc<Socket>,
            _fec: Option<(&Arc<Fec>, Arc<tokio::net::UdpSocket>)>,
        ) -> Result<(), String> {
            match *self {}
        }

        pub fn nic(&self) -> &str {
            match *self {}
        }

        pub fn packets(&self) -> u64 {
            match *self {}
        }

        pub fn fec_full(&self) -> u64 {
            match *self {}
        }
    }
}
#[cfg(not(ebpf))]
pub use imp::{Connection, Offload};
