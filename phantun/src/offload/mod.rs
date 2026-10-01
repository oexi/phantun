//! Converts the packets of established connections in the kernel with eBPF, so that they do not
//! pass through Phantun. See src/bpf/offload.bpf.c for how it works.
//!
//! It is used when available: the kernel has to support the programs and Phantun needs the
//! privileges to load them (CAP_BPF and CAP_NET_ADMIN, or root). Otherwise, or with --no-ebpf,
//! every packet goes through Phantun as before, which is also the case for connections whose
//! application is on another host, as the programs only deliver datagrams locally.
//!
//! The packets are converted on the network interface the fake TCP connection uses, bypassing the
//! Tun interface, routing and netfilter, unless that is not possible or disabled with
//! --no-ebpf-nic, in which case they are converted on the Tun interface.
//!
//! With FEC, the programs convert data shards and pass a copy of them to Phantun, which computes
//! the parity shards and recovers lost data shards.

use crate::fec::Fec;
use clap::{Arg, ArgAction, ArgMatches};
use fake_tcp::Socket;
use std::net::SocketAddr;
use std::sync::Arc;

pub fn args() -> [Arg; 2] {
    [
        Arg::new("no_ebpf")
            .long("no-ebpf")
            .required(false)
            .help(
                "Do not convert packets in the kernel with eBPF. By default, the packets of a \
                 connection whose UDP peer is on this host are converted between UDP and fake \
                 TCP by eBPF programs, when the kernel and permissions allow it",
            )
            .action(ArgAction::SetTrue),
        Arg::new("no_ebpf_nic")
            .long("no-ebpf-nic")
            .required(false)
            .help(
                "Convert packets with eBPF on the Tun interface only. By default, they are \
                 converted on the network interface the fake TCP connection uses, bypassing the \
                 Tun interface, routing and netfilter",
            )
            .action(ArgAction::SetTrue),
    ]
}

/// Sets up the eBPF data path for the Tun interface `tun`, unless it is disabled or not possible,
/// which is logged
pub fn start(matches: &ArgMatches, tun: &str, fec: bool) -> Option<Arc<Offload>> {
    if matches.get_flag("no_ebpf") {
        log::info!("eBPF data path disabled by --no-ebpf");
        return None;
    }
    match Offload::new(tun, fec, !matches.get_flag("no_ebpf_nic")) {
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
        Ok(()) if fec.is_some() => log::info!(
            "Packets of {sock} are converted by eBPF {}, with FEC computed by Phantun",
            conn.location()
        ),
        Ok(()) => log::info!(
            "Packets of {sock} are converted by eBPF {}",
            conn.location()
        ),
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
    use std::net::SocketAddr;
    use std::sync::Arc;

    pub enum Offload {}

    impl Offload {
        pub fn new(_tun: &str, _fec: bool, _nic: bool) -> Result<Offload, String> {
            Err("Phantun was built without eBPF support".to_string())
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

        pub fn location(&self) -> String {
            match *self {}
        }

        pub fn packets(&self) -> u64 {
            match *self {}
        }
    }
}
#[cfg(not(ebpf))]
pub use imp::{Connection, Offload};
