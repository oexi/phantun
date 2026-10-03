use super::netlink::{self, Direction, FilterId, LOOPBACK_IFINDEX, Netlink};
use crate::fec::Fec;
use aya::maps::RingBuf;
use aya::maps::{HashMap as BpfHashMap, MapData};
use aya::programs::SchedClassifier;
use aya::{Ebpf, EbpfLoader, Pod};
use fake_tcp::{Numbers, SharedNumbers, Socket};
use log::{debug, error, info, warn};
use nix::libc;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsFd, AsRawFd};
use std::ptr::NonNull;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex, Weak};
use tokio::io::unix::AsyncFd;

static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offload.bpf.o"));

// Must match the definitions in offload.bpf.c
const MAX_CONNECTIONS: u32 = 4096;

/// struct tuple
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Tuple {
    saddr: [u8; 16],
    daddr: [u8; 16],
    // network byte order
    sport: u16,
    dport: u16,
    family: u32,
}

/// CONV_USER_RX
const CONV_USER_RX: u32 = 1;

/// struct conversion
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Conversion {
    out: Tuple,
    tun: Tuple,
    slot: u32,
    fec_id: u32,
    fec_data_shards: u32,
    flags: u32,
    ifindex: u32,
    _pad: u32,
}

// Only accessed through atomics, where they exist
#[cfg(target_has_atomic = "64")]
type FecClaims = std::sync::atomic::AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
type FecClaims = u64;

/// struct state
#[repr(C)]
struct State {
    numbers: Numbers,
    _pad1: u32,
    // Written by the eBPF programs without atomics
    tx: UnsafeCell<u64>,
    rx: UnsafeCell<u64>,
    fec_claims: FecClaims,
    fec_full: UnsafeCell<u64>,
    _pad2: u64,
}

/// The header of struct record, followed by the data
const RECORD_HEADER_LEN: usize = 16;
const RECORD_SENT_DATA: u32 = 0;
const RECORD_RECEIVED_DATA: u32 = 1;
const RECORD_RECEIVED_PARITY: u32 = 2;
/// The size of the ring buffer for records, when FEC is enabled. Each record takes about 1.5 KiB,
/// so it holds about 150 ms at 1.5 Gbit/s. When it is full, packets take the path through Phantun,
/// out of order with the others.
const RECORDS_SIZE: u32 = 32 * 1024 * 1024;

const _: () = assert!(size_of::<Tuple>() == 40);
const _: () = assert!(size_of::<Conversion>() == 104);
const _: () = assert!(size_of::<State>() == 64);

unsafe impl Pod for Tuple {}
unsafe impl Pod for Conversion {}

// The priorities of the filters on the loopback and network interfaces, where filters of other
// programs and other instances of Phantun may be as well. The instances share these priorities,
// their filters are told apart by the handle, which is the index of their Tun interface.
const CONVERT_PRIORITY: u16 = 0x7068;
const REDIRECT_PRIORITY: u16 = 0x7069;
const FILTER_NAME_PREFIX: &str = "phantun:";

// Link types (ARPHRD_*) of the network interfaces the programs support, with an Ethernet header
// and without any
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_PPP: u16 = 512;
const ARPHRD_RAWIP: u16 = 519;
const ARPHRD_NONE: u16 = 0xfffe;

impl Tuple {
    /// The addresses of a packet from `src` to `dst`, unless they are of different families
    fn new(src: SocketAddr, dst: SocketAddr) -> Option<Tuple> {
        let mut t = Tuple {
            sport: src.port().to_be(),
            dport: dst.port().to_be(),
            ..Default::default()
        };
        match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                t.saddr[..4].copy_from_slice(&s.octets());
                t.daddr[..4].copy_from_slice(&d.octets());
                t.family = 4;
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                t.saddr = s.octets();
                t.daddr = d.octets();
                t.family = 6;
            }
            _ => return None,
        }
        Some(t)
    }
}

/// IPv4-mapped IPv6 addresses are IPv4 addresses on the wire
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Whether `ip` is an address of this host
fn is_local(ip: IpAddr) -> bool {
    UdpSocket::bind((ip, 0)).is_ok()
}

fn last_os_error(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

/// Loads the program `name` of `ebpf`, and returns its file descriptor
fn load_program(ebpf: &mut Ebpf, name: &str) -> Result<i32, String> {
    let prog: &mut SchedClassifier = ebpf
        .program_mut(name)
        .unwrap()
        .try_into()
        .map_err(|e| format!("{name}: {e}"))?;
    prog.load().map_err(|e| match e {
        // The verifier log is long, only show it when asked for
        aya::programs::ProgramError::LoadError {
            io_error,
            verifier_log,
        } => {
            debug!("verifier log of {name}:\n{verifier_log}");
            format!("the kernel rejected the eBPF program {name}: {io_error}")
        }
        e => format!("unable to load the eBPF program {name}: {e}"),
    })?;
    Ok(prog.fd().unwrap().as_fd().as_raw_fd())
}

fn if_index(name: &str) -> Option<u32> {
    nix::net::if_::if_nametoindex(name).ok()
}

/// The `states` array mapped into memory
struct States {
    ptr: NonNull<State>,
    _map: MapData,
}

impl States {
    fn new(map: MapData) -> Result<States, String> {
        let len = MAX_CONNECTIONS as usize * size_of::<State>();
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                map.fd().as_fd().as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(last_os_error("unable to map the connection states"));
        }
        Ok(States {
            ptr: NonNull::new(ptr as *mut State).unwrap(),
            _map: map,
        })
    }

    fn get(&self, slot: u32) -> &State {
        assert!(slot < MAX_CONNECTIONS);
        unsafe { &*self.ptr.as_ptr().add(slot as usize) }
    }
}

impl Drop for States {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.ptr.as_ptr() as *mut libc::c_void,
                MAX_CONNECTIONS as usize * size_of::<State>(),
            );
        }
    }
}

// The mapped memory is only accessed through atomics and volatile reads
unsafe impl Send for States {}
unsafe impl Sync for States {}

/// The programs for network interfaces
struct NicPrograms {
    /// For interfaces with an Ethernet header
    ingress_eth: i32,
    /// For interfaces without one
    ingress_l3: i32,
    redirect: i32,
}

pub struct Offload {
    tcp_conversions: Mutex<BpfHashMap<MapData, Tuple, Conversion>>,
    udp_conversions: Mutex<BpfHashMap<MapData, Tuple, Conversion>>,
    tun_conversions: Mutex<BpfHashMap<MapData, Tuple, Conversion>>,
    states: States,
    free_slots: Mutex<Vec<u32>>,
    tun: String,
    tun_ifindex: u32,
    nic_programs: NicPrograms,
    /// The filters on the loopback and network interfaces, the ones on the Tun interface go with
    /// it. The network interfaces get theirs once a connection uses them, by index.
    filters: Mutex<HashMap<u32, Vec<FilterId>>>,
    /// Why IPv4 datagrams cannot be delivered, see `enable_ipv4_delivery`
    ipv4_unavailable: Option<String>,
    /// FEC records from the eBPF programs, until the task reading them is started
    records: Mutex<Option<RingBuf<MapData>>>,
    /// The connections with FEC by the ID in their records
    fec_connections: Mutex<HashMap<u32, Arc<FecConnection>>>,
    // FEC needs 64-bit atomics
    #[cfg_attr(not(target_has_atomic = "64"), allow(dead_code))]
    next_fec_id: AtomicU32,
    // Keeps the programs loaded
    _ebpf: Ebpf,
}

impl Offload {
    /// Loads the programs for the Tun interface `tun`. With `fec`, records of FEC frames are
    /// passed to Phantun, otherwise the buffer for them is kept small. `remote`, the address of
    /// the Tun interface and the remote end of the connections, if known, helps to find their
    /// network interface in advance.
    pub fn new(tun: &str, fec: bool, remote: Option<(IpAddr, IpAddr)>) -> Result<Offload, String> {
        let tun_ifindex = if_index(tun).ok_or_else(|| format!("no interface {tun}"))?;
        // a power of two and a multiple of the page size
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u32;
        let records_size = if fec {
            RECORDS_SIZE.max(page_size)
        } else {
            page_size
        };

        let mut ebpf = EbpfLoader::new()
            .map_max_entries("records", records_size)
            .load(OBJECT)
            .map_err(|e| format!("unable to load the eBPF programs: {e}"))?;

        let udp_to_tcp = load_program(&mut ebpf, "udp_to_tcp")?;
        let tun_ingress = load_program(&mut ebpf, "tun_ingress")?;
        let nic_programs = NicPrograms {
            ingress_eth: load_program(&mut ebpf, "nic_ingress_eth")?,
            ingress_l3: load_program(&mut ebpf, "nic_ingress_l3")?,
            redirect: load_program(&mut ebpf, "redirect")?,
        };

        let take_hash_map = |ebpf: &mut Ebpf, name| {
            BpfHashMap::try_from(ebpf.take_map(name).unwrap()).map_err(|e| format!("{name}: {e}"))
        };
        let tcp_conversions = take_hash_map(&mut ebpf, "tcp_conversions")?;
        let udp_conversions = take_hash_map(&mut ebpf, "udp_conversions")?;
        let tun_conversions = take_hash_map(&mut ebpf, "tun_conversions")?;
        let states = match ebpf.take_map("states").unwrap() {
            aya::maps::Map::Array(map) => States::new(map)?,
            _ => unreachable!(),
        };
        let records = RingBuf::try_from(ebpf.take_map("records").unwrap())
            .map_err(|e| format!("records: {e}"))?;

        let mut offload = Offload {
            tcp_conversions: Mutex::new(tcp_conversions),
            udp_conversions: Mutex::new(udp_conversions),
            tun_conversions: Mutex::new(tun_conversions),
            states,
            free_slots: Mutex::new((0..MAX_CONNECTIONS).rev().collect()),
            tun: tun.to_string(),
            tun_ifindex,
            nic_programs,
            filters: Mutex::new(HashMap::new()),
            ipv4_unavailable: None,
            records: Mutex::new(Some(records)),
            fec_connections: Mutex::new(HashMap::new()),
            next_fec_id: AtomicU32::new(1),
            _ebpf: ebpf,
        };
        // On failure, dropping `offload` removes the filters attached so far
        offload.attach(udp_to_tcp, tun_ingress)?;
        offload.prepare_nics(remote);

        offload.ipv4_unavailable = enable_ipv4_delivery().err();
        if let Some(ref e) = offload.ipv4_unavailable {
            warn!("eBPF data path only available for IPv6: {e}");
        }
        Ok(offload)
    }

    fn filter_name(&self) -> String {
        format!("{FILTER_NAME_PREFIX}{}", self.tun)
    }

    fn attach(&self, udp_to_tcp: i32, tun_ingress: i32) -> Result<(), String> {
        let mut nl = Netlink::new().map_err(|e| format!("netlink: {e}"))?;
        let name = self.filter_name();
        let tun_ifindex = self.tun_ifindex;

        for ifindex in [tun_ifindex, LOOPBACK_IFINDEX] {
            nl.add_clsact(ifindex)
                .map_err(|e| format!("unable to add a clsact qdisc: {e}"))?;
        }
        remove_stale_filters(&mut nl, LOOPBACK_IFINDEX);

        let filter = |ifindex, direction, priority, handle| FilterId {
            ifindex,
            direction,
            priority,
            handle,
        };
        let redirect = self.nic_programs.redirect;
        let filters = [
            (
                filter(tun_ifindex, Direction::Ingress, 1, 1),
                tun_ingress,
                None,
            ),
            (
                filter(
                    LOOPBACK_IFINDEX,
                    Direction::Ingress,
                    CONVERT_PRIORITY,
                    tun_ifindex,
                ),
                udp_to_tcp,
                Some(netlink::TCA_CSUM_UPDATE_FLAG_IPV4HDR | netlink::TCA_CSUM_UPDATE_FLAG_TCP),
            ),
            (
                filter(
                    LOOPBACK_IFINDEX,
                    Direction::Ingress,
                    REDIRECT_PRIORITY,
                    tun_ifindex,
                ),
                redirect,
                None,
            ),
        ];
        for (id, fd, csum_flags) in filters {
            nl.add_bpf_filter(id, fd, &name, csum_flags)
                .map_err(|e| format!("unable to attach a tc filter: {e}"))?;
            if id.ifindex == LOOPBACK_IFINDEX {
                self.filters
                    .lock()
                    .unwrap()
                    .entry(id.ifindex)
                    .or_default()
                    .push(id);
            }
        }
        Ok(())
    }

    /// Adds a clsact qdisc to the network interfaces that connections are likely to use: those of
    /// the default routes, and the one to `remote`. Adding a qdisc drops the packets queued on
    /// the interface, so doing it once the first connection uses the interface would usually drop
    /// the end of its handshake. The programs are only attached then.
    fn prepare_nics(&self, remote: Option<(IpAddr, IpAddr)>) {
        let Ok(mut nl) = Netlink::new() else {
            return;
        };
        let mut interfaces = nl.default_route_interfaces().unwrap_or_else(|e| {
            debug!("Unable to look up the default routes: {e}");
            Vec::new()
        });
        if let Some((local, remote)) = remote
            && let Ok(ifindex) = nl.forward_interface(local, remote, self.tun_ifindex)
        {
            interfaces.push(ifindex);
        }
        interfaces.sort_unstable();
        interfaces.dedup();
        for ifindex in interfaces {
            if ifindex == self.tun_ifindex || ifindex == LOOPBACK_IFINDEX {
                continue;
            }
            let supported = nl.link(ifindex).is_ok_and(|(t, _)| {
                [ARPHRD_ETHER, ARPHRD_NONE, ARPHRD_PPP, ARPHRD_RAWIP].contains(&t)
            });
            if supported && let Err(e) = nl.add_clsact(ifindex) {
                debug!("Unable to add a clsact qdisc to interface {ifindex}: {e}");
            }
        }
    }

    /// Attaches the programs to the network interface `ifindex`, unless they are already
    fn attach_nic(&self, nl: &mut Netlink, ifindex: u32, eth: bool) -> Result<(), String> {
        let programs = &self.nic_programs;
        let mut filters = self.filters.lock().unwrap();
        if filters.contains_key(&ifindex) {
            return Ok(());
        }

        nl.add_clsact(ifindex)
            .map_err(|e| format!("unable to add a clsact qdisc: {e}"))?;
        remove_stale_filters(nl, ifindex);

        let name = self.filter_name();
        let filter = |priority| FilterId {
            ifindex,
            direction: Direction::Ingress,
            priority,
            handle: self.tun_ifindex,
        };
        let mut attached = Vec::new();
        for (id, fd, csum_flags) in [
            (
                filter(CONVERT_PRIORITY),
                if eth {
                    programs.ingress_eth
                } else {
                    programs.ingress_l3
                },
                Some(
                    netlink::TCA_CSUM_UPDATE_FLAG_IPV4HDR
                        | netlink::TCA_CSUM_UPDATE_FLAG_TCP
                        | netlink::TCA_CSUM_UPDATE_FLAG_UDP,
                ),
            ),
            (filter(REDIRECT_PRIORITY), programs.redirect, None),
        ] {
            if let Err(e) = nl.add_bpf_filter(id, fd, &name, csum_flags) {
                for id in attached {
                    let _ = nl.del_filter(id);
                }
                return Err(format!("unable to attach a tc filter: {e}"));
            }
            attached.push(id);
        }
        filters.insert(ifindex, attached);
        Ok(())
    }

    /// Removes the filters from the loopback and network interfaces, after which nothing is
    /// converted any more. Phantun calls this before it exits, as the filters stay otherwise.
    pub fn detach(&self) {
        let filters: Vec<_> = self
            .filters
            .lock()
            .unwrap()
            .drain()
            .flat_map(|(_, f)| f)
            .collect();
        if filters.is_empty() {
            return;
        }
        let mut nl = match Netlink::new() {
            Ok(nl) => nl,
            Err(e) => {
                warn!("Unable to remove the eBPF filters: {e}");
                return;
            }
        };
        for id in filters {
            match nl.del_filter(id) {
                Ok(()) => {}
                // The interface is gone, and its filters with it
                Err(e) if e.raw_os_error() == Some(libc::ENODEV) => {}
                Err(e) => warn!("Unable to remove eBPF filter {id:?}: {e}"),
            }
        }
    }

    /// The network interface that the kernel forwards the packets from `local` to `remote` on the
    /// Tun interface to, if the programs support it: its index, name, and whether it has an
    /// Ethernet header
    fn nic(
        &self,
        nl: &mut Netlink,
        local: IpAddr,
        remote: IpAddr,
    ) -> Result<(u32, String, bool), String> {
        let ifindex = nl
            .forward_interface(local, remote, self.tun_ifindex)
            .map_err(|e| format!("no route to {remote} from the Tun interface: {e}"))?;
        if ifindex == self.tun_ifindex || ifindex == LOOPBACK_IFINDEX {
            return Err(format!("{remote} is routed to the host itself"));
        }
        let (link_type, name) = nl
            .link(ifindex)
            .map_err(|e| format!("unable to look up interface {ifindex}: {e}"))?;
        let eth = match link_type {
            ARPHRD_ETHER => true,
            ARPHRD_NONE | ARPHRD_PPP | ARPHRD_RAWIP => false,
            t => return Err(format!("{name} is of an unsupported type ({t})")),
        };
        Ok((ifindex, name, eth))
    }

    /// The network interface of the fake TCP connection from `local` to `remote` on the Tun
    /// interface, with the programs attached, and its addresses there, which NAT may have changed
    fn nic_path(&self, local: SocketAddr, remote: SocketAddr) -> Result<NicPath, String> {
        let mut nl = Netlink::new().map_err(|e| format!("netlink: {e}"))?;
        let (ifindex, name, eth) = self.nic(&mut nl, local.ip(), remote.ip())?;

        let (wire_local, wire_remote) = Netlink::conntrack()
            .and_then(|mut ct| ct.conntrack_wire_addresses(local, remote))
            .map_err(|e| format!("unable to look up the connection in conntrack: {e}"))?
            // Not tracked, so not NATed either
            .unwrap_or((local, remote));
        if wire_local.is_ipv4() != local.is_ipv4() || wire_remote.is_ipv4() != remote.is_ipv4() {
            return Err("NAT changes its IP version".to_string());
        }

        self.attach_nic(&mut nl, ifindex, eth)?;
        Ok(NicPath {
            ifindex,
            name,
            local: wire_local,
            remote: wire_remote,
        })
    }

    /// Whether the datagrams of `udp_peer` can be delivered by the programs
    fn check_udp_peer(&self, udp_peer: SocketAddr) -> Result<(), String> {
        if let IpAddr::V6(ip) = udp_peer.ip()
            && ip.is_unicast_link_local()
        {
            return Err(format!("UDP peer {udp_peer} has a link-local address"));
        }
        if !is_local(udp_peer.ip()) {
            return Err(format!("UDP peer {udp_peer} is not on this host"));
        }
        if let (true, Some(e)) = (udp_peer.is_ipv4(), &self.ipv4_unavailable) {
            return Err(e.clone());
        }
        Ok(())
    }

    /// Whether a connection from `tcp_local` to `tcp_remote` on the Tun interface for `udp_peer`
    /// is likely to be converted, before it exists. Whether NAT allows it is only known once it
    /// does, see [`Offload::register`].
    pub fn may_convert(
        &self,
        udp_peer: SocketAddr,
        tcp_local: IpAddr,
        tcp_remote: IpAddr,
    ) -> Result<(), String> {
        self.check_udp_peer(canonical(udp_peer))?;
        let mut nl = Netlink::new().map_err(|e| format!("netlink: {e}"))?;
        self.nic(&mut nl, tcp_local.to_canonical(), tcp_remote.to_canonical())
            .map(|_| ())
    }

    pub fn register(
        self: &Arc<Self>,
        sock: &mut Socket,
        udp_local: SocketAddr,
        udp_peer: SocketAddr,
    ) -> Result<Arc<Connection>, String> {
        let (udp_local, udp_peer) = (canonical(udp_local), canonical(udp_peer));
        let (tcp_local, tcp_remote) = (canonical(sock.local_addr()), canonical(sock.remote_addr()));
        self.check_udp_peer(udp_peer)?;

        let mismatch = || format!("{udp_local} and {udp_peer} are of different IP versions");
        // fake TCP packets from the remote end, and datagrams from the UDP peer
        let tcp_key = Tuple::new(tcp_remote, tcp_local).ok_or_else(mismatch)?;
        let udp_key = Tuple::new(udp_peer, udp_local).ok_or_else(mismatch)?;
        let to_udp = Tuple::new(udp_local, udp_peer).ok_or_else(mismatch)?;
        let to_tcp = Tuple::new(tcp_local, tcp_remote).ok_or_else(mismatch)?;

        let path = self.nic_path(tcp_local, tcp_remote)?;

        let slot = self
            .free_slots
            .lock()
            .unwrap()
            .pop()
            .ok_or("too many connections")?;
        let state = self.states.get(slot);
        unsafe {
            std::ptr::write_volatile(state.tx.get(), 0);
            std::ptr::write_volatile(state.rx.get(), 0);
            std::ptr::write_volatile(state.fec_full.get(), 0);
        }

        let conversion = |out, ifindex| Conversion {
            out,
            tun: tcp_key,
            slot,
            ifindex,
            ..Default::default()
        };
        // Both are of the same IP version as on the Tun interface
        let wire_key = Tuple::new(path.remote, path.local).unwrap();
        let wire_out = Tuple::new(path.local, path.remote).unwrap();
        let mut entries = vec![
            (Table::Tcp, wire_key, conversion(to_udp, self.tun_ifindex)),
            (Table::Udp, udp_key, conversion(wire_out, path.ifindex)),
            (Table::Tun, to_tcp, conversion(wire_out, path.ifindex)),
        ];

        // The other end may send merged packets, which only user space can take, and all of them
        // have to take the same path to stay in order
        if sock.merges() {
            for (table, _, conversion) in &mut entries {
                if *table == Table::Tcp {
                    conversion.flags |= CONV_USER_RX;
                }
            }
        }

        let conn = Arc::new(Connection {
            offload: self.clone(),
            slot,
            entries,
            nic: path.name,
            fec_id: Mutex::new(None),
            name: sock.to_string(),
        });
        sock.share_numbers(conn.clone());

        Ok(conn)
    }

    fn table(&self, table: Table) -> &Mutex<BpfHashMap<MapData, Tuple, Conversion>> {
        match table {
            Table::Tcp => &self.tcp_conversions,
            Table::Udp => &self.udp_conversions,
            Table::Tun => &self.tun_conversions,
        }
    }

    /// Starts the task passing the FEC records of the eBPF programs to the connections
    pub fn start_records(self: &Arc<Self>) {
        let Some(records) = self.records.lock().unwrap().take() else {
            return;
        };
        let records = match AsyncFd::new(records) {
            Ok(records) => records,
            Err(e) => {
                error!("Unable to read the FEC records of the eBPF programs: {e}");
                return;
            }
        };
        tokio::spawn(read_records(Arc::downgrade(self), records));
    }
}

impl Drop for Offload {
    fn drop(&mut self) {
        self.detach();
    }
}

/// The network interface of a connection, see [`Offload::nic_path`]
struct NicPath {
    ifindex: u32,
    name: String,
    local: SocketAddr,
    remote: SocketAddr,
}

/// The eBPF maps of conversions
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Table {
    Tcp,
    Udp,
    Tun,
}

/// The converted datagrams enter the loopback interface without a route, so the kernel looks one
/// up as if they came from another host. For IPv4 it then drops packets with loopback addresses,
/// unless `route_localnet` is set, and with local source addresses, unless `accept_local` is set.
/// They only affect packets arriving on the loopback interface that way, as packets sent to it by
/// the kernel already have their route.
fn enable_ipv4_delivery() -> Result<(), String> {
    for name in ["route_localnet", "accept_local"] {
        let path = format!("/proc/sys/net/ipv4/conf/lo/{name}");
        let enabled = || std::fs::read_to_string(&path).is_ok_and(|v| v.trim() == "1");
        if enabled() {
            continue;
        }
        // Writing may "succeed" without effect, so read it back
        let result = std::fs::write(&path, "1");
        if !enabled() {
            let reason = result
                .err()
                .map_or("unchanged".to_string(), |e| e.to_string());
            return Err(format!(
                "unable to set net.ipv4.conf.lo.{name} to 1 ({reason})"
            ));
        }
        info!("Set net.ipv4.conf.lo.{name} to 1 for the eBPF data path");
    }
    Ok(())
}

/// Removes the filters that Phantun instances which are gone left on the interface `ifindex`,
/// which happens when they are killed
fn remove_stale_filters(nl: &mut Netlink, ifindex: u32) {
    let filters = match nl.bpf_filters(ifindex, Direction::Ingress) {
        Ok(filters) => filters,
        Err(e) => {
            warn!("Unable to list the tc filters of interface {ifindex}: {e}");
            return;
        }
    };
    for f in filters {
        let Some(tun) = f.name.strip_prefix(FILTER_NAME_PREFIX) else {
            continue;
        };
        if ![CONVERT_PRIORITY, REDIRECT_PRIORITY].contains(&f.id.priority)
            || if_index(tun) == Some(f.id.handle)
        {
            continue;
        }
        match nl.del_filter(f.id) {
            Ok(()) => info!("Removed the eBPF filter of a former instance on {tun}"),
            Err(e) => warn!("Unable to remove the stale eBPF filter {:?}: {e}", f.id),
        }
    }
}

/// A connection whose packets are converted by eBPF once started, until this is dropped
pub struct Connection {
    offload: Arc<Offload>,
    slot: u32,
    /// What to insert into the maps when it starts
    entries: Vec<(Table, Tuple, Conversion)>,
    /// The name of the network interface its packets are converted on
    nic: String,
    /// The ID of its FEC records, if it uses FEC
    fec_id: Mutex<Option<u32>>,
    name: String,
}

/// What the FEC records of a connection are passed to
struct FecConnection {
    fec: Arc<Fec>,
    /// Sends the parity shards, and is dropped with the connection
    sock: Weak<Socket>,
    /// Sends the recovered datagrams
    udp_sock: Arc<tokio::net::UdpSocket>,
}

/// The FEC group and index claims of a connection, shared with the eBPF programs
#[cfg(target_has_atomic = "64")]
struct Claims {
    offload: Arc<Offload>,
    slot: u32,
}

#[cfg(target_has_atomic = "64")]
impl crate::fec::SharedClaims for Claims {
    fn claims(&self) -> &std::sync::atomic::AtomicU64 {
        &self.offload.states.get(self.slot).fec_claims
    }
}

impl Connection {
    /// Starts converting the packets of `sock`. With FEC, the eBPF programs convert data shards,
    /// and Phantun computes parity shards and recovers lost data shards from the records they
    /// pass, sending recovered datagrams with `udp_sock`.
    pub fn start(
        &self,
        sock: &Arc<Socket>,
        fec: Option<(&Arc<Fec>, Arc<tokio::net::UdpSocket>)>,
    ) -> Result<(), String> {
        let mut entries = self.entries.clone();
        if let Some((fec, udp_sock)) = fec {
            let id = self.start_fec(sock, fec, udp_sock)?;
            for (table, _, c) in &mut entries {
                if *table != Table::Tun {
                    c.fec_id = id;
                    c.fec_data_shards = fec.data_shards() as u32;
                }
            }
        }

        for (table, key, conversion) in entries {
            self.offload
                .table(table)
                .lock()
                .unwrap()
                .insert(key, conversion, 0)
                .map_err(|e| format!("unable to register the connection: {e}"))?;
        }
        Ok(())
    }

    /// The name of the network interface its packets are converted on
    pub fn nic(&self) -> &str {
        &self.nic
    }

    /// Shares the FEC claims with the eBPF programs and has the records of the connection passed
    /// to `fec`. Returns the ID of the records.
    #[cfg(target_has_atomic = "64")]
    fn start_fec(
        &self,
        sock: &Arc<Socket>,
        fec: &Arc<Fec>,
        udp_sock: Arc<tokio::net::UdpSocket>,
    ) -> Result<u32, String> {
        let offload = &self.offload;
        let id = offload
            .next_fec_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .max(1);
        fec.share_claims(Arc::new(Claims {
            offload: offload.clone(),
            slot: self.slot,
        }));
        offload.fec_connections.lock().unwrap().insert(
            id,
            Arc::new(FecConnection {
                fec: fec.clone(),
                sock: Arc::downgrade(sock),
                udp_sock,
            }),
        );
        *self.fec_id.lock().unwrap() = Some(id);
        Ok(id)
    }

    #[cfg(not(target_has_atomic = "64"))]
    fn start_fec(
        &self,
        _sock: &Arc<Socket>,
        _fec: &Arc<Fec>,
        _udp_sock: Arc<tokio::net::UdpSocket>,
    ) -> Result<u32, String> {
        Err("FEC needs 64-bit atomics, which this platform lacks".to_string())
    }

    fn state(&self) -> &State {
        self.offload.states.get(self.slot)
    }

    /// The number of datagrams and fake TCP packets converted
    fn counters(&self) -> (u64, u64) {
        let state = self.state();
        unsafe {
            (
                std::ptr::read_volatile(state.tx.get()),
                std::ptr::read_volatile(state.rx.get()),
            )
        }
    }

    /// The number of packets left to Phantun so far, as the ring buffer for FEC records was full
    pub fn fec_full(&self) -> u64 {
        unsafe { std::ptr::read_volatile(self.state().fec_full.get()) }
    }

    /// The number of packets converted so far
    pub fn packets(&self) -> u64 {
        let (tx, rx) = self.counters();
        tx.wrapping_add(rx)
    }
}

impl SharedNumbers for Connection {
    fn numbers(&self) -> &Numbers {
        &self.state().numbers
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        for (table, key, _) in &self.entries {
            let _ = self.offload.table(*table).lock().unwrap().remove(key);
        }
        if let Some(id) = *self.fec_id.lock().unwrap() {
            self.offload.fec_connections.lock().unwrap().remove(&id);
        }
        let (tx, rx) = self.counters();
        info!(
            "eBPF converted {tx} datagrams to fake TCP and {rx} fake TCP packets to datagrams for {}",
            self.name
        );
        self.offload.free_slots.lock().unwrap().push(self.slot);
    }
}

/// A FEC frame passed by the eBPF programs
struct Record<'a> {
    fec_id: u32,
    kind: u32,
    group: u32,
    index: u16,
    data: &'a [u8],
}

impl Record<'_> {
    fn parse(buf: &[u8]) -> Option<Record<'_>> {
        let header = buf.get(..RECORD_HEADER_LEN)?;
        let u32_at = |i: usize| u32::from_ne_bytes(header[i..i + 4].try_into().unwrap());
        let len = u16::from_ne_bytes([header[14], header[15]]) as usize;
        Some(Record {
            fec_id: u32_at(0),
            kind: u32_at(4),
            group: u32_at(8),
            index: u16::from_ne_bytes([header[12], header[13]]),
            data: buf.get(RECORD_HEADER_LEN..RECORD_HEADER_LEN + len)?,
        })
    }
}

/// What has to be sent after the records have been processed
enum Output {
    /// A parity shard to the peer
    Parity(Arc<FecConnection>, Vec<u8>),
    /// A recovered datagram to the UDP peer
    Recovered(Arc<FecConnection>, Vec<u8>),
}

/// Passes the FEC records of the eBPF programs to their connections until `offload` is gone
async fn read_records(offload: Weak<Offload>, mut records: AsyncFd<RingBuf<MapData>>) {
    let mut outputs = Vec::new();
    loop {
        let mut guard = match records.readable_mut().await {
            Ok(guard) => guard,
            Err(e) => {
                error!("Unable to read the FEC records of the eBPF programs: {e}");
                return;
            }
        };
        {
            let Some(offload) = offload.upgrade() else {
                return;
            };
            let connections = offload.fec_connections.lock().unwrap();
            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                let Some(r) = Record::parse(&item) else {
                    continue;
                };
                // the connection may be gone already
                let Some(conn) = connections.get(&r.fec_id) else {
                    continue;
                };
                let fec = &conn.fec;
                match r.kind {
                    RECORD_SENT_DATA => outputs.extend(
                        fec.sent_elsewhere(r.group, r.index as u8, r.data)
                            .into_iter()
                            .map(|p| Output::Parity(conn.clone(), p)),
                    ),
                    RECORD_RECEIVED_DATA => outputs.extend(
                        fec.received_elsewhere(r.group, r.index as u8, r.data)
                            .into_iter()
                            .map(|d| Output::Recovered(conn.clone(), d)),
                    ),
                    RECORD_RECEIVED_PARITY => outputs.extend(
                        fec.parity_received_elsewhere(r.data)
                            .into_iter()
                            .map(|d| Output::Recovered(conn.clone(), d)),
                    ),
                    _ => {}
                }
            }
        }
        guard.clear_ready();

        for output in outputs.drain(..) {
            match output {
                Output::Parity(conn, parity) => {
                    if let Some(sock) = conn.sock.upgrade() {
                        // a failure closes the connection elsewhere
                        let _ = sock.send(&parity).await;
                    }
                }
                Output::Recovered(conn, datagram) => {
                    if let Err(e) = conn.udp_sock.send(&datagram).await {
                        debug!("Unable to send a recovered datagram: {e}");
                    }
                }
            }
        }
    }
}
