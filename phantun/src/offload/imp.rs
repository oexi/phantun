use super::tc::{self, Direction, FilterId, LOOPBACK_IFINDEX, Netlink};
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

/// struct conversion
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Conversion {
    out: Tuple,
    slot: u32,
    fec_id: u32,
    fec_data_shards: u32,
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
    // Written by the eBPF programs without atomics
    tx: UnsafeCell<u64>,
    rx: UnsafeCell<u64>,
    fec_claims: FecClaims,
    _pad2: [u64; 3],
}

/// The header of struct record, followed by the data
const RECORD_HEADER_LEN: usize = 16;
const RECORD_SENT_DATA: u32 = 0;
const RECORD_RECEIVED_DATA: u32 = 1;
const RECORD_RECEIVED_PARITY: u32 = 2;
/// The size of the ring buffer for records, when FEC is enabled. Each record takes about 1.5 KiB.
const RECORDS_SIZE: u32 = 8 * 1024 * 1024;

const _: () = assert!(size_of::<Tuple>() == 40);
const _: () = assert!(size_of::<Conversion>() == 56);
const _: () = assert!(size_of::<State>() == 64);

unsafe impl Pod for Tuple {}
unsafe impl Pod for Conversion {}

// The priorities of the filters on the loopback interface, where filters of other programs and
// other instances of Phantun may be as well. The instances share these priorities, their filters
// are told apart by the handle, which is the index of their Tun interface.
const LO_CONVERT_PRIORITY: u16 = 0x7068;
const LO_REDIRECT_PRIORITY: u16 = 0x7069;
const FILTER_NAME_PREFIX: &str = "phantun:";

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

pub struct Offload {
    tcp_conversions: Mutex<BpfHashMap<MapData, Tuple, Conversion>>,
    udp_conversions: Mutex<BpfHashMap<MapData, Tuple, Conversion>>,
    states: States,
    free_slots: Mutex<Vec<u32>>,
    /// The filters on the loopback interface, the ones on the Tun interface go with it
    lo_filters: Mutex<Vec<FilterId>>,
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
    /// passed to Phantun, otherwise the buffer for them is kept small.
    pub fn new(tun: &str, fec: bool) -> Result<Offload, String> {
        let tun_ifindex = if_index(tun).ok_or_else(|| format!("no interface {tun}"))?;
        // a power of two and a multiple of the page size
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u32;
        let records_size = if fec {
            RECORDS_SIZE.max(page_size)
        } else {
            page_size
        };

        let mut ebpf = EbpfLoader::new()
            .override_global("tun_ifindex", &tun_ifindex, true)
            .map_max_entries("records", records_size)
            .load(OBJECT)
            .map_err(|e| format!("unable to load the eBPF programs: {e}"))?;

        let mut fds = Vec::new();
        for name in ["tcp_to_udp", "udp_to_tcp", "redirect"] {
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
            fds.push(prog.fd().unwrap().as_fd().as_raw_fd());
        }
        let [tcp_to_udp, udp_to_tcp, redirect] = fds[..] else {
            unreachable!()
        };

        let take_hash_map = |ebpf: &mut Ebpf, name| {
            BpfHashMap::try_from(ebpf.take_map(name).unwrap()).map_err(|e| format!("{name}: {e}"))
        };
        let tcp_conversions = take_hash_map(&mut ebpf, "tcp_conversions")?;
        let udp_conversions = take_hash_map(&mut ebpf, "udp_conversions")?;
        let states = match ebpf.take_map("states").unwrap() {
            aya::maps::Map::Array(map) => States::new(map)?,
            _ => unreachable!(),
        };
        let records = RingBuf::try_from(ebpf.take_map("records").unwrap())
            .map_err(|e| format!("records: {e}"))?;

        let mut offload = Offload {
            tcp_conversions: Mutex::new(tcp_conversions),
            udp_conversions: Mutex::new(udp_conversions),
            states,
            free_slots: Mutex::new((0..MAX_CONNECTIONS).rev().collect()),
            lo_filters: Mutex::new(Vec::new()),
            ipv4_unavailable: None,
            records: Mutex::new(Some(records)),
            fec_connections: Mutex::new(HashMap::new()),
            next_fec_id: AtomicU32::new(1),
            _ebpf: ebpf,
        };
        // On failure, dropping `offload` removes the filters attached so far
        offload.attach(tun, tun_ifindex, tcp_to_udp, udp_to_tcp, redirect)?;

        offload.ipv4_unavailable = enable_ipv4_delivery().err();
        if let Some(ref e) = offload.ipv4_unavailable {
            warn!("eBPF data path only available for IPv6: {e}");
        }
        Ok(offload)
    }

    fn attach(
        &self,
        tun: &str,
        tun_ifindex: u32,
        tcp_to_udp: i32,
        udp_to_tcp: i32,
        redirect: i32,
    ) -> Result<(), String> {
        let mut nl = Netlink::new().map_err(|e| format!("netlink: {e}"))?;
        let name = format!("{FILTER_NAME_PREFIX}{tun}");

        for ifindex in [tun_ifindex, LOOPBACK_IFINDEX] {
            nl.add_clsact(ifindex)
                .map_err(|e| format!("unable to add a clsact qdisc: {e}"))?;
        }
        remove_stale_filters(&mut nl);

        let filter = |ifindex, direction, priority, handle| FilterId {
            ifindex,
            direction,
            priority,
            handle,
        };
        let filters = [
            (
                filter(tun_ifindex, Direction::Egress, 1, 1),
                tcp_to_udp,
                Some(tc::TCA_CSUM_UPDATE_FLAG_IPV4HDR | tc::TCA_CSUM_UPDATE_FLAG_UDP),
            ),
            (filter(tun_ifindex, Direction::Egress, 2, 1), redirect, None),
            (
                filter(
                    LOOPBACK_IFINDEX,
                    Direction::Ingress,
                    LO_CONVERT_PRIORITY,
                    tun_ifindex,
                ),
                udp_to_tcp,
                Some(tc::TCA_CSUM_UPDATE_FLAG_IPV4HDR | tc::TCA_CSUM_UPDATE_FLAG_TCP),
            ),
            (
                filter(
                    LOOPBACK_IFINDEX,
                    Direction::Ingress,
                    LO_REDIRECT_PRIORITY,
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
                self.lo_filters.lock().unwrap().push(id);
            }
        }
        Ok(())
    }

    /// Removes the filters from the loopback interface, after which nothing is converted any
    /// more. Phantun calls this before it exits, as the filters stay otherwise.
    pub fn detach(&self) {
        let filters: Vec<_> = self.lo_filters.lock().unwrap().drain(..).collect();
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
            if let Err(e) = nl.del_filter(id) {
                warn!("Unable to remove eBPF filter {id:?}: {e}");
            }
        }
    }

    pub fn register(
        self: &Arc<Self>,
        sock: &mut Socket,
        udp_local: SocketAddr,
        udp_peer: SocketAddr,
    ) -> Result<Arc<Connection>, String> {
        let (udp_local, udp_peer) = (canonical(udp_local), canonical(udp_peer));
        let (tcp_local, tcp_remote) = (canonical(sock.local_addr()), canonical(sock.remote_addr()));

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

        let mismatch = || format!("{udp_local} and {udp_peer} are of different IP versions");
        // fake TCP packets from the remote end, and datagrams from the UDP peer
        let tcp_key = Tuple::new(tcp_remote, tcp_local).ok_or_else(mismatch)?;
        let udp_key = Tuple::new(udp_peer, udp_local).ok_or_else(mismatch)?;
        let tcp_conversion = Conversion {
            out: Tuple::new(udp_local, udp_peer).ok_or_else(mismatch)?,
            ..Default::default()
        };
        let udp_conversion = Conversion {
            out: Tuple::new(tcp_local, tcp_remote).ok_or_else(mismatch)?,
            ..Default::default()
        };

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
        }

        let conn = Arc::new(Connection {
            offload: self.clone(),
            slot,
            tcp_key,
            udp_key,
            tcp_conversion: Conversion {
                slot,
                ..tcp_conversion
            },
            udp_conversion: Conversion {
                slot,
                ..udp_conversion
            },
            fec_id: Mutex::new(None),
            name: sock.to_string(),
        });
        sock.share_numbers(conn.clone());

        Ok(conn)
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

/// Removes the filters of Phantun instances that are gone, which happens when they are killed
fn remove_stale_filters(nl: &mut Netlink) {
    let filters = match nl.bpf_filters(LOOPBACK_IFINDEX, Direction::Ingress) {
        Ok(filters) => filters,
        Err(e) => {
            warn!("Unable to list the tc filters of the loopback interface: {e}");
            return;
        }
    };
    for f in filters {
        let Some(tun) = f.name.strip_prefix(FILTER_NAME_PREFIX) else {
            continue;
        };
        if ![LO_CONVERT_PRIORITY, LO_REDIRECT_PRIORITY].contains(&f.id.priority)
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
    tcp_key: Tuple,
    udp_key: Tuple,
    tcp_conversion: Conversion,
    udp_conversion: Conversion,
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
        let (mut tcp_conversion, mut udp_conversion) = (self.tcp_conversion, self.udp_conversion);
        if let Some((fec, udp_sock)) = fec {
            let id = self.start_fec(sock, fec, udp_sock)?;
            for c in [&mut tcp_conversion, &mut udp_conversion] {
                c.fec_id = id;
                c.fec_data_shards = fec.data_shards() as u32;
            }
        }

        let offload = &self.offload;
        offload
            .tcp_conversions
            .lock()
            .unwrap()
            .insert(self.tcp_key, tcp_conversion, 0)
            .and_then(|_| {
                offload
                    .udp_conversions
                    .lock()
                    .unwrap()
                    .insert(self.udp_key, udp_conversion, 0)
            })
            .map_err(|e| format!("unable to register the connection: {e}"))
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
        let _ = self
            .offload
            .tcp_conversions
            .lock()
            .unwrap()
            .remove(&self.tcp_key);
        let _ = self
            .offload
            .udp_conversions
            .lock()
            .unwrap()
            .remove(&self.udp_key);
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
