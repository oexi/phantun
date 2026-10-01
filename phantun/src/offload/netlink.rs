//! Just enough netlink for the eBPF data path: tc, to attach the programs, as aya can only attach
//! direct action classifiers, but the converting classifiers need a csum action; routes and links,
//! to find the network interface of a connection; and conntrack, to find its addresses after NAT.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use nix::libc;

pub const LOOPBACK_IFINDEX: u32 = 1;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_ACK_TLVS: u16 = 0x200;
const NLMSGERR_ATTR_MSG: u16 = 1;
const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;
const SOL_NETLINK: libc::c_int = 270;
const NETLINK_EXT_ACK: libc::c_int = 11;

const RTM_GETLINK: u16 = 18;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWQDISC: u16 = 36;
const RTM_NEWTFILTER: u16 = 44;
const RTM_DELTFILTER: u16 = 45;
const RTM_GETTFILTER: u16 = 46;

const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCA_BPF_ACT: u16 = 1;
const TCA_BPF_FD: u16 = 6;
const TCA_BPF_NAME: u16 = 7;
const TCA_BPF_FLAGS: u16 = 8;
const TCA_BPF_FLAG_ACT_DIRECT: u32 = 1;
const TCA_ACT_KIND: u16 = 1;
const TCA_ACT_OPTIONS: u16 = 2;
const TCA_CSUM_PARMS: u16 = 1;
pub const TCA_CSUM_UPDATE_FLAG_IPV4HDR: u32 = 1;
pub const TCA_CSUM_UPDATE_FLAG_TCP: u32 = 8;
pub const TCA_CSUM_UPDATE_FLAG_UDP: u32 = 16;
const TC_ACT_UNSPEC: i32 = -1;

const IFLA_IFNAME: u16 = 3;
const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_IIF: u16 = 3;
const RTA_OIF: u16 = 4;
const RTA_MULTIPATH: u16 = 9;
const RTN_UNICAST: u8 = 1;

const NETLINK_NETFILTER: libc::c_int = 12;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_GET: u16 = 1;
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;

const TC_H_CLSACT: u32 = 0xffff_fff1;
const ETH_P_ALL: u16 = 0x0003;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Ingress,
    Egress,
}

impl Direction {
    fn parent(self) -> u32 {
        match self {
            Direction::Ingress => 0xffff_fff2,
            Direction::Egress => 0xffff_fff3,
        }
    }
}

/// Identifies a filter
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilterId {
    pub ifindex: u32,
    pub direction: Direction,
    pub priority: u16,
    pub handle: u32,
}

/// A bpf filter found by [`Netlink::bpf_filters`]
pub struct BpfFilter {
    pub id: FilterId,
    pub name: String,
}

struct Message {
    buf: Vec<u8>,
}

impl Message {
    fn new(msg_type: u16, flags: u16) -> Message {
        let mut buf = vec![0; 16];
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        Message { buf }
    }

    /// Appends the fixed header that follows the netlink header
    fn header(mut self, header: &[u8]) -> Message {
        self.buf.extend_from_slice(header);
        self
    }

    fn tcmsg(mut self, ifindex: u32, handle: u32, parent: u32, info: u32) -> Message {
        // family, padding
        self.buf.extend_from_slice(&[0; 4]);
        self.buf.extend_from_slice(&ifindex.to_ne_bytes());
        self.buf.extend_from_slice(&handle.to_ne_bytes());
        self.buf.extend_from_slice(&parent.to_ne_bytes());
        self.buf.extend_from_slice(&info.to_ne_bytes());
        self
    }

    fn align(&mut self) {
        self.buf.resize(self.buf.len().next_multiple_of(4), 0);
    }

    fn attr(&mut self, attr_type: u16, data: &[u8]) {
        self.align();
        self.buf
            .extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        self.buf.extend_from_slice(&attr_type.to_ne_bytes());
        self.buf.extend_from_slice(data);
    }

    fn attr_str(&mut self, attr_type: u16, s: &str) {
        let mut data = s.as_bytes().to_vec();
        data.push(0);
        self.attr(attr_type, &data);
    }

    fn nest<F: FnOnce(&mut Message)>(&mut self, attr_type: u16, f: F) {
        self.align();
        let start = self.buf.len();
        self.attr(attr_type | NLA_F_NESTED, &[]);
        f(self);
        self.align();
        let len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
    }

    fn finish(mut self, seq: u32) -> Vec<u8> {
        self.align();
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        self.buf
    }
}

/// Iterates over the netlink attributes in `buf`, as (type, payload)
fn attrs(mut buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if buf.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let attr_type = u16::from_ne_bytes([buf[2], buf[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > buf.len() {
            return None;
        }
        let payload = &buf[4..len];
        buf = &buf[len.next_multiple_of(4).min(buf.len())..];
        Some((attr_type, payload))
    })
}

fn attr_string(payload: &[u8]) -> String {
    let end = payload
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(payload.len());
    String::from_utf8_lossy(&payload[..end]).into_owned()
}

pub struct Netlink {
    fd: OwnedFd,
    seq: u32,
}

impl Netlink {
    /// A socket for rtnetlink
    pub fn new() -> io::Result<Netlink> {
        Netlink::with_protocol(libc::NETLINK_ROUTE)
    }

    /// A socket for conntrack
    pub fn conntrack() -> io::Result<Netlink> {
        Netlink::with_protocol(NETLINK_NETFILTER)
    }

    fn with_protocol(protocol: libc::c_int) -> io::Result<Netlink> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // Error messages from the kernel, it still works without them
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                SOL_NETLINK,
                NETLINK_EXT_ACK,
                &one as *const _ as *const libc::c_void,
                size_of_val(&one) as libc::socklen_t,
            );
        }
        Ok(Netlink { fd, seq: 0 })
    }

    /// Sends a request and returns the payloads of the messages it gets back, until the ACK of
    /// a request or the end of a dump
    fn request(&mut self, msg: Message) -> io::Result<Vec<Vec<u8>>> {
        self.request_until(msg, |_| false)
    }

    /// Like [`Netlink::request`], but also stops once `done` returns true for the replies so far
    fn request_until(
        &mut self,
        msg: Message,
        done: impl Fn(&[Vec<u8>]) -> bool,
    ) -> io::Result<Vec<Vec<u8>>> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let buf = msg.finish(seq);
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                size_of_val(&addr) as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut replies = Vec::new();
        let mut rbuf = vec![0u8; 64 * 1024];
        loop {
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    rbuf.as_mut_ptr() as *mut libc::c_void,
                    rbuf.len(),
                    0,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let mut data = &rbuf[..n as usize];
            while data.len() >= 16 {
                let len = u32::from_ne_bytes(data[0..4].try_into().unwrap()) as usize;
                if len < 16 || len > data.len() {
                    return Err(io::Error::other("truncated netlink message"));
                }
                let msg_type = u16::from_ne_bytes([data[4], data[5]]);
                let flags = u16::from_ne_bytes([data[6], data[7]]);
                let msg_seq = u32::from_ne_bytes(data[8..12].try_into().unwrap());
                let payload = &data[16..len];
                data = &data[len.next_multiple_of(4).min(data.len())..];

                if msg_seq != seq {
                    continue;
                }
                match msg_type {
                    NLMSG_ERROR => {
                        let errno = i32::from_ne_bytes(payload[0..4].try_into().unwrap());
                        if errno == 0 {
                            return Ok(replies);
                        }
                        let err = io::Error::from_raw_os_error(-errno);
                        return Err(match extack_message(payload, flags) {
                            Some(m) => io::Error::new(err.kind(), format!("{err}: {m}")),
                            None => err,
                        });
                    }
                    NLMSG_DONE => return Ok(replies),
                    _ => replies.push(payload.to_vec()),
                }
            }
            if done(&replies) {
                return Ok(replies);
            }
        }
    }

    /// Adds a clsact qdisc to the interface, unless it already has one
    pub fn add_clsact(&mut self, ifindex: u32) -> io::Result<()> {
        let mut msg = Message::new(
            RTM_NEWQDISC,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        )
        .tcmsg(ifindex, 0xffff_0000, TC_H_CLSACT, 0);
        msg.attr_str(TCA_KIND, "clsact");
        match self.request(msg) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            r => r.map(|_| ()),
        }
    }

    /// Adds a bpf filter running `prog_fd`. Without `csum_flags`, it is a direct action
    /// classifier. With them, it is a classifier whose matches run a csum action updating the
    /// given checksums, which then continues with the next filter.
    pub fn add_bpf_filter(
        &mut self,
        id: FilterId,
        prog_fd: i32,
        name: &str,
        csum_flags: Option<u32>,
    ) -> io::Result<()> {
        let mut msg = Message::new(
            RTM_NEWTFILTER,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        )
        .tcmsg(id.ifindex, id.handle, id.direction.parent(), info(id));
        msg.attr_str(TCA_KIND, "bpf");
        msg.nest(TCA_OPTIONS, |m| {
            m.attr(TCA_BPF_FD, &prog_fd.to_ne_bytes());
            m.attr_str(TCA_BPF_NAME, name);
            match csum_flags {
                None => m.attr(TCA_BPF_FLAGS, &TCA_BPF_FLAG_ACT_DIRECT.to_ne_bytes()),
                Some(update_flags) => m.nest(TCA_BPF_ACT, |m| {
                    // the first action
                    m.nest(1, |m| {
                        m.attr_str(TCA_ACT_KIND, "csum");
                        m.nest(TCA_ACT_OPTIONS, |m| {
                            // struct tc_csum: index, capab, action, refcnt, bindcnt, update_flags
                            let mut parms = Vec::with_capacity(24);
                            parms.extend_from_slice(&0u32.to_ne_bytes());
                            parms.extend_from_slice(&0u32.to_ne_bytes());
                            parms.extend_from_slice(&TC_ACT_UNSPEC.to_ne_bytes());
                            parms.extend_from_slice(&0i32.to_ne_bytes());
                            parms.extend_from_slice(&0i32.to_ne_bytes());
                            parms.extend_from_slice(&update_flags.to_ne_bytes());
                            m.attr(TCA_CSUM_PARMS, &parms);
                        });
                    });
                }),
            }
        });
        self.request(msg).map(|_| ())
    }

    pub fn del_filter(&mut self, id: FilterId) -> io::Result<()> {
        let mut msg = Message::new(RTM_DELTFILTER, NLM_F_REQUEST | NLM_F_ACK).tcmsg(
            id.ifindex,
            id.handle,
            id.direction.parent(),
            info(id),
        );
        msg.attr_str(TCA_KIND, "bpf");
        self.request(msg).map(|_| ())
    }

    /// The bpf filters of an interface
    pub fn bpf_filters(
        &mut self,
        ifindex: u32,
        direction: Direction,
    ) -> io::Result<Vec<BpfFilter>> {
        let msg = Message::new(RTM_GETTFILTER, NLM_F_REQUEST | NLM_F_DUMP).tcmsg(
            ifindex,
            0,
            direction.parent(),
            0,
        );
        let mut filters = Vec::new();
        for reply in self.request(msg)? {
            if reply.len() < 20 {
                continue;
            }
            let handle = u32::from_ne_bytes(reply[8..12].try_into().unwrap());
            let info = u32::from_ne_bytes(reply[16..20].try_into().unwrap());
            let mut kind = String::new();
            let mut name = String::new();
            for (attr_type, payload) in attrs(&reply[20..]) {
                match attr_type {
                    TCA_KIND => kind = attr_string(payload),
                    TCA_OPTIONS => {
                        for (t, p) in attrs(payload) {
                            if t == TCA_BPF_NAME {
                                name = attr_string(p);
                            }
                        }
                    }
                    _ => {}
                }
            }
            // The first message of every priority describes the priority rather than a filter
            if kind == "bpf" && handle != 0 {
                filters.push(BpfFilter {
                    id: FilterId {
                        ifindex,
                        direction,
                        priority: (info >> 16) as u16,
                        handle,
                    },
                    name,
                });
            }
        }
        Ok(filters)
    }
}

impl Netlink {
    /// The interface the kernel forwards a packet from `src` to `dst` to, which arrived on
    /// `iif`, like `ip route get <dst> from <src> iif <iif>`
    pub fn forward_interface(&mut self, src: IpAddr, dst: IpAddr, iif: u32) -> io::Result<u32> {
        let (family, bits) = match dst {
            IpAddr::V4(_) => (libc::AF_INET as u8, 32),
            IpAddr::V6(_) => (libc::AF_INET6 as u8, 128),
        };
        // struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags
        let mut msg = Message::new(RTM_GETROUTE, NLM_F_REQUEST)
            .header(&[family, bits, bits, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        msg.attr(RTA_DST, &ip_octets(dst));
        msg.attr(RTA_SRC, &ip_octets(src));
        msg.attr(RTA_IIF, &iif.to_ne_bytes());
        let replies = self.request_one(msg)?;
        replies
            .iter()
            .filter_map(|r| r.get(12..))
            .flat_map(attrs)
            .find(|(t, p)| *t == RTA_OIF && p.len() == 4)
            .map(|(_, p)| u32::from_ne_bytes(p.try_into().unwrap()))
            .ok_or_else(|| io::Error::other("the route has no output interface"))
    }

    /// The output interfaces of the default routes, of both IP versions
    pub fn default_route_interfaces(&mut self) -> io::Result<Vec<u32>> {
        let mut interfaces = Vec::new();
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            let msg = Message::new(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP)
                .header(&[family, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            for reply in self.request(msg)? {
                // struct rtmsg: dst_len and type
                if reply.len() < 12 || reply[1] != 0 || reply[7] != RTN_UNICAST {
                    continue;
                }
                for (t, p) in attrs(&reply[12..]) {
                    match t {
                        RTA_OIF if p.len() == 4 => {
                            interfaces.push(u32::from_ne_bytes(p.try_into().unwrap()))
                        }
                        // struct rtnexthop: len, flags, hops, ifindex, followed by attributes
                        RTA_MULTIPATH => {
                            let mut rest = p;
                            while rest.len() >= 8 {
                                let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
                                interfaces.push(u32::from_ne_bytes(rest[4..8].try_into().unwrap()));
                                if len < 8 {
                                    break;
                                }
                                rest = &rest[len.next_multiple_of(4).min(rest.len())..];
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        interfaces.sort_unstable();
        interfaces.dedup();
        Ok(interfaces)
    }

    /// The link type (ARPHRD_*) and name of an interface
    pub fn link(&mut self, ifindex: u32) -> io::Result<(u16, String)> {
        // struct ifinfomsg: family, padding, type, index, flags, change
        let mut header = [0u8; 16];
        header[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        let msg = Message::new(RTM_GETLINK, NLM_F_REQUEST).header(&header);
        let replies = self.request_one(msg)?;
        let reply = replies
            .first()
            .filter(|r| r.len() >= 16)
            .ok_or_else(|| io::Error::other("no link"))?;
        let link_type = u16::from_ne_bytes([reply[2], reply[3]]);
        let name = attrs(&reply[16..])
            .find(|(t, _)| *t == IFLA_IFNAME)
            .map_or_else(|| ifindex.to_string(), |(_, p)| attr_string(p));
        Ok((link_type, name))
    }

    /// Sends a request that is answered by a single message rather than an ACK
    fn request_one(&mut self, msg: Message) -> io::Result<Vec<Vec<u8>>> {
        self.request_until(msg, |replies| !replies.is_empty())
    }

    /// The addresses on the wire of the TCP connection from `local` to `remote`, in conntrack,
    /// where NAT may have changed them, as (local, remote). `None` if conntrack does not know
    /// the connection.
    pub fn conntrack_wire_addresses(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> io::Result<Option<(SocketAddr, SocketAddr)>> {
        let family = match local {
            SocketAddr::V4(_) => libc::AF_INET as u8,
            SocketAddr::V6(_) => libc::AF_INET6 as u8,
        };
        // struct nfgenmsg: family, version, resource ID
        let mut msg = Message::new(
            (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET,
            NLM_F_REQUEST | NLM_F_ACK,
        )
        .header(&[family, 0, 0, 0]);
        // Finds the entry whichever direction the tuple is of
        msg.nest(CTA_TUPLE_ORIG, |m| {
            m.nest(CTA_TUPLE_IP, |m| {
                let (src, dst) = match family as i32 {
                    libc::AF_INET => (CTA_IP_V4_SRC, CTA_IP_V4_DST),
                    _ => (CTA_IP_V6_SRC, CTA_IP_V6_DST),
                };
                m.attr(src, &ip_octets(local.ip()));
                m.attr(dst, &ip_octets(remote.ip()));
            });
            m.nest(CTA_TUPLE_PROTO, |m| {
                m.attr(CTA_PROTO_NUM, &[libc::IPPROTO_TCP as u8]);
                m.attr(CTA_PROTO_SRC_PORT, &local.port().to_be_bytes());
                m.attr(CTA_PROTO_DST_PORT, &remote.port().to_be_bytes());
            });
        });
        let replies = match self.request(msg) {
            Ok(replies) => replies,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let reply = replies
            .first()
            .and_then(|r| r.get(4..))
            .ok_or_else(|| io::Error::other("empty conntrack reply"))?;
        let mut tuples = [None, None];
        for (t, payload) in attrs(reply) {
            if t == CTA_TUPLE_ORIG || t == CTA_TUPLE_REPLY {
                tuples[(t - CTA_TUPLE_ORIG) as usize] = parse_ct_tuple(payload);
            }
        }
        let [Some(orig), Some(reply)] = tuples else {
            return Err(io::Error::other("incomplete conntrack entry"));
        };
        // Packets from the other end are of the other direction
        let incoming = if orig == (local, remote) { reply } else { orig };
        Ok(Some((incoming.1, incoming.0)))
    }
}

fn ip_octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

/// A CTA_TUPLE_* as (source, destination)
fn parse_ct_tuple(buf: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    let (mut src, mut dst, mut sport, mut dport) = (None, None, None, None);
    for (t, payload) in attrs(buf) {
        match t {
            CTA_TUPLE_IP => {
                for (t, p) in attrs(payload) {
                    let ip = match p.len() {
                        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(p).unwrap())),
                        16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(p).unwrap())),
                        _ => continue,
                    };
                    match t {
                        CTA_IP_V4_SRC | CTA_IP_V6_SRC => src = Some(ip),
                        CTA_IP_V4_DST | CTA_IP_V6_DST => dst = Some(ip),
                        _ => {}
                    }
                }
            }
            CTA_TUPLE_PROTO => {
                for (t, p) in attrs(payload) {
                    let Ok(port) = <[u8; 2]>::try_from(p) else {
                        continue;
                    };
                    match t {
                        CTA_PROTO_SRC_PORT => sport = Some(u16::from_be_bytes(port)),
                        CTA_PROTO_DST_PORT => dport = Some(u16::from_be_bytes(port)),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Some((SocketAddr::new(src?, sport?), SocketAddr::new(dst?, dport?)))
}

fn info(id: FilterId) -> u32 {
    ((id.priority as u32) << 16) | ETH_P_ALL.to_be() as u32
}

/// The error message in the extended ACK of an NLMSG_ERROR payload
fn extack_message(payload: &[u8], flags: u16) -> Option<String> {
    if flags & NLM_F_ACK_TLVS == 0 || payload.len() < 20 {
        return None;
    }
    // The error code is followed by the request, of which only the header is included when the
    // ACK is capped (0x100), which is the default
    let request_len = if flags & 0x100 != 0 {
        16
    } else {
        u32::from_ne_bytes(payload[4..8].try_into().unwrap()) as usize
    };
    let tlvs = payload.get((4 + request_len).next_multiple_of(4)..)?;
    attrs(tlvs)
        .find(|(t, _)| *t == NLMSGERR_ATTR_MSG)
        .map(|(_, p)| attr_string(p))
}
