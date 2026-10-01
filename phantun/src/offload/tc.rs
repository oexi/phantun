//! Just enough rtnetlink to attach the eBPF programs with tc. aya can only attach direct action
//! classifiers, but the converting classifiers need a csum action.

use std::io;
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
    pub fn new() -> io::Result<Netlink> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
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
