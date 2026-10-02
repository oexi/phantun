//! A Tun interface whose packets can pass in batches. With virtio-net headers, a write can hold
//! many TCP segments for the kernel to split (TSO), and a read many segments that the kernel
//! merged (GRO), with their checksums left to the kernel or not checked at all.

use log::warn;
use std::ffi::CStr;
use std::io::{self, IoSlice};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// Length of the virtio-net header (`struct virtio_net_hdr`) in front of every packet read or
/// written with `IFF_VNET_HDR`
pub const VNET_HDR_LEN: usize = 10;

/// The checksum from `csum_start` on is left to the kernel, which takes the checksum field to
/// hold the sum of the pseudo header
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
pub const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

/// A virtio-net header, in the byte order of the host
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct VnetHdr {
    pub flags: u8,
    pub gso_type: u8,
    /// Length of the headers of a segment
    pub hdr_len: u16,
    /// Length of the payload of each segment, but the last, which may be shorter
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VnetHdr {
    pub fn read(buf: &[u8]) -> VnetHdr {
        let u16_at = |i: usize| u16::from_ne_bytes([buf[i], buf[i + 1]]);
        VnetHdr {
            flags: buf[0],
            gso_type: buf[1],
            hdr_len: u16_at(2),
            gso_size: u16_at(4),
            csum_start: u16_at(6),
            csum_offset: u16_at(8),
        }
    }

    pub fn write(&self, buf: &mut [u8]) {
        buf[0] = self.flags;
        buf[1] = self.gso_type;
        buf[2..4].copy_from_slice(&self.hdr_len.to_ne_bytes());
        buf[4..6].copy_from_slice(&self.gso_size.to_ne_bytes());
        buf[6..8].copy_from_slice(&self.csum_start.to_ne_bytes());
        buf[8..10].copy_from_slice(&self.csum_offset.to_ne_bytes());
    }

    /// The length of the TCP payload of each segment if the packet holds several, merged by GRO
    pub fn tcp_segment_len(&self) -> Option<usize> {
        match self.gso_type & !VIRTIO_NET_HDR_GSO_ECN {
            VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_TCPV6 if self.gso_size > 0 => {
                Some(self.gso_size as usize)
            }
            _ => None,
        }
    }
}

/// A queue of a Tun interface
pub struct Tun {
    fd: AsyncFd<OwnedFd>,
    name: String,
    vnet_hdr: bool,
    gro: bool,
}

impl Tun {
    /// Creates the Tun interface `name`, or the next free one if `name` is empty, with `queues`
    /// queues, and sets it up. With `offload`, packets pass with virtio-net headers if the kernel
    /// allows, see [`Tun::vnet_hdr`] and [`Tun::gro`].
    pub fn create(name: &str, queues: usize, offload: bool) -> io::Result<Vec<Tun>> {
        match Tun::create_with(name, queues, offload) {
            Err(e) if offload => {
                warn!(
                    "Unable to create the Tun interface with virtio-net headers, creating it without: {e}"
                );
                Tun::create_with(name, queues, false)
            }
            result => result,
        }
    }

    fn create_with(name: &str, queues: usize, offload: bool) -> io::Result<Vec<Tun>> {
        let mut flags = libc::IFF_TUN | libc::IFF_NO_PI;
        if queues > 1 {
            flags |= libc::IFF_MULTI_QUEUE;
        }
        if offload {
            flags |= libc::IFF_VNET_HDR;
        }

        let mut name = name.to_string();
        let mut fds = Vec::with_capacity(queues);
        for _ in 0..queues.max(1) {
            let fd = unsafe {
                libc::open(
                    c"/dev/net/tun".as_ptr(),
                    libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };

            let mut req = ifreq(&name)?;
            req.ifr_ifru.ifru_flags = flags as libc::c_short;
            if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF as _, &mut req) } < 0 {
                return Err(io::Error::last_os_error());
            }
            name = unsafe { CStr::from_ptr(req.ifr_name.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            fds.push(fd);
        }

        // Lets the kernel pass packets with partial checksums and merged by GRO, which only
        // concerns reading: writes may always have them
        let offloads = libc::TUN_F_CSUM | libc::TUN_F_TSO4 | libc::TUN_F_TSO6;
        let gro = offload
            && unsafe {
                libc::ioctl(
                    fds[0].as_raw_fd(),
                    libc::TUNSETOFFLOAD as _,
                    offloads as libc::c_ulong,
                )
            } == 0;

        set_up(&name)?;

        fds.into_iter()
            .map(|fd| {
                Ok(Tun {
                    fd: AsyncFd::new(fd)?,
                    name: name.clone(),
                    vnet_hdr: offload,
                    gro,
                })
            })
            .collect()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether every packet read or written starts with a virtio-net header, see [`VnetHdr`]
    pub fn vnet_hdr(&self) -> bool {
        self.vnet_hdr
    }

    /// Whether the kernel may pass several TCP segments that it merged as one packet, along with
    /// packets whose checksum it left to compute
    pub fn gro(&self) -> bool {
        self.gro
    }

    /// Reads a packet, with the virtio-net header in front if [`Tun::vnet_hdr`]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.fd
            .async_io(Interest::READABLE, |fd| {
                let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(n as usize)
            })
            .await
    }

    /// Writes `packet`, which has no virtio-net header: one with nothing to offload is added if
    /// needed
    pub async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        let hdr = [0u8; VNET_HDR_LEN];
        let iov = [IoSlice::new(&hdr), IoSlice::new(packet)];
        self.send_vectored(if self.vnet_hdr { &iov } else { &iov[1..] })
            .await
    }

    /// Like [`Tun::send`], but fails rather than waits if the packet cannot be written right away
    pub fn try_send(&self, packet: &[u8]) -> io::Result<usize> {
        let hdr = [0u8; VNET_HDR_LEN];
        let iov = [IoSlice::new(&hdr), IoSlice::new(packet)];
        let iov = if self.vnet_hdr { &iov[..] } else { &iov[1..] };
        self.fd
            .try_io(Interest::WRITABLE, |fd| writev(fd.as_raw_fd(), iov))
    }

    /// Writes the packet gathered from `iov`, which starts with the virtio-net header if
    /// [`Tun::vnet_hdr`]
    pub async fn send_vectored(&self, iov: &[IoSlice<'_>]) -> io::Result<usize> {
        self.fd
            .async_io(Interest::WRITABLE, |fd| writev(fd.as_raw_fd(), iov))
            .await
    }
}

fn writev(fd: RawFd, iov: &[IoSlice<'_>]) -> io::Result<usize> {
    // IoSlice has the layout of struct iovec
    let n = unsafe { libc::writev(fd, iov.as_ptr().cast(), iov.len() as libc::c_int) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

fn ifreq(name: &str) -> io::Result<libc::ifreq> {
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    if name.len() >= req.ifr_name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface name {name} is too long"),
        ));
    }
    for (dst, src) in req.ifr_name.iter_mut().zip(name.bytes()) {
        *dst = src as libc::c_char;
    }
    Ok(req)
}

/// Brings the interface `name` up
fn set_up(name: &str) -> io::Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let sock = unsafe { OwnedFd::from_raw_fd(sock) };

    let mut req = ifreq(name)?;
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe { req.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short };
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS as _, &req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vnet_hdr_round_trip() {
        let hdr = VnetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV6 | VIRTIO_NET_HDR_GSO_ECN,
            hdr_len: 60,
            gso_size: 1400,
            csum_start: 40,
            csum_offset: 16,
        };
        let mut buf = [0u8; VNET_HDR_LEN];
        hdr.write(&mut buf);
        assert_eq!(VnetHdr::read(&buf), hdr);
        assert_eq!(hdr.tcp_segment_len(), Some(1400));
        assert_eq!(VnetHdr::default().tcp_segment_len(), None);
    }
}
