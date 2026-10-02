//! Receiving and sending datagrams in batches on connected UDP sockets: several are received with
//! one system call, and several of the same length are sent with one, which the kernel splits
//! (UDP GSO)

use fake_tcp::packet::MAX_PACKET_LEN;
use log::info;
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use std::io::{self, IoSlice};
use std::os::fd::AsRawFd;
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// The most datagrams received at once
const RECV_BATCH: usize = 64;
/// The most datagrams sent at once with UDP GSO, UDP_MAX_SEGMENTS of older kernels
const MAX_SEGMENTS: usize = 64;
/// The most bytes sent at once with UDP GSO, which the length field of the UDP header limits
const MAX_SEGMENTS_LEN: usize = u16::MAX as usize - 8;

/// Buffers that datagrams are received into, several at once
pub struct Receiver {
    bufs: Vec<u8>,
    lens: [usize; RECV_BATCH],
    headroom: usize,
}

impl Receiver {
    /// Receives datagrams of up to `MAX_PACKET_LEN` bytes, each with `headroom` bytes in front
    pub fn new(headroom: usize) -> Receiver {
        Receiver {
            bufs: vec![0; RECV_BATCH * (headroom + MAX_PACKET_LEN)],
            lens: [0; RECV_BATCH],
            headroom,
        }
    }

    /// Receives the datagrams that are queued on `sock`, waiting for one if there are none, and
    /// returns the buffers holding them, each with the headroom in front. Longer datagrams are cut
    /// short.
    pub async fn recv(&mut self, sock: &UdpSocket) -> io::Result<Vec<&mut [u8]>> {
        let slot_len = self.headroom + MAX_PACKET_LEN;
        let count = sock
            .async_io(Interest::READABLE, || {
                let mut iov: [libc::iovec; RECV_BATCH] = unsafe { std::mem::zeroed() };
                let mut msgs: [libc::mmsghdr; RECV_BATCH] = unsafe { std::mem::zeroed() };
                for (i, (iov, msg)) in iov.iter_mut().zip(msgs.iter_mut()).enumerate() {
                    iov.iov_base = self.bufs[i * slot_len + self.headroom..]
                        .as_mut_ptr()
                        .cast();
                    iov.iov_len = MAX_PACKET_LEN;
                    msg.msg_hdr.msg_iov = iov;
                    msg.msg_hdr.msg_iovlen = 1;
                }
                let n = unsafe {
                    libc::recvmmsg(
                        sock.as_raw_fd(),
                        msgs.as_mut_ptr(),
                        RECV_BATCH as _,
                        libc::MSG_DONTWAIT as _,
                        std::ptr::null_mut(),
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                for (len, msg) in self.lens.iter_mut().zip(&msgs[..n as usize]) {
                    *len = msg.msg_len as usize;
                }
                Ok(n as usize)
            })
            .await?;

        Ok(self
            .bufs
            .chunks_mut(slot_len)
            .zip(&self.lens[..count])
            .map(|(buf, len)| &mut buf[..self.headroom + len])
            .collect())
    }
}

/// Sends datagrams on a connected UDP socket with as few system calls as possible
pub struct Sender {
    /// Whether the kernel takes datagrams to split
    gso: bool,
    /// Datagrams gathered by [`Sender::push`]
    buf: Vec<u8>,
    runs: Vec<Run>,
}

/// Datagrams of the same length in [`Sender::buf`], but the last, which may be shorter
struct Run {
    start: usize,
    len: usize,
    segment_len: usize,
    count: usize,
    /// Whether the last datagram was shorter
    closed: bool,
}

impl Default for Sender {
    fn default() -> Sender {
        Sender::new(true)
    }
}

impl Sender {
    /// With `gso`, datagrams of the same length are sent at once with UDP GSO, until the kernel
    /// refuses
    pub fn new(gso: bool) -> Sender {
        Sender {
            gso,
            buf: Vec::new(),
            runs: Vec::new(),
        }
    }

    /// Sends the datagrams in `payload` to the peer `sock` is connected to: each is
    /// `segment_len` bytes long, but the last, which may be shorter
    pub async fn send_segments(
        &mut self,
        sock: &UdpSocket,
        payload: &[u8],
        segment_len: usize,
    ) -> io::Result<()> {
        let mut rest = payload;
        while !rest.is_empty() {
            if !self.gso || rest.len() <= segment_len {
                let (datagram, tail) = rest.split_at(segment_len.min(rest.len()));
                rest = tail;
                sock.send(datagram).await?;
                continue;
            }

            let max_len =
                (MAX_SEGMENTS * segment_len).min(MAX_SEGMENTS_LEN / segment_len * segment_len);
            let (segments, tail) = rest.split_at(max_len.min(rest.len()));
            match send_gso(sock, segments, segment_len).await {
                Ok(()) => rest = tail,
                // e.g. EIO without checksum offloading, or EINVAL for datagrams that need to be
                // fragmented
                Err(e) if e.raw_os_error() != Some(libc::ECONNREFUSED) => {
                    info!(
                        "Unable to send datagrams to {:?} at once, sending them one by one: {e}",
                        sock.peer_addr()
                    );
                    self.gso = false;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Adds a datagram to send with [`Sender::flush`]. Empty ones are left out.
    pub fn push(&mut self, datagram: &[u8]) {
        let len = datagram.len();
        if len == 0 {
            return;
        }
        let start = self.buf.len();
        self.buf.extend_from_slice(datagram);

        if let Some(run) = self.runs.last_mut()
            && !run.closed
            && len <= run.segment_len
            && run.count < MAX_SEGMENTS
            && run.len + len <= MAX_SEGMENTS_LEN
        {
            run.len += len;
            run.count += 1;
            run.closed = len < run.segment_len;
            return;
        }
        self.runs.push(Run {
            start,
            len,
            segment_len: len,
            count: 1,
            closed: false,
        });
    }

    /// Sends the datagrams added with [`Sender::push`]
    pub async fn flush(&mut self, sock: &UdpSocket) -> io::Result<()> {
        let buf = std::mem::take(&mut self.buf);
        let runs = std::mem::take(&mut self.runs);
        let mut result = Ok(());
        for run in &runs {
            result = self
                .send_segments(sock, &buf[run.start..run.start + run.len], run.segment_len)
                .await;
            if result.is_err() {
                break;
            }
        }
        // keep the memory
        self.buf = buf;
        self.buf.clear();
        self.runs = runs;
        self.runs.clear();
        result
    }
}

/// Sends the datagrams in `payload`, each `segment_len` bytes long but the last, with one system
/// call
async fn send_gso(sock: &UdpSocket, payload: &[u8], segment_len: usize) -> io::Result<()> {
    let segment_len = segment_len as u16;
    sock.async_io(Interest::WRITABLE, || {
        sendmsg::<()>(
            sock.as_raw_fd(),
            &[IoSlice::new(payload)],
            &[ControlMessage::UdpGsoSegments(&segment_len)],
            MsgFlags::empty(),
            None,
        )
        .map_err(io::Error::from)
    })
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runs(sender: &Sender) -> Vec<(usize, usize, usize)> {
        sender
            .runs
            .iter()
            .map(|r| (r.len, r.segment_len, r.count))
            .collect()
    }

    #[test]
    fn push_runs() {
        let mut sender = Sender::new(true);
        for len in [100, 100, 100, 50, 100, 200, 0, 200] {
            sender.push(&vec![1; len]);
        }
        // a shorter datagram ends a run, a longer one starts another
        assert_eq!(runs(&sender), [(350, 100, 4), (100, 100, 1), (400, 200, 2)]);

        let mut sender = Sender::new(true);
        for _ in 0..MAX_SEGMENTS + 1 {
            sender.push(&[1; 10]);
        }
        assert_eq!(
            runs(&sender),
            [(10 * MAX_SEGMENTS, 10, MAX_SEGMENTS), (10, 10, 1)]
        );
    }

    #[tokio::test]
    async fn send_and_receive_batches() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        a.connect(b.local_addr().unwrap()).await.unwrap();
        b.connect(a.local_addr().unwrap()).await.unwrap();

        let mut sender = Sender::new(true);
        let payload: Vec<u8> = (0..1000u32).map(|i| (i / 300) as u8).collect();
        // three of 300 bytes and one of 100, sent at once, then one by one
        sender.send_segments(&a, &payload, 300).await.unwrap();
        for len in [300, 300, 300, 100] {
            sender.push(&vec![9; len]);
        }
        sender.flush(&a).await.unwrap();

        let mut receiver = Receiver::new(6);
        let mut received = Vec::new();
        while received.len() < 8 {
            for buf in receiver.recv(&b).await.unwrap() {
                received.push(buf[6..].to_vec());
            }
        }
        let lens: Vec<usize> = received.iter().map(Vec::len).collect();
        assert_eq!(lens, [300, 300, 300, 100, 300, 300, 300, 100]);
        assert_eq!(received[1], vec![1; 300]);
        assert_eq!(received[4], vec![9; 300]);
    }
}
