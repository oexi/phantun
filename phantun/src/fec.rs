//! Forward error correction (FEC) for the fake TCP tunnel.
//!
//! Outgoing datagrams are grouped into blocks of up to `K` data shards. After each
//! block, `M` Reed-Solomon parity shards are sent, allowing the receiver to recover
//! up to `M` lost packets per block without any retransmission. Data shards are
//! forwarded as soon as they arrive, so FEC adds no latency when nothing is lost.
//! A block that is not filled within the configured timeout is closed early. It gets
//! as many parity shards as it needs to be as resilient as a full block, which is more
//! than a proportional share, since small blocks are more likely to lose more than
//! their share of packets.
//!
//! Parity shards are sent back to back by default, so a burst of loss can take out a whole
//! block. With a spreading interval, only the first parity shard is sent right away and the
//! others are spread evenly over the interval, trading recovery delay under burst loss for a
//! better chance that enough shards of the block get through.
//!
//! Wire format, prepended to every fake TCP payload:
//!
//! ```text
//! Data shard:   | 0 (u8) | group (u32 BE) | index (u8) | datagram                   |
//! Parity shard: | 1 (u8) | group (u32 BE) | index (u8) | k (u8) | m (u8) | parity  |
//! ```
//!
//! For encoding, each data shard is laid out as `| len (u16 BE) | datagram | zeros |`,
//! padded to the longest datagram of the group, and parity shards have that same length.
//! The length prefix and padding are never sent with data shards, as both are derived
//! from the received packet size. The number of data shards in a group is only known
//! once the group is closed, so only parity shards carry `k` and `m`.

use fake_tcp::Socket;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::io;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time;

const TYPE_DATA: u8 = 0;
const TYPE_PARITY: u8 = 1;
/// Bytes reserved in front of every outgoing datagram buffer for the data shard header
pub const HEADROOM: usize = 6;
const PARITY_HEADER_LEN: usize = 8;
const LEN_PREFIX: usize = 2;
/// Extra bytes FEC adds on top of the largest datagram, which is the size of a parity shard header
/// plus the length prefix
pub const MTU_OVERHEAD: usize = PARITY_HEADER_LEN + LEN_PREFIX;
/// Number of recent groups the decoder keeps track of
const MAX_GROUPS: usize = 256;
const MAX_CODECS: usize = 64;
/// Fraction of data shards that may stay unrecovered, used to find the loss rate a `K:M`
/// ratio is meant for, and the parity shards smaller groups need to cope with it
const TARGET_RESIDUAL_LOSS: f64 = 0.001;
/// Most parity shards a connection keeps waiting when they are spread out. Beyond this, parity
/// shards are sent right away rather than growing the queue without bound.
const MAX_PENDING_PARITY: usize = 4096;
/// Longest time parity shards may be spread over, far longer than any burst worth riding out
const MAX_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FecConfig {
    pub data_shards: usize,
    pub parity_shards: usize,
    pub timeout: Duration,
    /// Time over which the parity shards of a group are spread out, zero sends them back to back
    pub interval: Duration,
}

impl FecConfig {
    /// Parses `K:M`, where `K` is the number of data shards and `M` the number of parity shards
    /// per group.
    pub fn parse(ratio: &str, timeout: Duration, interval: Duration) -> Result<FecConfig, String> {
        let (k, m) = ratio
            .split_once(':')
            .ok_or_else(|| format!("expected K:M, got \"{ratio}\""))?;
        let k: usize = k.parse().map_err(|_| format!("bad K in \"{ratio}\""))?;
        let m: usize = m.parse().map_err(|_| format!("bad M in \"{ratio}\""))?;

        if k == 0 || m == 0 || k + m > 256 {
            return Err(format!(
                "K and M must be at least 1 and K + M must not exceed 256, got \"{ratio}\""
            ));
        }
        if interval > MAX_INTERVAL {
            return Err(format!(
                "the interval must not exceed {MAX_INTERVAL:?}, got {interval:?}"
            ));
        }

        Ok(FecConfig {
            data_shards: k,
            parity_shards: m,
            timeout,
            interval,
        })
    }
}

/// Offsets from the close of a group at which its `count` parity shards are sent, spread evenly
/// over `interval`. The first one is always sent right away, so a single lost packet is recovered
/// as quickly as without spreading, and only a burst of loss has to wait for the later ones.
fn parity_offsets(count: usize, interval: Duration) -> impl Iterator<Item = Duration> {
    (0..count).map(move |i| {
        if count > 1 {
            interval * i as u32 / (count - 1) as u32
        } else {
            Duration::ZERO
        }
    })
}

/// Parity shards waiting to be sent, when they are spread out over time
#[derive(Default)]
struct Pacer {
    /// `(send at, sequence, frame)`, the sequence number keeps shards due at the same time in order
    queue: BinaryHeap<Reverse<(Instant, u64, Vec<u8>)>>,
    seq: u64,
}

impl Pacer {
    fn push(&mut self, at: Instant, frame: Vec<u8>) {
        self.queue.push(Reverse((at, self.seq, frame)));
        self.seq = self.seq.wrapping_add(1);
    }

    /// When the next shard is due, or `None` if nothing is queued
    fn next(&self) -> Option<Instant> {
        self.queue.peek().map(|Reverse((at, _, _))| *at)
    }

    /// Moves every shard due at `now` to `out`, in the order they are due
    fn pop_due(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) {
        while self.next().is_some_and(|at| at <= now) {
            let Reverse((_, _, frame)) = self.queue.pop().unwrap();
            out.push(frame);
        }
    }
}

/// Expected fraction of data shards that can not be recovered, for a group of `k` data and `m`
/// parity shards sent over a link losing packets randomly with probability `p`
fn residual_loss(k: usize, m: usize, p: f64) -> f64 {
    // a group is unrecoverable once more than `m` of its `n` shards are lost, and on average
    // `k / n` of the lost shards are data shards
    let n = k + m;
    let mut pmf = (1.0 - p).powi(n as i32);
    let mut lost = 0.0;
    for l in 0..=n {
        if l > m {
            lost += pmf * l as f64;
        }
        pmf *= (n - l) as f64 / (l + 1) as f64 * p / (1.0 - p);
    }

    lost / n as f64
}

/// Returns the number of parity shards for groups of 1 to `k` data shards. A full group gets `m`
/// parity shards. A smaller group gets as many as it needs to meet `TARGET_RESIDUAL_LOSS` at the
/// highest loss rate a full group meets it at, but no less than a proportional share and no more
/// than `m`.
fn parity_table(k: usize, m: usize) -> Vec<usize> {
    let (mut loss, mut hi) = (0.0, 0.5);
    for _ in 0..50 {
        let mid = (loss + hi) / 2.0;
        if residual_loss(k, m, mid) <= TARGET_RESIDUAL_LOSS {
            loss = mid;
        } else {
            hi = mid;
        }
    }

    (1..=k)
        .map(|n| {
            ((n * m).div_ceil(k)..m)
                .find(|&p| residual_loss(n, p, loss) <= TARGET_RESIDUAL_LOSS)
                .unwrap_or(m)
        })
        .collect()
}

#[derive(Default)]
struct Codecs(HashMap<(usize, usize), ReedSolomon>);

impl Codecs {
    fn get(&mut self, k: usize, m: usize) -> Option<&ReedSolomon> {
        if !self.0.contains_key(&(k, m)) {
            if self.0.len() >= MAX_CODECS {
                self.0.clear();
            }
            self.0.insert((k, m), ReedSolomon::new(k, m).ok()?);
        }

        self.0.get(&(k, m))
    }
}

struct Encoder {
    config: FecConfig,
    /// Number of parity shards by number of data shards in the group, minus one
    parity: Vec<usize>,
    group: u32,
    shards: Vec<Vec<u8>>,
    started: Option<Instant>,
    codecs: Codecs,
}

impl Encoder {
    fn new(config: FecConfig) -> Encoder {
        Encoder {
            config,
            parity: parity_table(config.data_shards, config.parity_shards),
            group: 0,
            shards: Vec::with_capacity(config.data_shards),
            started: None,
            codecs: Codecs::default(),
        }
    }

    /// Turns `buf` (`HEADROOM` bytes followed by the datagram) into a data shard in place.
    /// Returns parity shards to send if this closes the current group.
    fn push(&mut self, buf: &mut [u8], now: Instant) -> Vec<Vec<u8>> {
        buf[0] = TYPE_DATA;
        buf[1..5].copy_from_slice(&self.group.to_be_bytes());
        buf[5] = self.shards.len() as u8;
        self.shards.push(buf[HEADROOM..].to_vec());

        if self.started.is_none() {
            self.started = Some(now);
        }

        if self.shards.len() == self.config.data_shards {
            self.finish()
        } else {
            Vec::new()
        }
    }

    /// When the current group has to be flushed, or `None` if it is empty
    fn deadline(&self) -> Option<Instant> {
        self.started.map(|t| t + self.config.timeout)
    }

    fn flush_expired(&mut self, now: Instant) -> Vec<Vec<u8>> {
        match self.deadline() {
            Some(deadline) if deadline <= now => self.finish(),
            _ => Vec::new(),
        }
    }

    /// Closes the current group and returns its parity shards
    fn finish(&mut self) -> Vec<Vec<u8>> {
        let k = self.shards.len();
        let m = self.parity[k - 1];
        let shard_size = LEN_PREFIX + self.shards.iter().map(Vec::len).max().unwrap_or(0);

        let data: Vec<Vec<u8>> = self
            .shards
            .drain(..)
            .map(|d| {
                let mut shard = Vec::with_capacity(shard_size);
                shard.extend_from_slice(&(d.len() as u16).to_be_bytes());
                shard.extend_from_slice(&d);
                shard.resize(shard_size, 0);
                shard
            })
            .collect();

        let mut parity: Vec<Vec<u8>> = (0..m)
            .map(|i| {
                let mut p = vec![0u8; PARITY_HEADER_LEN + shard_size];
                p[0] = TYPE_PARITY;
                p[1..5].copy_from_slice(&self.group.to_be_bytes());
                p[5] = (k + i) as u8;
                p[6] = k as u8;
                p[7] = m as u8;
                p
            })
            .collect();

        let codec = self
            .codecs
            .get(k, m)
            .expect("FEC parameters are validated by FecConfig::parse");
        let mut parity_shards: Vec<&mut [u8]> = parity
            .iter_mut()
            .map(|p| &mut p[PARITY_HEADER_LEN..])
            .collect();
        codec
            .encode_sep(&data, &mut parity_shards)
            .expect("shards are of equal size");

        self.group = self.group.wrapping_add(1);
        self.started = None;

        parity
    }
}

#[derive(Default)]
struct Group {
    /// `(k, m)`, known once a parity shard has been received
    params: Option<(usize, usize)>,
    data: Vec<(u8, Vec<u8>)>,
    parity: Vec<(u8, Vec<u8>)>,
    done: bool,
}

impl Group {
    fn close(&mut self) {
        self.done = true;
        self.data = Vec::new();
        self.parity = Vec::new();
    }
}

#[derive(Default)]
struct Decoder {
    groups: HashMap<u32, Group>,
    order: VecDeque<u32>,
    codecs: Codecs,
}

impl Decoder {
    fn group(&mut self, id: u32) -> &mut Group {
        if !self.groups.contains_key(&id) {
            if self.order.len() >= MAX_GROUPS
                && let Some(oldest) = self.order.pop_front()
            {
                self.groups.remove(&oldest);
            }
            self.order.push_back(id);
        }

        self.groups.entry(id).or_default()
    }

    /// Decodes a frame received from the peer. Returns the datagram to forward right away
    /// if `frame` is a new data shard, and appends datagrams recovered from lost data
    /// shards to `recovered`.
    fn feed<'a>(&mut self, frame: &'a [u8], recovered: &mut Vec<Vec<u8>>) -> Option<&'a [u8]> {
        if frame.len() < HEADROOM {
            return None;
        }

        let id = u32::from_be_bytes(frame[1..5].try_into().unwrap());
        let index = frame[5];

        match frame[0] {
            TYPE_DATA => {
                let payload = &frame[HEADROOM..];
                let group = self.group(id);
                if group.done || group.data.iter().any(|(i, _)| *i == index) {
                    return None;
                }

                group.data.push((index, payload.to_vec()));
                self.try_recover(id, recovered);

                Some(payload)
            }
            TYPE_PARITY => {
                if frame.len() < PARITY_HEADER_LEN + LEN_PREFIX {
                    return None;
                }
                let (k, m) = (frame[6] as usize, frame[7] as usize);
                if k == 0 || m == 0 || (index as usize) < k || index as usize >= k + m {
                    return None;
                }

                let parity = &frame[PARITY_HEADER_LEN..];
                let group = self.group(id);
                if group.done
                    || group.params.is_some_and(|p| p != (k, m))
                    || group
                        .parity
                        .iter()
                        .any(|(i, p)| *i == index || p.len() != parity.len())
                {
                    return None;
                }

                group.params = Some((k, m));
                group.parity.push((index, parity.to_vec()));
                self.try_recover(id, recovered);

                None
            }
            _ => None,
        }
    }

    fn try_recover(&mut self, id: u32, recovered: &mut Vec<Vec<u8>>) {
        let group = self.groups.get_mut(&id).unwrap();
        let Some((k, m)) = group.params else {
            return;
        };

        if group.data.len() >= k {
            // nothing lost
            group.close();
            return;
        }
        if group.data.len() + group.parity.len() < k {
            return;
        }

        let data = std::mem::take(&mut group.data);
        let parity = std::mem::take(&mut group.parity);
        group.close();

        let shard_size = parity[0].1.len();
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; k + m];
        for (index, payload) in data {
            if index as usize >= k || LEN_PREFIX + payload.len() > shard_size {
                return;
            }

            let mut shard = Vec::with_capacity(shard_size);
            shard.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            shard.extend_from_slice(&payload);
            shard.resize(shard_size, 0);
            shards[index as usize] = Some(shard);
        }
        for (index, parity) in parity {
            shards[index as usize] = Some(parity);
        }

        let missing: Vec<usize> = (0..k).filter(|&i| shards[i].is_none()).collect();
        let Some(codec) = self.codecs.get(k, m) else {
            return;
        };
        if codec.reconstruct_data(&mut shards).is_err() {
            return;
        }

        for i in missing {
            let shard = shards[i].as_ref().unwrap();
            let len = u16::from_be_bytes([shard[0], shard[1]]) as usize;
            if LEN_PREFIX + len <= shard.len() {
                recovered.push(shard[LEN_PREFIX..LEN_PREFIX + len].to_vec());
            }
        }
    }
}

/// FEC state of a single fake TCP connection, shared by all of its worker tasks.
pub struct Fec {
    encoder: Mutex<Encoder>,
    decoder: Mutex<Decoder>,
    pacer: Mutex<Pacer>,
    interval: Duration,
    /// Wakes the flusher when a group starts or parity shards are queued
    wake: Notify,
}

impl Fec {
    pub fn new(config: FecConfig) -> Fec {
        Fec {
            encoder: Mutex::new(Encoder::new(config)),
            decoder: Mutex::new(Decoder::default()),
            pacer: Mutex::new(Pacer::default()),
            interval: config.interval,
            wake: Notify::new(),
        }
    }

    /// Sends parity shards of groups that have not been filled within the timeout, and parity
    /// shards that were spread out once they are due. Returns once `sock` fails.
    pub async fn run_flusher(&self, sock: &Socket) {
        let mut out = Vec::new();
        loop {
            let deadline = self.encoder.lock().unwrap().deadline();
            let due = self.pacer.lock().unwrap().next();
            match deadline.into_iter().chain(due).min() {
                // a group closing or parity being queued may need an earlier wake up
                Some(next) => tokio::select! {
                    _ = time::sleep_until(next.into()) => {}
                    _ = self.wake.notified() => {}
                },
                None => self.wake.notified().await,
            }

            let now = Instant::now();
            let parity = self.encoder.lock().unwrap().flush_expired(now);
            out.extend(self.schedule(parity, now));
            self.pacer.lock().unwrap().pop_due(now, &mut out);
            for p in out.drain(..) {
                if sock.send(&p).await.is_none() {
                    return;
                }
            }
        }
    }

    /// Takes the parity shards of a group that closed at `now` and returns those to send right
    /// away. When they are spread out, the others are queued for the flusher to send later.
    fn schedule(&self, parity: Vec<Vec<u8>>, now: Instant) -> Vec<Vec<u8>> {
        if self.interval.is_zero() || parity.len() <= 1 {
            return parity;
        }

        let mut send_now = Vec::new();
        let mut pacer = self.pacer.lock().unwrap();
        let offsets = parity_offsets(parity.len(), self.interval);
        for (p, offset) in parity.into_iter().zip(offsets) {
            if offset.is_zero() || pacer.queue.len() >= MAX_PENDING_PARITY {
                send_now.push(p);
            } else {
                pacer.push(now + offset, p);
            }
        }
        drop(pacer);
        self.wake.notify_one();

        send_now
    }
}

/// Sends the datagram `buf[HEADROOM..]` to the peer, encoding it with FEC if enabled.
/// The first `HEADROOM` bytes of `buf` are scratch space for the FEC header.
///
/// A return of `None` means `sock` must be closed.
pub async fn send_datagram(sock: &Socket, fec: Option<&Fec>, buf: &mut [u8]) -> Option<()> {
    let Some(fec) = fec else {
        return sock.send(&buf[HEADROOM..]).await;
    };

    let now = Instant::now();
    let parity = {
        let mut encoder = fec.encoder.lock().unwrap();
        let group_started = encoder.started.is_none();
        let parity = encoder.push(buf, now);
        if group_started && encoder.started.is_some() {
            fec.wake.notify_one();
        }
        parity
    };
    let parity = fec.schedule(parity, now);

    sock.send(buf).await?;
    for p in parity {
        sock.send(&p).await?;
    }

    Some(())
}

/// Forwards a payload received from the peer to `udp_sock`, decoding FEC if enabled.
/// `recovered` is scratch space reused between calls.
pub async fn forward_to_udp(
    udp_sock: &UdpSocket,
    fec: Option<&Fec>,
    frame: &[u8],
    recovered: &mut Vec<Vec<u8>>,
) -> io::Result<()> {
    let Some(fec) = fec else {
        udp_sock.send(frame).await?;
        return Ok(());
    };

    let datagram = fec.decoder.lock().unwrap().feed(frame, recovered);
    if let Some(datagram) = datagram {
        udp_sock.send(datagram).await?;
    }
    for datagram in recovered.drain(..) {
        udp_sock.send(&datagram).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(k: usize, m: usize) -> FecConfig {
        FecConfig {
            data_shards: k,
            parity_shards: m,
            timeout: Duration::from_millis(10),
            interval: Duration::ZERO,
        }
    }

    fn datagram(i: usize) -> Vec<u8> {
        (0..(i * 37) % 1400 + 1).map(|b| (b + i) as u8).collect()
    }

    /// Encodes `datagrams`, flushing the last partial group, and returns the frames on the wire
    fn encode(encoder: &mut Encoder, datagrams: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut frames = Vec::new();
        for d in datagrams {
            let mut buf = vec![0u8; HEADROOM];
            buf.extend_from_slice(d);
            let parity = encoder.push(&mut buf, now);
            frames.push(buf);
            frames.extend(parity);
        }
        frames.extend(encoder.flush_expired(now + Duration::from_secs(1)));
        frames
    }

    /// Feeds `frames` into `decoder` and returns every datagram it delivers
    fn decode<'a>(
        decoder: &mut Decoder,
        frames: impl Iterator<Item = &'a Vec<u8>>,
    ) -> Vec<Vec<u8>> {
        let mut delivered = Vec::new();
        let mut recovered = Vec::new();
        for f in frames {
            if let Some(d) = decoder.feed(f, &mut recovered) {
                delivered.push(d.to_vec());
            }
            delivered.append(&mut recovered);
        }
        delivered
    }

    fn sorted(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        v.sort();
        v
    }

    #[test]
    fn parse_config() {
        let t = Duration::from_millis(8);
        let i = Duration::from_millis(20);
        assert_eq!(
            FecConfig::parse("10:3", t, i),
            Ok(FecConfig {
                data_shards: 10,
                parity_shards: 3,
                timeout: t,
                interval: i,
            })
        );
        assert!(FecConfig::parse("10", t, i).is_err());
        assert!(FecConfig::parse("0:3", t, i).is_err());
        assert!(FecConfig::parse("10:0", t, i).is_err());
        assert!(FecConfig::parse("200:57", t, i).is_err());
        assert!(FecConfig::parse("200:56", t, i).is_ok());
        assert!(FecConfig::parse("10:3", t, MAX_INTERVAL).is_ok());
        assert!(FecConfig::parse("10:3", t, MAX_INTERVAL + Duration::from_millis(1)).is_err());
    }

    #[test]
    fn parity_spread_offsets() {
        let ms = Duration::from_millis;
        assert_eq!(parity_offsets(1, ms(9)).collect::<Vec<_>>(), [ms(0)]);
        assert_eq!(
            parity_offsets(4, ms(9)).collect::<Vec<_>>(),
            [ms(0), ms(3), ms(6), ms(9)]
        );
        assert!(parity_offsets(3, Duration::ZERO).all(|d| d.is_zero()));
    }

    /// Frames standing in for parity shards, tagged by group and index
    fn fake_parity(group: u8, count: u8) -> Vec<Vec<u8>> {
        (0..count).map(|i| vec![group, i]).collect()
    }

    #[test]
    fn parity_back_to_back_without_interval() {
        let fec = Fec::new(config(10, 3));
        let now = Instant::now();
        assert_eq!(fec.schedule(fake_parity(0, 3), now), fake_parity(0, 3));
        assert_eq!(fec.pacer.lock().unwrap().next(), None);
    }

    #[test]
    fn parity_spread_over_interval() {
        let fec = Fec::new(FecConfig {
            interval: Duration::from_millis(20),
            ..config(10, 3)
        });
        let ms = Duration::from_millis;
        let t0 = Instant::now();

        // only the first parity shard goes out right away
        assert_eq!(fec.schedule(fake_parity(0, 3), t0), [vec![0, 0]]);
        // a second group closing while the first one is still being spread out
        assert_eq!(fec.schedule(fake_parity(1, 3), t0 + ms(5)), [vec![1, 0]]);

        let mut pacer = fec.pacer.lock().unwrap();
        assert_eq!(pacer.next(), Some(t0 + ms(10)));

        let mut out = Vec::new();
        pacer.pop_due(t0 + ms(9), &mut out);
        assert!(out.is_empty());

        // shards of both groups come out interleaved, in the order they are due
        pacer.pop_due(t0 + ms(25), &mut out);
        assert_eq!(out, [vec![0, 1], vec![1, 1], vec![0, 2], vec![1, 2]]);
        assert_eq!(pacer.next(), None);
    }

    #[test]
    fn bounded_pending_parity() {
        let fec = Fec::new(FecConfig {
            interval: Duration::from_millis(20),
            ..config(1, 2)
        });
        let now = Instant::now();
        let mut sent_now = 0;
        for g in 0..=MAX_PENDING_PARITY {
            sent_now += fec.schedule(fake_parity(g as u8, 2), now).len();
        }

        // once the queue is full, parity shards are sent right away instead of queued
        assert_eq!(fec.pacer.lock().unwrap().queue.len(), MAX_PENDING_PARITY);
        assert_eq!(sent_now, MAX_PENDING_PARITY + 2);
    }

    #[test]
    fn residual_loss_rate() {
        // one data and one parity shard are unrecoverable only if both are lost
        assert!((residual_loss(1, 1, 0.1) - 0.01).abs() < 1e-12);
        assert_eq!(residual_loss(10, 3, 0.0), 0.0);
        assert!((residual_loss(10, 3, 1.0 - 1e-9) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn parity_for_small_groups() {
        assert_eq!(parity_table(1, 1), [1]);
        assert_eq!(parity_table(10, 3), [2, 2, 2, 3, 3, 3, 3, 3, 3, 3]);
        assert_eq!(parity_table(10, 9), [4, 5, 6, 6, 7, 7, 8, 8, 9, 9]);
        assert_eq!(
            parity_table(20, 2),
            [1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
        );
        assert_eq!(
            parity_table(20, 14),
            [
                4, 5, 6, 6, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 14
            ]
        );

        let table = parity_table(200, 56);
        assert_eq!(table.len(), 200);
        assert!(table.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(table[199], 56);
    }

    #[test]
    fn no_loss() {
        let datagrams: Vec<_> = (0..25).map(datagram).collect();
        let frames = encode(&mut Encoder::new(config(10, 3)), &datagrams);
        // 2 full groups and a group of 5 closed by timeout, all with 3 parity each
        assert_eq!(frames.len(), 25 + 3 + 3 + 3);

        let delivered = decode(&mut Decoder::default(), frames.iter());
        assert_eq!(delivered, datagrams);
    }

    #[test]
    fn recover_lost_data() {
        let datagrams: Vec<_> = (0..20).map(datagram).collect();
        let frames = encode(&mut Encoder::new(config(10, 3)), &datagrams);

        // drop 3 frames of the first group and 2 data + 1 parity of the second
        let lost = [0, 4, 9, 13, 20, 24];
        let delivered = decode(
            &mut Decoder::default(),
            frames
                .iter()
                .enumerate()
                .filter(|(i, _)| !lost.contains(i))
                .map(|(_, f)| f),
        );
        assert_eq!(sorted(delivered), sorted(datagrams));
    }

    #[test]
    fn too_many_lost() {
        let datagrams: Vec<_> = (0..10).map(datagram).collect();
        let frames = encode(&mut Encoder::new(config(10, 3)), &datagrams);

        let lost = [0, 1, 2, 3];
        let delivered = decode(
            &mut Decoder::default(),
            frames
                .iter()
                .enumerate()
                .filter(|(i, _)| !lost.contains(i))
                .map(|(_, f)| f),
        );
        assert_eq!(delivered, datagrams[4..]);
    }

    #[test]
    fn recover_partial_group() {
        let datagrams: Vec<_> = (0..3).map(datagram).collect();
        let frames = encode(&mut Encoder::new(config(10, 4)), &datagrams);
        // 3 parity shards rather than a proportional share of 2
        assert_eq!(frames.len(), 6);

        // every data shard lost
        let delivered = decode(&mut Decoder::default(), frames[3..].iter());
        assert_eq!(sorted(delivered), sorted(datagrams));
    }

    #[test]
    fn reordered_and_duplicated() {
        let datagrams: Vec<_> = (0..10).map(datagram).collect();
        let frames = encode(&mut Encoder::new(config(10, 3)), &datagrams);

        // parity first, one data shard lost, everything duplicated
        let order = [10, 11, 12, 10, 5, 5, 6, 7, 8, 9, 0, 1, 2, 3, 3];
        let delivered = decode(&mut Decoder::default(), order.iter().map(|&i| &frames[i]));
        assert_eq!(sorted(delivered), sorted(datagrams));
    }

    #[test]
    fn group_timeout() {
        let mut encoder = Encoder::new(config(10, 3));
        let now = Instant::now();
        assert_eq!(encoder.deadline(), None);

        let mut buf = vec![0u8; HEADROOM + 100];
        assert!(encoder.push(&mut buf, now).is_empty());
        assert_eq!(encoder.deadline(), Some(now + Duration::from_millis(10)));
        assert!(
            encoder
                .flush_expired(now + Duration::from_millis(9))
                .is_empty()
        );
        assert_eq!(
            encoder.flush_expired(now + Duration::from_millis(10)).len(),
            2
        );
        assert_eq!(encoder.deadline(), None);
    }

    #[test]
    fn malformed_frames() {
        let mut decoder = Decoder::default();
        let mut recovered = Vec::new();
        let frames: [&[u8]; 7] = [
            &[],
            &[0, 0, 0],
            &[2, 0, 0, 0, 0, 0, 1],
            // parity with k = 0, index < k, index >= k + m, no length prefix
            &[1, 0, 0, 0, 0, 0, 0, 1, 0, 0],
            &[1, 0, 0, 0, 0, 0, 1, 1, 0, 0],
            &[1, 0, 0, 0, 0, 2, 1, 1, 0, 0],
            &[1, 0, 0, 0, 0, 1, 1, 1, 0],
        ];
        for f in frames {
            assert!(decoder.feed(f, &mut recovered).is_none());
        }

        // parity claiming a length larger than the shard
        assert!(
            decoder
                .feed(&[1, 0, 0, 0, 1, 1, 1, 1, 0xff, 0xff], &mut recovered)
                .is_none()
        );
        assert!(recovered.is_empty());

        // data shard larger than the parity shards of its group
        assert!(
            decoder
                .feed(&[1, 0, 0, 0, 2, 2, 2, 1, 0, 0], &mut recovered)
                .is_none()
        );
        assert!(
            decoder
                .feed(&[0, 0, 0, 0, 2, 0, 1, 2, 3], &mut recovered)
                .is_some()
        );
        assert!(recovered.is_empty());
    }

    #[test]
    fn bounded_group_state() {
        let mut decoder = Decoder::default();
        let mut recovered = Vec::new();
        for id in 0..(MAX_GROUPS as u32 * 4) {
            let mut frame = vec![0u8; HEADROOM + 10];
            frame[1..5].copy_from_slice(&id.to_be_bytes());
            assert!(decoder.feed(&frame, &mut recovered).is_some());
        }
        assert_eq!(decoder.groups.len(), MAX_GROUPS);
        assert_eq!(decoder.order.len(), MAX_GROUPS);
    }
}
