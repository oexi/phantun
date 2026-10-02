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

use clap::{Arg, ArgMatches, value_parser};
use fake_tcp::Socket;
use fake_tcp::packet::{MAX_HEADER_LEN, MAX_PACKET_LEN};
use log::{info, warn};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time;

const TYPE_DATA: u8 = 0;
const TYPE_PARITY: u8 = 1;
/// Length of the header of a data shard
pub const HEADROOM: usize = 6;
/// Bytes reserved in front of every outgoing datagram for the headers of its packet, see
/// [`send_datagram`]
pub const SEND_HEADROOM: usize = MAX_HEADER_LEN + HEADROOM;
const PARITY_HEADER_LEN: usize = 8;
const LEN_PREFIX: usize = 2;
/// Extra bytes FEC adds on top of the largest datagram, which is the size of a parity shard header
/// plus the length prefix
pub const MTU_OVERHEAD: usize = PARITY_HEADER_LEN + LEN_PREFIX;
/// Number of recent groups the decoder keeps track of, a power of two so that group numbers keep
/// mapping to the same slot when they wrap around
const MAX_GROUPS: usize = 256;
const _: () = assert!(MAX_GROUPS.is_power_of_two());
/// Number of codecs the decoder keeps, enough for every group size of any peer
const MAX_CODECS: usize = 256;
/// Fraction of data shards that may stay unrecovered, used to find the loss rate a `K:M`
/// ratio is meant for, and the parity shards smaller groups need to cope with it
const TARGET_RESIDUAL_LOSS: f64 = 0.001;
/// Most parity shards a connection keeps waiting when they are spread out. Beyond this, parity
/// shards are sent right away rather than growing the queue without bound.
const MAX_PENDING_PARITY: usize = 4096;
/// Longest time in milliseconds a partial group may wait for more packets, far longer than any
/// recovery delay worth waiting for
const MAX_TIMEOUT_MS: u64 = 1000;
/// Longest time in milliseconds parity shards may be spread over, far longer than any burst worth
/// riding out
const MAX_INTERVAL_MS: u64 = 1000;
/// Longest time in seconds between two statistics reports of a connection
const MAX_STATS_SECS: u64 = 86400;
/// Number of frames that are not FEC frames, without a single FEC data shard, after which the peer
/// is assumed not to use FEC. More than one, as the peer may send a handshake packet.
const MISMATCH_FRAMES: u64 = 3;

/// Command line arguments configuring FEC, shared by the client and the server
pub fn args() -> [Arg; 4] {
    [
        Arg::new("fec")
            .long("fec")
            .required(false)
            .value_name("K:M")
            .value_parser(parse_ratio)
            .help("Enables forward error correction: after every K packets, M parity packets are \
                   sent so that up to M lost packets can be recovered by the peer. \
                   Must be enabled on both ends, K:M can differ per direction. \
                   Reduce the WireGuard MTU by another 10 bytes when enabled"),
        Arg::new("fec_timeout")
            .long("fec-timeout")
            .required(false)
            .value_name("MS")
            .value_parser(value_parser!(u64).range(0..=MAX_TIMEOUT_MS))
            .requires("fec")
            .help("Sends parity packets for a group of less than K packets after this many milliseconds, \
                   at most 1000")
            .default_value("8"),
        Arg::new("fec_interval")
            .long("fec-interval")
            .required(false)
            .value_name("MS")
            .value_parser(value_parser!(u64).range(0..=MAX_INTERVAL_MS))
            .requires("fec")
            .help("Spreads the parity packets of each group evenly over this many milliseconds \
                   instead of sending them back to back, so that a burst of loss is less likely \
                   to take out a whole group. The first parity packet is still sent right away, \
                   but recovery from a burst may be delayed by up to this much. 0 disables, at most 1000")
            .default_value("0"),
        Arg::new("fec_stats")
            .long("fec-stats")
            .required(false)
            .value_name("SECS")
            .value_parser(value_parser!(u64).range(0..=MAX_STATS_SECS))
            .requires("fec")
            .help("Logs how many packets of each connection were sent, received, recovered and lost \
                   every this many seconds, and when the connection closes. 0 only logs them when \
                   the connection closes")
            .default_value("300"),
    ]
}

/// Parses `K:M`, where `K` is the number of data shards and `M` the number of parity shards per
/// group.
fn parse_ratio(ratio: &str) -> Result<(usize, usize), String> {
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

    Ok((k, m))
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FecConfig {
    pub data_shards: usize,
    pub parity_shards: usize,
    pub timeout: Duration,
    /// Time over which the parity shards of a group are spread out, zero sends them back to back
    pub interval: Duration,
    /// Time between two statistics reports, zero only reports them when the connection closes
    pub stats_interval: Duration,
}

impl FecConfig {
    /// Reads the configuration from the arguments of [`args`], `None` if FEC is not enabled
    pub fn from_matches(matches: &ArgMatches) -> Option<FecConfig> {
        let &(data_shards, parity_shards) = matches.get_one::<(usize, usize)>("fec")?;
        let value = |id| *matches.get_one::<u64>(id).unwrap();

        Some(FecConfig {
            data_shards,
            parity_shards,
            timeout: Duration::from_millis(value("fec_timeout")),
            interval: Duration::from_millis(value("fec_interval")),
            stats_interval: Duration::from_secs(value("fec_stats")),
        })
    }
}

impl fmt::Display for FecConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}, timeout {:?}, parity spread over {:?}",
            self.data_shards, self.parity_shards, self.timeout, self.interval
        )
    }
}

/// Packet counters of a connection
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Stats {
    sent_data: u64,
    sent_parity: u64,
    /// Data and parity shards received, not counting duplicates
    received_data: u64,
    received_parity: u64,
    /// Lost data shards recovered from parity shards
    recovered: u64,
    /// Lost data shards that could not be recovered. Losses at the end of a group are only known
    /// once a parity shard of the group was received.
    lost: u64,
    /// Parity shards that arrived after their group was forgotten
    late_parity: u64,
    /// Frames that are not FEC frames
    invalid: u64,
}

impl Stats {
    /// Counters since `earlier`
    fn since(&self, earlier: &Stats) -> Stats {
        Stats {
            sent_data: self.sent_data - earlier.sent_data,
            sent_parity: self.sent_parity - earlier.sent_parity,
            received_data: self.received_data - earlier.received_data,
            received_parity: self.received_parity - earlier.received_parity,
            recovered: self.recovered - earlier.recovered,
            lost: self.lost - earlier.lost,
            late_parity: self.late_parity - earlier.late_parity,
            invalid: self.invalid - earlier.invalid,
        }
    }

    fn is_empty(&self) -> bool {
        *self == Stats::default()
    }
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sent {} data + {} parity packets, received {} data + {} parity packets, \
             recovered {} and lost {} data packets",
            self.sent_data,
            self.sent_parity,
            self.received_data,
            self.received_parity,
            self.recovered,
            self.lost
        )?;

        let data = self.received_data + self.recovered + self.lost;
        if data > 0 {
            let percent = |n| n as f64 * 100.0 / data as f64;
            write!(
                f,
                " ({:.2}% loss before FEC, {:.3}% after)",
                percent(self.recovered + self.lost),
                percent(self.lost)
            )?;
        }
        if self.late_parity > 0 {
            write!(f, ", {} late parity packets", self.late_parity)?;
        }
        if self.invalid > 0 {
            write!(f, ", {} invalid packets", self.invalid)?;
        }

        Ok(())
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

fn codec(k: usize, m: usize) -> Option<Arc<ReedSolomon>> {
    ReedSolomon::new(k, m).ok().map(Arc::new)
}

/// Codecs for the parameters chosen by the peer
#[derive(Default)]
struct Codecs(HashMap<(usize, usize), Arc<ReedSolomon>>);

impl Codecs {
    fn get(&mut self, k: usize, m: usize) -> Option<Arc<ReedSolomon>> {
        if !self.0.contains_key(&(k, m)) {
            if self.0.len() >= MAX_CODECS {
                self.0.clear();
            }
            self.0.insert((k, m), codec(k, m)?);
        }

        self.0.get(&(k, m)).cloned()
    }
}

/// Lays out a datagram as a data shard for encoding, `| len (u16 BE) | datagram |`, leaving room
/// for padding up to the largest datagram
fn data_shard(datagram: &[u8]) -> Vec<u8> {
    let mut shard = Vec::with_capacity(LEN_PREFIX + MAX_PACKET_LEN);
    shard.extend_from_slice(&(datagram.len() as u16).to_be_bytes());
    shard.extend_from_slice(datagram);
    shard
}

/// Shared memory holding the group number (upper half) and the number of data shards taken in it
/// (lower half) of the encoder of a connection, which something else sending data shards on its
/// behalf, such as an eBPF program, takes from as well. Whoever takes the last index of a group
/// moves on to the next one. See [`Fec::share_claims`].
#[cfg(target_has_atomic = "64")]
pub trait SharedClaims: Send + Sync {
    fn claims(&self) -> &std::sync::atomic::AtomicU64;
}

/// Where the group numbers and indexes of data shards come from
enum Claims {
    Local {
        group: u32,
        count: usize,
    },
    #[cfg(target_has_atomic = "64")]
    Shared(Arc<dyn SharedClaims>),
}

/// A group whose data shards are being collected. Shards sent by someone else may arrive out of
/// order or after the group was closed.
struct Pending {
    group: u32,
    /// Data shards by index, not padded yet
    shards: Vec<Option<Vec<u8>>>,
    present: usize,
    /// The number of data shards, if the group was closed before it was full
    closed_at: Option<usize>,
    started: Instant,
}

impl Pending {
    fn data_shards(&self) -> usize {
        self.closed_at.unwrap_or(self.shards.len())
    }
}

/// How long a group other than the current one may wait for data shards taken by someone else,
/// which only happens if they never get to send them
const MAX_PENDING_TIME: Duration = Duration::from_secs(1);

struct Encoder {
    config: FecConfig,
    /// Number of parity shards by number of data shards in the group, minus one
    parity: Vec<usize>,
    /// Codecs by number of data shards in the group, minus one, created as needed
    codecs: Vec<Option<Arc<ReedSolomon>>>,
    claims: Claims,
    /// Groups with data shards that are yet to be encoded, oldest first
    pending: Vec<Pending>,
    /// Whether a group has been started since the flusher was last told
    started_group: bool,
    /// Only the sent counters are used
    stats: Stats,
}

impl Encoder {
    fn new(config: FecConfig) -> Encoder {
        Encoder {
            config,
            parity: parity_table(config.data_shards, config.parity_shards),
            codecs: vec![None; config.data_shards],
            // a random start makes it unlikely that anything else the peer receives, such as a
            // handshake packet, passes for a shard of a recent group
            claims: Claims::Local {
                group: rand::random(),
                count: 0,
            },
            pending: Vec::new(),
            started_group: false,
            stats: Stats::default(),
        }
    }

    /// Takes the group number and index for the next data shard
    fn claim(&mut self) -> (u32, u8) {
        let k = self.config.data_shards;
        match &mut self.claims {
            Claims::Local { group, count } => {
                let claimed = (*group, *count as u8);
                *count += 1;
                if *count == k {
                    *group = group.wrapping_add(1);
                    *count = 0;
                }
                claimed
            }
            #[cfg(target_has_atomic = "64")]
            Claims::Shared(shared) => {
                use std::sync::atomic::Ordering;
                let claims = shared.claims();
                let mut old = claims.load(Ordering::Acquire);
                loop {
                    let (group, count) = ((old >> 32) as u32, old as u32 as usize);
                    let new = if count + 1 >= k {
                        (group.wrapping_add(1) as u64) << 32
                    } else {
                        old + 1
                    };
                    match claims.compare_exchange_weak(
                        old,
                        new,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return (group, count as u8),
                        Err(current) => old = current,
                    }
                }
            }
        }
    }

    /// Takes claims from `shared` from now on, continuing with the current group
    #[cfg(target_has_atomic = "64")]
    fn share(&mut self, shared: Arc<dyn SharedClaims>) {
        let (group, count) = self.current();
        shared.claims().store(
            ((group as u64) << 32) | count as u64,
            std::sync::atomic::Ordering::Release,
        );
        self.claims = Claims::Shared(shared);
    }

    /// The group data shards are taken from, and how many have been taken from it
    fn current(&self) -> (u32, usize) {
        match &self.claims {
            Claims::Local { group, count } => (*group, *count),
            #[cfg(target_has_atomic = "64")]
            Claims::Shared(shared) => {
                let claims = shared.claims().load(std::sync::atomic::Ordering::Acquire);
                ((claims >> 32) as u32, claims as u32 as usize)
            }
        }
    }

    /// Adds data shard `index` of `group`. Returns the group if it is now complete.
    fn insert(
        &mut self,
        group: u32,
        index: u8,
        shard: Vec<u8>,
        now: Instant,
    ) -> Option<ClosedGroup> {
        let k = self.config.data_shards;
        if index as usize >= k {
            return None;
        }

        let pos = match self.pending.iter().position(|p| p.group == group) {
            Some(pos) => pos,
            None => {
                self.pending.push(Pending {
                    group,
                    shards: vec![None; k],
                    present: 0,
                    closed_at: None,
                    started: now,
                });
                self.started_group = true;
                self.pending.len() - 1
            }
        };
        let pending = &mut self.pending[pos];
        if pending.shards[index as usize].is_some() {
            return None;
        }
        pending.shards[index as usize] = Some(shard);
        pending.present += 1;
        self.stats.sent_data += 1;

        self.complete(pos)
    }

    /// Removes and returns the group at `pos` of `pending` if it has all of its data shards
    fn complete(&mut self, pos: usize) -> Option<ClosedGroup> {
        let pending = &self.pending[pos];
        let k = pending.data_shards();
        if pending.present < k || pending.shards[..k].iter().any(Option::is_none) {
            return None;
        }

        let pending = self.pending.remove(pos);
        let m = self.parity[k - 1];
        let codec = self.codecs[k - 1]
            .get_or_insert_with(|| {
                codec(k, m).expect("FEC parameters are validated by parse_ratio")
            })
            .clone();
        self.stats.sent_parity += m as u64;

        Some(ClosedGroup {
            group: pending.group,
            shards: pending
                .shards
                .into_iter()
                .take(k)
                .map(Option::unwrap)
                .collect(),
            codec,
        })
    }

    #[cfg(test)]
    fn group(&self) -> u32 {
        self.current().0
    }

    #[cfg(test)]
    fn set_group(&mut self, group: u32) {
        self.claims = Claims::Local { group, count: 0 };
    }

    /// Turns `buf` (`HEADROOM` bytes followed by the datagram) into a data shard in place.
    /// Returns the group if this closes it.
    fn push(&mut self, buf: &mut [u8], now: Instant) -> Option<ClosedGroup> {
        let (group, index) = self.claim();
        buf[0] = TYPE_DATA;
        buf[1..5].copy_from_slice(&group.to_be_bytes());
        buf[5] = index;
        self.insert(group, index, data_shard(&buf[HEADROOM..]), now)
    }

    /// When the current group has to be flushed, or `None` if it is empty. Data shards that
    /// someone else takes are only known once they arrive.
    fn deadline(&self) -> Option<Instant> {
        let (group, count) = self.current();
        if count == 0 {
            return None;
        }
        self.pending
            .iter()
            .find(|p| p.group == group)
            .map(|p| p.started + self.config.timeout)
    }

    /// Closes the current group if it has not been filled within the timeout. Returns it, unless
    /// it is still missing data shards someone else has taken.
    fn flush_expired(&mut self, now: Instant) -> Option<ClosedGroup> {
        let (group, count) = self.current();
        // forget closed groups whose data shards never arrived
        self.pending
            .retain(|p| p.group == group || p.started + MAX_PENDING_TIME > now);

        let deadline = self.deadline()?;
        if deadline > now {
            return None;
        }
        let closed_at = match &mut self.claims {
            Claims::Local {
                group: local_group,
                count: local_count,
            } => {
                *local_group = local_group.wrapping_add(1);
                *local_count = 0;
                count
            }
            #[cfg(target_has_atomic = "64")]
            Claims::Shared(shared) => {
                use std::sync::atomic::Ordering;
                let old = ((group as u64) << 32) | count as u64;
                let new = (group.wrapping_add(1) as u64) << 32;
                match shared.claims().compare_exchange(
                    old,
                    new,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => count,
                    // filled up or grew in the meantime, try again on the next wake up, which
                    // is right away as the deadline has passed
                    Err(_) => return None,
                }
            }
        };

        let pos = self.pending.iter().position(|p| p.group == group)?;
        self.pending[pos].closed_at = Some(closed_at);
        self.complete(pos)
    }
}

/// A group whose parity shards are yet to be computed, which is left for after the encoder is
/// unlocked
struct ClosedGroup {
    group: u32,
    shards: Vec<Vec<u8>>,
    codec: Arc<ReedSolomon>,
}

impl ClosedGroup {
    /// Returns the parity shards of the group
    fn encode(mut self) -> Vec<Vec<u8>> {
        let (k, m) = (
            self.codec.data_shard_count(),
            self.codec.parity_shard_count(),
        );
        let shard_size = self.shards.iter().map(Vec::len).max().unwrap();
        for shard in &mut self.shards {
            shard.resize(shard_size, 0);
        }

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

        let mut parity_shards: Vec<&mut [u8]> = parity
            .iter_mut()
            .map(|p| &mut p[PARITY_HEADER_LEN..])
            .collect();
        self.codec
            .encode_sep(&self.shards, &mut parity_shards)
            .expect("shards are of equal size");

        parity
    }
}

struct Group {
    id: u32,
    /// `(k, m)`, known once a parity shard has been received
    params: Option<(usize, usize)>,
    /// Data shards, not padded yet
    data: Vec<(u8, Vec<u8>)>,
    parity: Vec<(u8, Vec<u8>)>,
    done: bool,
}

impl Group {
    fn new(id: u32) -> Group {
        Group {
            id,
            params: None,
            data: Vec::new(),
            parity: Vec::new(),
            done: false,
        }
    }

    fn close(&mut self) {
        self.done = true;
        self.data = Vec::new();
        self.parity = Vec::new();
    }

    /// Number of data shards that are missing for good once the group is forgotten
    fn lost(&self) -> usize {
        if self.done {
            return 0;
        }

        let k = match self.params {
            Some((k, _)) => k,
            // without parity shards, only the data shards before the last one received are known
            None => self
                .data
                .iter()
                .map(|&(i, _)| i as usize + 1)
                .max()
                .unwrap_or(0),
        };
        k.saturating_sub(self.data.len())
    }
}

/// Whether groups `a` and `b` are less than `MAX_GROUPS` apart, accounting for wrap-around
fn near(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32).unsigned_abs() < MAX_GROUPS as u32
}

struct Decoder {
    /// Recent groups by group number modulo `MAX_GROUPS`
    slots: Vec<Option<Group>>,
    /// Newest group seen, those `MAX_GROUPS` or more before it are forgotten
    newest: Option<u32>,
    /// `(group, index, shard)` of the last data shard too far from the recent groups to keep
    /// track of
    far: Option<(u32, u8, Vec<u8>)>,
    codecs: Codecs,
    /// Only the received counters are used
    stats: Stats,
    /// Whether it has been reported that the peer does not seem to use FEC
    mismatch_reported: bool,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder {
            slots: std::iter::repeat_with(|| None).take(MAX_GROUPS).collect(),
            newest: None,
            far: None,
            codecs: Codecs::default(),
            stats: Stats::default(),
            mismatch_reported: false,
        }
    }
}

impl Decoder {
    /// Stores `group` in `slot`, forgetting the group it held
    fn replace(&mut self, slot: usize, group: Option<Group>) {
        if let Some(forgotten) = std::mem::replace(&mut self.slots[slot], group) {
            self.stats.lost += forgotten.lost() as u64;
        }
    }

    /// Returns `true` once, when the peer does not seem to use FEC
    fn mismatch(&mut self) -> bool {
        if self.mismatch_reported
            || self.stats.received_data > 0
            || self.stats.invalid < MISMATCH_FRAMES
        {
            return false;
        }

        self.mismatch_reported = true;
        true
    }

    /// Returns the slot of group `id`, or `None` if it is too far from the recent groups to keep
    /// track of. Groups are tracked relative to the newest one, so a late parity shard of a
    /// forgotten group can neither take the place of a recent group, nor recover datagrams that
    /// were already delivered.
    fn slot(&mut self, id: u32) -> Option<usize> {
        let newest = *self.newest.get_or_insert(id);
        if !near(newest, id) {
            return None;
        }
        if (id.wrapping_sub(newest) as i32) > 0 {
            self.newest = Some(id);
        }

        // the slot holds either this group, or one that is no longer recent
        let slot = id as usize % MAX_GROUPS;
        if self.slots[slot].as_ref().is_none_or(|g| g.id != id) {
            self.replace(slot, Some(Group::new(id)));
        }

        Some(slot)
    }

    /// Returns the slot of the group of a data shard, like [`Decoder::slot`].
    ///
    /// A data shard far from the recent groups is either stray, or the peer moved on after more
    /// than `MAX_GROUPS` groups were lost in a row. As the peer never delays data shards, the
    /// latter is assumed once the next data shard is close to it, and the decoder starts over.
    fn data_slot(&mut self, id: u32, index: u8, datagram: &[u8]) -> Option<usize> {
        if let Some(slot) = self.slot(id) {
            self.far = None;
            return Some(slot);
        }

        match self.far.take() {
            Some((far, far_index, far_shard)) if near(far, id) => {
                for slot in 0..MAX_GROUPS {
                    self.replace(slot, None);
                }
                self.newest = Some(id);
                // it was forwarded already, so it must not be recovered again
                let slot = self.slot(far).unwrap();
                let group = self.slots[slot].as_mut().unwrap();
                group.data.push((far_index, far_shard));
                self.slot(id)
            }
            _ => {
                self.far = Some((id, index, data_shard(datagram)));
                None
            }
        }
    }

    /// Decodes a frame received from the peer. Returns the datagram to forward right away if
    /// `frame` is a new data shard, and the group if lost data shards can now be recovered.
    fn feed<'a>(&mut self, frame: &'a [u8]) -> (Option<&'a [u8]>, Option<Recovery>) {
        if frame.len() < HEADROOM {
            self.stats.invalid += 1;
            return (None, None);
        }

        let id = u32::from_be_bytes(frame[1..5].try_into().unwrap());
        let index = frame[5];

        match frame[0] {
            TYPE_DATA => {
                let payload = &frame[HEADROOM..];
                let (new, recovery) = self.data(id, index, payload);
                (new.then_some(payload), recovery)
            }
            TYPE_PARITY => {
                if frame.len() < PARITY_HEADER_LEN + LEN_PREFIX {
                    self.stats.invalid += 1;
                    return (None, None);
                }
                let (k, m) = (frame[6] as usize, frame[7] as usize);
                if k == 0 || m == 0 || (index as usize) < k || index as usize >= k + m {
                    self.stats.invalid += 1;
                    return (None, None);
                }

                let parity = &frame[PARITY_HEADER_LEN..];
                let Some(slot) = self.slot(id) else {
                    self.stats.late_parity += 1;
                    return (None, None);
                };
                let group = self.slots[slot].as_mut().unwrap();
                if group.done {
                    // no longer needed, e.g. as no data shard was lost, but it did arrive
                    self.stats.received_parity += 1;
                    return (None, None);
                }
                if group.params.is_some_and(|p| p != (k, m))
                    || group
                        .parity
                        .iter()
                        .any(|(i, p)| *i == index || p.len() != parity.len())
                {
                    return (None, None);
                }

                group.params = Some((k, m));
                group.parity.push((index, parity.to_vec()));
                self.stats.received_parity += 1;
                (None, self.recovery(slot))
            }
            _ => {
                self.stats.invalid += 1;
                (None, None)
            }
        }
    }

    /// Takes data shard `index` of group `id`. Returns whether it is new, and the group if lost
    /// data shards can now be recovered.
    fn data(&mut self, id: u32, index: u8, payload: &[u8]) -> (bool, Option<Recovery>) {
        let Some(slot) = self.data_slot(id, index, payload) else {
            // FEC can not help with this one, but it is still worth forwarding
            self.stats.received_data += 1;
            return (true, None);
        };
        let group = self.slots[slot].as_mut().unwrap();
        if group.done || group.data.iter().any(|(i, _)| *i == index) {
            return (false, None);
        }

        group.data.push((index, data_shard(payload)));
        self.stats.received_data += 1;
        (true, self.recovery(slot))
    }

    /// Closes the group in `slot` once it has either all of its data shards, or enough shards to
    /// recover the lost ones, which it then returns
    fn recovery(&mut self, slot: usize) -> Option<Recovery> {
        let group = self.slots[slot].as_mut().unwrap();
        let (k, m) = group.params?;

        if group.data.len() >= k {
            // nothing lost
            group.close();
            return None;
        }
        if group.data.len() + group.parity.len() < k {
            return None;
        }

        let data = std::mem::take(&mut group.data);
        let parity = std::mem::take(&mut group.parity);
        group.close();
        self.stats.recovered += (k - data.len()) as u64;

        Some(Recovery {
            data,
            parity,
            codec: self.codecs.get(k, m)?,
        })
    }
}

/// A group with enough shards to recover its lost data shards, which is left for after the
/// decoder is unlocked
struct Recovery {
    data: Vec<(u8, Vec<u8>)>,
    parity: Vec<(u8, Vec<u8>)>,
    codec: Arc<ReedSolomon>,
}

impl Recovery {
    /// Appends the datagrams of the lost data shards to `recovered`
    fn run(self, recovered: &mut Vec<Vec<u8>>) {
        let (k, m) = (
            self.codec.data_shard_count(),
            self.codec.parity_shard_count(),
        );
        let shard_size = self.parity[0].1.len();
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; k + m];
        for (index, mut shard) in self.data {
            if index as usize >= k || shard.len() > shard_size {
                return;
            }

            shard.resize(shard_size, 0);
            shards[index as usize] = Some(shard);
        }
        for (index, parity) in self.parity {
            shards[index as usize] = Some(parity);
        }

        let missing: Vec<usize> = (0..k).filter(|&i| shards[i].is_none()).collect();
        if self.codec.reconstruct_data(&mut shards).is_err() {
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
    /// The connection, for logging
    name: String,
    encoder: Mutex<Encoder>,
    decoder: Mutex<Decoder>,
    pacer: Mutex<Pacer>,
    interval: Duration,
    stats_interval: Duration,
    /// Wakes the flusher when a group starts or parity shards are queued
    wake: Notify,
}

impl Fec {
    /// Creates the FEC state of the connection `name`, which is only used for logging.
    pub fn new(config: FecConfig, name: String) -> Fec {
        Fec {
            name,
            encoder: Mutex::new(Encoder::new(config)),
            decoder: Mutex::new(Decoder::default()),
            pacer: Mutex::new(Pacer::default()),
            interval: config.interval,
            stats_interval: config.stats_interval,
            wake: Notify::new(),
        }
    }

    fn stats(&self) -> Stats {
        let sent = self.encoder.lock().unwrap().stats;
        let received = self.decoder.lock().unwrap().stats;
        Stats {
            sent_data: sent.sent_data,
            sent_parity: sent.sent_parity,
            ..received
        }
    }

    /// Sends parity shards of groups that have not been filled within the timeout, and parity
    /// shards that were spread out once they are due, and logs statistics periodically. Returns
    /// once `sock` fails.
    pub async fn run_flusher(&self, sock: &Socket) {
        let mut out = Vec::new();
        let mut reported = Stats::default();
        let mut next_report =
            (!self.stats_interval.is_zero()).then(|| Instant::now() + self.stats_interval);
        loop {
            let deadline = self.encoder.lock().unwrap().deadline();
            let due = self.pacer.lock().unwrap().next();
            match deadline.into_iter().chain(due).chain(next_report).min() {
                // a group closing or parity being queued may need an earlier wake up
                Some(next) => tokio::select! {
                    _ = time::sleep_until(next.into()) => {}
                    _ = self.wake.notified() => {}
                },
                None => self.wake.notified().await,
            }

            let now = Instant::now();
            let closed = self.encoder.lock().unwrap().flush_expired(now);
            if let Some(closed) = closed {
                out.extend(self.schedule(closed.encode(), now));
            }
            self.pacer.lock().unwrap().pop_due(now, &mut out);
            for p in out.drain(..) {
                if sock.send(&p).await.is_none() {
                    return;
                }
            }

            if next_report.is_some_and(|t| t <= now) {
                let stats = self.stats();
                let period = stats.since(&reported);
                if !period.is_empty() {
                    info!(
                        "FEC stats of {} in the last {:?}: {}",
                        self.name, self.stats_interval, period
                    );
                }
                reported = stats;
                next_report = Some(now + self.stats_interval);
            }
        }
    }

    /// `K`, the number of data shards in a full group
    pub fn data_shards(&self) -> usize {
        self.encoder.lock().unwrap().config.data_shards
    }

    /// Takes group numbers and data shard indexes from `shared` from now on, which someone else
    /// sending data shards takes from as well. The data shards they send have to be passed to
    /// [`Fec::sent_elsewhere`].
    #[cfg(target_has_atomic = "64")]
    pub fn share_claims(&self, shared: Arc<dyn SharedClaims>) {
        self.encoder.lock().unwrap().share(shared);
    }

    /// Takes the data shard `index` of `group` that has been sent elsewhere, with the shared
    /// claims. Returns the parity shards to send right away.
    pub fn sent_elsewhere(&self, group: u32, index: u8, datagram: &[u8]) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let closed = {
            let mut encoder = self.encoder.lock().unwrap();
            let closed = encoder.insert(group, index, data_shard(datagram), now);
            if std::mem::take(&mut encoder.started_group) {
                self.wake.notify_one();
            }
            closed
        };
        closed.map_or_else(Vec::new, |closed| self.schedule(closed.encode(), now))
    }

    /// Takes the data shard `index` of `group` that has been received and forwarded elsewhere.
    /// Returns the datagrams of the data shards this recovers.
    pub fn received_elsewhere(&self, group: u32, index: u8, datagram: &[u8]) -> Vec<Vec<u8>> {
        let (_, recovery) = self.decoder.lock().unwrap().data(group, index, datagram);
        let mut recovered = Vec::new();
        if let Some(recovery) = recovery {
            recovery.run(&mut recovered);
        }
        recovered
    }

    /// Takes a parity frame received elsewhere. Returns the datagrams of the data shards this
    /// recovers.
    pub fn parity_received_elsewhere(&self, frame: &[u8]) -> Vec<Vec<u8>> {
        let (_, recovery) = self.decoder.lock().unwrap().feed(frame);
        let mut recovered = Vec::new();
        if let Some(recovery) = recovery {
            recovery.run(&mut recovered);
        }
        recovered
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

impl Drop for Fec {
    /// Logs the statistics of the whole connection once it is closed
    fn drop(&mut self) {
        let stats = self.stats();
        if !stats.is_empty() {
            info!("FEC stats of {} in total: {}", self.name, stats);
        }
    }
}

/// Sends the datagram `buf[SEND_HEADROOM..]` to the peer, encoding it with FEC if enabled.
/// The first `SEND_HEADROOM` bytes of `buf` are scratch space for the headers, which are written
/// in front of the datagram rather than copying it.
///
/// A return of `None` means `sock` must be closed.
pub async fn send_datagram(sock: &Socket, fec: Option<&Fec>, buf: &mut [u8]) -> Option<()> {
    let Some(fec) = fec else {
        return sock.send_in_place(buf, SEND_HEADROOM).await;
    };

    let now = Instant::now();
    let closed = {
        let mut encoder = fec.encoder.lock().unwrap();
        let closed = encoder.push(&mut buf[MAX_HEADER_LEN..], now);
        if std::mem::take(&mut encoder.started_group) {
            fec.wake.notify_one();
        }
        closed
    };

    sock.send_in_place(buf, MAX_HEADER_LEN).await?;
    if let Some(closed) = closed {
        for p in fec.schedule(closed.encode(), now) {
            sock.send(&p).await?;
        }
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

    let (datagram, recovery) = {
        let mut decoder = fec.decoder.lock().unwrap();
        let decoded = decoder.feed(frame);
        if decoder.mismatch() {
            warn!(
                "{} received {} packets that are not FEC frames and no FEC data packet, \
                 is --fec enabled on the peer?",
                fec.name, decoder.stats.invalid
            );
        }
        decoded
    };
    if let Some(datagram) = datagram {
        udp_sock.send(datagram).await?;
    }
    if let Some(recovery) = recovery {
        recovery.run(recovered);
        for datagram in recovered.drain(..) {
            udp_sock.send(&datagram).await?;
        }
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
            stats_interval: Duration::ZERO,
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
            let closed = encoder.push(&mut buf, now);
            frames.push(buf);
            frames.extend(closed.into_iter().flat_map(ClosedGroup::encode));
        }
        let closed = encoder.flush_expired(now + Duration::from_secs(1));
        frames.extend(closed.into_iter().flat_map(ClosedGroup::encode));
        frames
    }

    /// Feeds `frame` into `decoder` and appends recovered datagrams to `recovered`. Returns the
    /// datagram to forward right away.
    fn feed(decoder: &mut Decoder, frame: &[u8], recovered: &mut Vec<Vec<u8>>) -> Option<Vec<u8>> {
        let (datagram, recovery) = decoder.feed(frame);
        if let Some(recovery) = recovery {
            recovery.run(recovered);
        }
        datagram.map(<[u8]>::to_vec)
    }

    /// Feeds `frames` into `decoder` and returns every datagram it delivers
    fn decode<'a>(
        decoder: &mut Decoder,
        frames: impl Iterator<Item = &'a Vec<u8>>,
    ) -> Vec<Vec<u8>> {
        let mut delivered = Vec::new();
        let mut recovered = Vec::new();
        for f in frames {
            delivered.extend(feed(decoder, f, &mut recovered));
            delivered.append(&mut recovered);
        }
        delivered
    }

    fn sorted(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        v.sort();
        v
    }

    fn parse_args(args: &[&str]) -> Result<Option<FecConfig>, clap::Error> {
        clap::Command::new("phantun")
            .args(super::args())
            .try_get_matches_from(std::iter::once("phantun").chain(args.iter().copied()))
            .map(|m| FecConfig::from_matches(&m))
    }

    #[test]
    fn parse_config() {
        assert_eq!(parse_args(&[]).unwrap(), None);
        assert_eq!(
            parse_args(&["--fec", "10:3"]).unwrap(),
            Some(FecConfig {
                data_shards: 10,
                parity_shards: 3,
                timeout: Duration::from_millis(8),
                interval: Duration::ZERO,
                stats_interval: Duration::from_secs(300),
            })
        );
        assert_eq!(
            parse_args(&[
                "--fec=20:2",
                "--fec-timeout",
                "0",
                "--fec-interval=1000",
                "--fec-stats=0"
            ])
            .unwrap(),
            Some(FecConfig {
                data_shards: 20,
                parity_shards: 2,
                timeout: Duration::ZERO,
                interval: Duration::from_secs(1),
                stats_interval: Duration::ZERO,
            })
        );

        for bad in [
            &["--fec", "10"][..],
            &["--fec", "0:3"],
            &["--fec", "10:0"],
            &["--fec", "200:57"],
            &["--fec", "10:3", "--fec-timeout", "1001"],
            &["--fec", "10:3", "--fec-interval", "1001"],
            &["--fec", "10:3", "--fec-interval", "-1"],
            &["--fec", "10:3", "--fec-stats", "86401"],
            // other options without --fec
            &["--fec-timeout", "8"],
            &["--fec-interval", "20"],
            &["--fec-stats", "60"],
        ] {
            assert!(parse_args(bad).is_err(), "{bad:?}");
        }
        assert!(parse_args(&["--fec", "200:56"]).is_ok());
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
        let fec = Fec::new(config(10, 3), "test".into());
        let now = Instant::now();
        assert_eq!(fec.schedule(fake_parity(0, 3), now), fake_parity(0, 3));
        assert_eq!(fec.pacer.lock().unwrap().next(), None);
    }

    #[test]
    fn parity_spread_over_interval() {
        let fec = Fec::new(
            FecConfig {
                interval: Duration::from_millis(20),
                ..config(10, 3)
            },
            "test".into(),
        );
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
        let fec = Fec::new(
            FecConfig {
                interval: Duration::from_millis(20),
                ..config(1, 2)
            },
            "test".into(),
        );
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
        assert!(encoder.push(&mut buf, now).is_none());
        assert_eq!(encoder.deadline(), Some(now + Duration::from_millis(10)));
        assert!(
            encoder
                .flush_expired(now + Duration::from_millis(9))
                .is_none()
        );
        let closed = encoder.flush_expired(now + Duration::from_millis(10));
        assert_eq!(closed.unwrap().encode().len(), 2);
        assert_eq!(encoder.deadline(), None);
    }

    #[test]
    fn encoder_codec_per_group_size() {
        // more group sizes than the previous cache of 64 codecs held
        let mut encoder = Encoder::new(config(70, 2));
        let now = Instant::now();
        let mut codecs = Vec::new();
        for round in 0..2 {
            for n in 1..=70 {
                let mut closed = None;
                for _ in 0..n {
                    let mut buf = vec![0u8; HEADROOM + 10];
                    closed = encoder.push(&mut buf, now);
                }
                let closed = closed
                    .or_else(|| encoder.flush_expired(now + Duration::from_secs(1)))
                    .unwrap();
                assert_eq!(closed.codec.data_shard_count(), n);
                if round == 0 {
                    codecs.push(closed.codec);
                } else {
                    assert!(Arc::ptr_eq(&codecs[n - 1], &closed.codec));
                }
            }
        }
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
            assert!(feed(&mut decoder, f, &mut recovered).is_none());
        }

        // parity claiming a length larger than the shard
        assert!(
            feed(
                &mut decoder,
                &[1, 0, 0, 0, 1, 1, 1, 1, 0xff, 0xff],
                &mut recovered
            )
            .is_none()
        );
        assert!(recovered.is_empty());

        // data shard larger than the parity shards of its group
        assert!(
            feed(
                &mut decoder,
                &[1, 0, 0, 0, 2, 2, 2, 1, 0, 0],
                &mut recovered
            )
            .is_none()
        );
        assert!(feed(&mut decoder, &[0, 0, 0, 0, 2, 0, 1, 2, 3], &mut recovered).is_some());
        assert!(recovered.is_empty());
    }

    #[test]
    fn bounded_group_state() {
        let mut decoder = Decoder::default();
        let mut recovered = Vec::new();
        for id in 0..(MAX_GROUPS as u32 * 4) {
            let mut frame = vec![0u8; HEADROOM + 10];
            frame[1..5].copy_from_slice(&id.to_be_bytes());
            assert!(feed(&mut decoder, &frame, &mut recovered).is_some());
        }
        assert_eq!(decoder.slots.len(), MAX_GROUPS);
        let mut ids: Vec<u32> = decoder
            .slots
            .iter()
            .map(|g| g.as_ref().unwrap().id)
            .collect();
        ids.sort();
        assert_eq!(
            ids,
            (MAX_GROUPS as u32 * 3..MAX_GROUPS as u32 * 4).collect::<Vec<_>>()
        );
    }

    /// Encodes `groups * k` datagrams, which make `groups` groups when `k` is the size of a full
    /// group, or a single group closed by timeout for 1 datagram. Returns the frames and datagrams.
    fn groups(encoder: &mut Encoder, groups: usize, k: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let datagrams: Vec<_> = (0..groups * k).map(datagram).collect();
        (encode(encoder, &datagrams), datagrams)
    }

    #[test]
    fn late_parity_of_forgotten_group() {
        let mut encoder = Encoder::new(config(10, 3));
        let mut decoder = Decoder::default();

        // a single datagram closed by timeout, whose 2 parity shards are delayed
        let (first, _) = groups(&mut encoder, 1, 1);
        let delivered = decode(&mut decoder, first[..1].iter());
        assert_eq!(delivered, [datagram(0)]);

        // the peer moves on by more groups than are remembered
        let (frames, datagrams) = groups(&mut encoder, MAX_GROUPS, 10);
        assert_eq!(decode(&mut decoder, frames.iter()), datagrams);

        // the late parity must neither deliver the datagram again nor displace a recent group
        let newest = decoder.newest;
        assert!(decode(&mut decoder, first[1..].iter()).is_empty());
        assert_eq!(decoder.newest, newest);
        assert!(
            decoder
                .slots
                .iter()
                .flatten()
                .all(|g| near(newest.unwrap(), g.id))
        );
    }

    #[test]
    fn stray_frame_before_first_group() {
        let mut encoder = Encoder::new(config(10, 3));
        // what a zeroed handshake packet looks like, and the group it would have collided with
        encoder.set_group(12345);
        let (frames, datagrams) = groups(&mut encoder, 2, 10);

        // one data shard of the second group is lost
        let handshake = vec![0u8; 64];
        let delivered = decode(
            &mut Decoder::default(),
            std::iter::once(&handshake).chain(
                frames
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != 15)
                    .map(|(_, f)| f),
            ),
        );
        assert_eq!(delivered[0], handshake[HEADROOM..]);
        assert_eq!(sorted(delivered[1..].to_vec()), sorted(datagrams));
    }

    #[test]
    fn stray_frame_between_groups() {
        let mut encoder = Encoder::new(config(10, 3));
        let (first, mut datagrams) = groups(&mut encoder, 1, 10);
        let (second, more) = groups(&mut encoder, 1, 10);
        datagrams.extend(more);

        let mut stray = vec![0u8; HEADROOM + 10];
        stray[1..5].copy_from_slice(&encoder.group().wrapping_add(1 << 31).to_be_bytes());
        let frames: Vec<_> = first
            .iter()
            .chain([&stray])
            .chain(second.iter().skip(1))
            .collect();
        let delivered = decode(&mut Decoder::default(), frames.into_iter());

        // the stray shard is forwarded, and the second group is still recovered
        assert_eq!(
            delivered
                .iter()
                .filter(|d| **d == stray[HEADROOM..])
                .count(),
            1
        );
        let delivered: Vec<_> = delivered
            .into_iter()
            .filter(|d| *d != stray[HEADROOM..])
            .collect();
        assert_eq!(sorted(delivered), sorted(datagrams));
    }

    #[test]
    fn resync_after_long_outage() {
        let mut encoder = Encoder::new(config(10, 3));
        let mut decoder = Decoder::default();
        let (frames, datagrams) = groups(&mut encoder, 1, 10);
        assert_eq!(decode(&mut decoder, frames.iter()), datagrams);

        // everything is lost for a while
        encoder.set_group(encoder.group().wrapping_add(MAX_GROUPS as u32 * 2));

        // the first data shard after the outage is forwarded, and the second one resyncs the decoder
        let (frames, datagrams) = groups(&mut encoder, 2, 10);
        let delivered = decode(
            &mut decoder,
            frames
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != 18)
                .map(|(_, f)| f),
        );
        assert_eq!(sorted(delivered), sorted(datagrams));
        assert_eq!(decoder.newest, Some(encoder.group().wrapping_sub(1)));
    }

    #[test]
    fn group_number_wrap_around() {
        let mut encoder = Encoder::new(config(10, 3));
        encoder.set_group(u32::MAX - 1);
        let (frames, datagrams) = groups(&mut encoder, 4, 10);
        assert_eq!(encoder.group(), 2);

        // one data shard lost in every group
        let delivered = decode(
            &mut Decoder::default(),
            frames
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 13 != 4)
                .map(|(_, f)| f),
        );
        assert_eq!(sorted(delivered), sorted(datagrams));
    }

    #[test]
    fn statistics() {
        let mut encoder = Encoder::new(config(10, 3));
        let mut decoder = Decoder::default();

        // 1: 3 data shards lost and recovered
        // 2: 4 data shards lost for good, which its parity shards tell
        // 3: 3 data shards and all parity shards lost, of which 2 data shards are known
        // 4: nothing lost, so the parity shards are not needed
        let (old, _) = groups(&mut encoder, 4, 10);
        let lost = [0, 1, 2, 13, 14, 15, 16, 26, 28, 35, 36, 37, 38];
        let frames = old.iter().enumerate().filter(|(i, _)| !lost.contains(i));
        decode(&mut decoder, frames.map(|(_, f)| f));

        // the peer moves on, which forgets all of them
        encoder.set_group(encoder.group().wrapping_add(MAX_GROUPS as u32 * 2));
        let (new, _) = groups(&mut encoder, 1, 10);
        decode(&mut decoder, new[..2].iter());

        // a late parity shard, a duplicate and a packet that is not a FEC frame
        let delivered = decode(&mut decoder, [&old[36], &new[1], &vec![4; 32]].into_iter());
        assert!(delivered.is_empty());

        assert_eq!(
            encoder.stats,
            Stats {
                sent_data: 50,
                sent_parity: 15,
                ..Stats::default()
            }
        );
        assert_eq!(
            decoder.stats,
            Stats {
                received_data: 7 + 6 + 7 + 10 + 2,
                received_parity: 3 + 3 + 3,
                recovered: 3,
                lost: 4 + 2,
                late_parity: 1,
                invalid: 1,
                ..Stats::default()
            }
        );
    }

    #[test]
    fn statistics_report() {
        let stats = Stats {
            sent_data: 1000,
            sent_parity: 300,
            received_data: 990,
            received_parity: 297,
            recovered: 9,
            lost: 1,
            late_parity: 0,
            invalid: 2,
        };
        assert_eq!(
            stats.to_string(),
            "sent 1000 data + 300 parity packets, received 990 data + 297 parity packets, \
             recovered 9 and lost 1 data packets (1.00% loss before FEC, 0.100% after), \
             2 invalid packets"
        );
        assert_eq!(stats.since(&stats), Stats::default());
        assert!(stats.since(&stats).is_empty());
    }

    #[test]
    fn peer_without_fec() {
        // WireGuard packets start with their type, 1 to 4, followed by 3 zero bytes
        let mut decoder = Decoder::default();
        let mut mismatch = 0;
        for i in 0..20u8 {
            let mut packet = vec![1 + i % 4, 0, 0, 0];
            packet.extend((0..60).map(|b| b ^ i));
            feed(&mut decoder, &packet, &mut Vec::new());
            mismatch += decoder.mismatch() as usize;
        }
        assert_eq!(mismatch, 1);

        // a handshake packet in front of FEC frames is fine
        let mut decoder = Decoder::default();
        let (frames, _) = groups(&mut Encoder::new(config(10, 3)), 3, 10);
        for f in std::iter::once(&vec![0x16; 3]).chain(frames.iter()) {
            feed(&mut decoder, f, &mut Vec::new());
            assert!(!decoder.mismatch());
        }
    }

    /// Claims shared with something else taking data shards, here the test standing in for the
    /// eBPF program
    #[cfg(target_has_atomic = "64")]
    struct TestClaims(std::sync::atomic::AtomicU64);

    #[cfg(target_has_atomic = "64")]
    impl SharedClaims for TestClaims {
        fn claims(&self) -> &std::sync::atomic::AtomicU64 {
            &self.0
        }
    }

    /// Claims like udp_to_tcp in offload.bpf.c does
    #[cfg(target_has_atomic = "64")]
    fn kernel_claim(claims: &TestClaims, k: usize) -> (u32, u8) {
        use std::sync::atomic::Ordering;
        let old = claims.0.load(Ordering::Acquire);
        let (group, count) = ((old >> 32) as u32, old as u32 as usize);
        let new = if count + 1 >= k {
            (group.wrapping_add(1) as u64) << 32
        } else {
            old + 1
        };
        claims
            .0
            .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
            .unwrap();
        (group, count as u8)
    }

    #[cfg(target_has_atomic = "64")]
    #[test]
    fn shared_claims() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let (k, m) = (10, 4);
        let mut rng = StdRng::seed_from_u64(1);
        let mut encoder = Encoder::new(config(k, m));
        let start = Instant::now();
        let mut now = start;

        // the group in progress carries over, as when a connection is registered after its
        // first datagram was sent
        let mut sent = vec![datagram(10_000)];
        let mut buf = vec![0u8; HEADROOM];
        buf.extend_from_slice(&sent[0]);
        assert!(encoder.push(&mut buf, now).is_none());
        let mut frames = vec![buf];
        let shared = Arc::new(TestClaims(std::sync::atomic::AtomicU64::new(0)));
        encoder.share(shared.clone());

        // datagrams sent by the kernel, whose records arrive later and out of order
        let mut records = Vec::new();
        for i in 0..2000 {
            let d = datagram(i);
            sent.push(d.clone());
            if rng.random_bool(0.7) {
                let (group, index) = kernel_claim(&shared, k);
                let mut frame = vec![TYPE_DATA];
                frame.extend_from_slice(&group.to_be_bytes());
                frame.push(index);
                frame.extend_from_slice(&d);
                frames.push(frame);
                records.push((group, index, d));
            } else {
                let mut buf = vec![0u8; HEADROOM];
                buf.extend_from_slice(&d);
                let closed = encoder.push(&mut buf, now);
                frames.push(buf);
                frames.extend(closed.into_iter().flat_map(ClosedGroup::encode));
            }

            // deliver some of the records, in random order
            while !records.is_empty() && rng.random_bool(0.6) {
                let (group, index, d) = records.swap_remove(rng.random_range(0..records.len()));
                let closed = encoder.insert(group, index, data_shard(&d), now);
                frames.extend(closed.into_iter().flat_map(ClosedGroup::encode));
            }

            // time passes, sometimes long enough to close a group early
            now += Duration::from_millis(if rng.random_bool(0.05) { 20 } else { 1 });
            let closed = encoder.flush_expired(now);
            frames.extend(closed.into_iter().flat_map(ClosedGroup::encode));
        }
        for (group, index, d) in records.drain(..) {
            let closed = encoder.insert(group, index, data_shard(&d), now);
            frames.extend(closed.into_iter().flat_map(ClosedGroup::encode));
        }
        now += Duration::from_millis(20);
        frames.extend(
            encoder
                .flush_expired(now)
                .into_iter()
                .flat_map(ClosedGroup::encode),
        );
        assert!(encoder.pending.is_empty());

        // every group can lose up to M of its shards
        let mut lost_per_group: HashMap<u32, usize> = HashMap::new();
        let received: Vec<_> = frames
            .into_iter()
            .filter(|f| {
                let group = u32::from_be_bytes(f[1..5].try_into().unwrap());
                let lost = lost_per_group.entry(group).or_default();
                // the lost data shards of a group have to be recoverable with its parity shards,
                // which is only checked by delivering everything below
                if *lost < 2 && rng.random_bool(0.1) {
                    *lost += 1;
                    false
                } else {
                    true
                }
            })
            .collect();

        let mut decoder = Decoder::default();
        assert_eq!(sorted(decode(&mut decoder, received.iter())), sorted(sent));
        assert_eq!(decoder.stats.lost, 0);
    }
}
