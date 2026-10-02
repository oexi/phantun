// SPDX-License-Identifier: MIT OR Apache-2.0
//
// In-kernel data path for established Phantun connections.
//
// Phantun normally moves every packet through user space: fake TCP packets are read from the Tun
// interface and their payload is sent from a UDP socket, and datagrams received on that socket are
// written to the Tun interface as fake TCP packets. Once user space has registered a connection in
// the maps below, these programs do the same conversion inside the kernel, in one of two ways.
//
// Like mimic, on the network interface the fake TCP packets of the connection use, which leaves
// out the Tun interface, routing and netfilter:
//
// - nic_ingress_eth and nic_ingress_l3, on ingress of the network interface (with an Ethernet
//   header or without one), turn fake TCP packets from the other end into the UDP datagrams
//   Phantun would have sent. The other packets of the connection, which Phantun handles, are
//   passed to it on the Tun interface, with the addresses they would have had after netfilter's
//   NAT, which never sees them.
// - udp_to_tcp, on ingress of the loopback interface, turns datagrams that local applications
//   send to Phantun into the fake TCP packets Phantun would have written to the Tun interface, with
//   the addresses they would have had after NAT, and sends them out of the network interface.
// - tun_ingress, on ingress of the Tun interface, does the same with the fake TCP packets Phantun
//   writes itself, such as ACKs, RSTs and FEC parity shards.
//
// User space finds the addresses after NAT in conntrack. Where the network interface cannot be
// used, the conversion happens on the Tun interface, and the kernel routes and NATs the packets:
//
// - tcp_to_udp, on egress of the Tun interface, turns fake TCP packets that the kernel is about to
//   hand to Phantun into the UDP datagrams Phantun would have sent, and
// - udp_to_tcp turns datagrams into the fake TCP packets that enter the Tun interface as if
//   Phantun had written them.
//
// The IP version may differ between both sides, e.g. fake TCP over IPv6 for an application on
// 127.0.0.1.
//
// The converting programs are classifiers without direct action. A converted packet runs the
// filter's csum action, which computes the checksums in software and clears CHECKSUM_PARTIAL (eBPF
// cannot move the offloaded checksum from the UDP to the TCP header), and is then redirected by the
// `redirect` program of a later filter: to loopback ingress, so the datagram is received like one
// sent by Phantun, to Tun ingress, so the packet is routed like one written by Phantun, or out of
// the network interface, with the Ethernet header from the neighbour table.
//
// Anything else, such as handshakes, RSTs, GRO/GSO packets, IP options or fragments, is left
// alone and keeps taking the user space path. The sequence numbers live in an array that user
// space maps into memory, so both paths share them.
//
// With FEC, udp_to_tcp also prepends the FEC header of a data shard, taking the group and index
// from the same shared memory as user space, and tcp_to_udp removes it. Both pass a copy of the
// datagram to user space through the `records` ring buffer, so that it can compute the parity
// shards of the groups sent, and recover lost data shards of the groups received. Parity shards
// received are only passed on as records and then dropped, so that user space gets everything in
// order. When the ring buffer is full, the packet takes the user space path.
//
// The file only needs clang to build, it does not use any system headers.

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#undef bpf_htons
#undef bpf_ntohs
#undef bpf_htonl
#undef bpf_ntohl
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#define bpf_htonl(x) (x)
#define bpf_ntohl(x) (x)
#endif

// From include/uapi/linux/bpf.h, up to the last field used here
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
	union {
		void *flow_keys;
		__u64 : 64;
	} __attribute__((aligned(8)));
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	union {
		void *sk;
		__u64 : 64;
	} __attribute__((aligned(8)));
	__u32 gso_size;
};

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_F_NO_PREALLOC (1U << 0)
#define BPF_F_MMAPABLE (1U << 10)
#define BPF_F_INGRESS (1ULL << 0)
#define BPF_ADJ_ROOM_NET 0
#define BPF_F_PSEUDO_HDR (1ULL << 4)


#define TC_ACT_UNSPEC (-1)
#define TC_ACT_SHOT 2
// Classifier results without direct action
#define CLS_NO_MATCH 0
#define CLS_MATCH (-1)

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define LOOPBACK_IFINDEX 1

// The fake TCP header is 12 bytes longer than the UDP header
#define HEADER_DIFF 12
// Phantun's MAX_PACKET_LEN, larger packets are left to user space, which handles them as before
#define MAX_PACKET_LEN 1500
// Must match fake-tcp's MAX_UNACKED_LEN
#define MAX_UNACKED_LEN (128 * 1024 * 1024)
// Must match fake-tcp's ACK_HOLD
#define ACK_HOLD (32 * 1024)

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len,
				   __u64 flags) = (void *)9;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)23;
static long (*bpf_skb_change_proto)(struct __sk_buff *skb, __be16 proto, __u64 flags) = (void *)31;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)26;
static long (*bpf_skb_change_head)(struct __sk_buff *skb, __u32 len, __u64 flags) = (void *)43;
static long (*bpf_skb_adjust_room)(struct __sk_buff *skb, __s32 len_diff, __u32 mode,
				   __u64 flags) = (void *)50;
static long (*bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to,
				   __u64 size) = (void *)10;
static long (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to,
				   __u64 flags) = (void *)11;
static __s64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size,
			      __u32 seed) = (void *)28;
static long (*bpf_redirect_neigh)(__u32 ifindex, void *params, int plen, __u64 flags) = (void *)152;
static long (*bpf_check_mtu)(void *ctx, __u32 ifindex, __u32 *mtu_len, __s32 len_diff,
			     __u64 flags) = (void *)163;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;

struct iphdr {
	__u8 ver_ihl;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__be32 saddr;
	__be32 daddr;
};

struct ipv6hdr {
	__be32 ver_tc_flow;
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__be32 saddr[4];
	__be32 daddr[4];
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u8 doff;
	__u8 flags;
	__be16 window;
	__u16 check;
	__be16 urg_ptr;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__u16 check;
};

// The structures below are shared with user space (src/offload/imp.rs)

// Addresses and ports of a packet. IPv4 addresses only use the first word, the rest is zero.
struct tuple {
	__be32 saddr[4];
	__be32 daddr[4];
	__be16 sport;
	__be16 dport;
	__u32 family; // 4 or 6
};

// The fake TCP packets of the connection are on a network interface rather than the Tun interface
#define CONV_NIC 1
// The fake TCP packets received are all left to user space, as the other end may send them merged
// by GRO, which cannot be converted, and they have to stay in order
#define CONV_USER_RX 2

// What a matching packet is turned into
struct conversion {
	struct tuple out;
	// For fake TCP packets on a network interface: their addresses on the Tun interface, for the
	// packets passed to user space there
	struct tuple tun;
	__u32 slot; // index into `states`
	// Identifies the connection in records, when it uses FEC, otherwise 0
	__u32 fec_id;
	// K, the number of data shards in a full FEC group
	__u32 fec_data_shards;
	// CONV_*
	__u32 flags;
	// Where the packets go: for udp_conversions and tun_conversions the network interface with
	// CONV_NIC and the Tun interface otherwise, for tcp_conversions with CONV_NIC the Tun
	// interface, for the packets passed to user space
	__u32 ifindex;
	__u32 _pad;
};

// The state of a connection. It occupies a whole cache line, so that connections do not slow
// each other down.
struct state {
	__u32 seq;
	__u32 ack;
	__u32 last_ack;
	// STATE_FLAG_*
	__u32 flags;
	// The IP ID of the next fake TCP packet over IPv4, of which the lower 16 bits are used. It goes
	// up by one for each, as the receiving kernel only merges packets with GRO when their IDs go up
	// one by one, or stay the same, and only passes merged packets with the same IDs to the Tun
	// interface after splitting them again.
	__u32 ip_id;
	__u32 _pad1;
	// Packets converted by udp_to_tcp and tcp_to_udp. They are only used to see whether there is
	// any traffic and for statistics, so the increments do not need to be atomic.
	__u64 tx;
	__u64 rx;
	// The FEC group (upper half) and the number of data shards in it so far (lower half), shared
	// with user space, which also sends data shards and closes groups that are not filled in time
	__u64 fec_claims;
	__u64 _pad2[2];
};

// FEC frames for user space, which computes parity shards from data shards sent, and recovers
// lost data shards from those received
#define RECORD_SENT_DATA 0
#define RECORD_RECEIVED_DATA 1
#define RECORD_RECEIVED_PARITY 2

struct record {
	__u32 fec_id;
	__u32 kind;
	// The group and index of a data shard
	__u32 group;
	__u16 index;
	// The length of the datagram of a data shard, or of the whole parity frame
	__u16 len;
	__u8 data[MAX_PACKET_LEN];
};

// The FEC header in front of data shards, see src/fec.rs
#define FEC_DATA_HEADER_LEN 6
#define FEC_TYPE_DATA 0
#define FEC_TYPE_PARITY 1

// fake-tcp's FLAG_PSH: the other end has completed the handshake, so data packets carry PSH
#define STATE_FLAG_PSH 1
// fake-tcp's FLAG_MERGE: the other end takes packets merged by GRO, so data packets never carry
// PSH, and their acknowledgement number only moves on every ACK_HOLD bytes, as GRO only merges
// packets with the same one
#define STATE_FLAG_MERGE 2

#define MAX_CONNECTIONS 4096

// Fake TCP packets that tcp_to_udp and nic_ingress_* turn into datagrams, by their addresses
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2 * MAX_CONNECTIONS);
	__type(key, struct tuple);
	__type(value, struct conversion);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} tcp_conversions SEC(".maps");

// Datagrams that udp_to_tcp turns into fake TCP packets, by their addresses
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CONNECTIONS);
	__type(key, struct tuple);
	__type(value, struct conversion);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} udp_conversions SEC(".maps");

// Fake TCP packets of user space that tun_ingress sends out of a network interface, by their
// addresses on the Tun interface. Only `out` and `ifindex` are used.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CONNECTIONS);
	__type(key, struct tuple);
	__type(value, struct conversion);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} tun_conversions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CONNECTIONS);
	__type(key, __u32);
	__type(value, struct state);
	__uint(map_flags, BPF_F_MMAPABLE);
} states SEC(".maps");

// User space sets the size, which is the minimum without FEC
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} records SEC(".maps");

// A converted packet is marked in the control block for the redirect program. The control block
// is not cleared between layers, so the mark is long enough to never match by accident. The
// value differs from that of earlier versions, as their redirect programs may be on the same
// loopback interface, and do not know all the flags.
#define MARK_MAGIC 0x70686e32 // "phn2"
// Push an Ethernet header for loopback, the packet has none
#define MARK_PUSH_ETH 1
// Replace the Ethernet header with one for loopback
#define MARK_LOOPBACK_ETH 2
// Redirect to egress rather than ingress
#define MARK_EGRESS 4
// Redirect to egress, with the Ethernet header from the neighbour table
#define MARK_NEIGH 8

static __always_inline void mark(struct __sk_buff *skb, __u32 ifindex, __u32 flags)
{
	skb->cb[0] = MARK_MAGIC;
	skb->cb[1] = ifindex;
	skb->cb[2] = flags;
	skb->cb[3] = ~(MARK_MAGIC ^ ifindex ^ flags);
}

struct headers {
	__u32 family;
	__u32 l3_off;
	__u32 l4_off;
	__u32 len; // of the IP packet
	__u8 protocol;
	struct tuple tuple;
};

// Parses an IP header without options or fragmentation at `off`
static __always_inline int parse_ip(struct __sk_buff *skb, __u32 off, struct headers *h)
{
	h->l3_off = off;
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr ip;
		if (bpf_skb_load_bytes(skb, off, &ip, sizeof(ip)))
			return -1;
		if (ip.ver_ihl != 0x45 || (ip.frag_off & bpf_htons(IP_MF | IP_OFFSET)))
			return -1;
		h->family = 4;
		h->l4_off = off + sizeof(ip);
		h->len = bpf_ntohs(ip.tot_len);
		h->protocol = ip.protocol;
		h->tuple.saddr[0] = ip.saddr;
		h->tuple.daddr[0] = ip.daddr;
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6;
		if (bpf_skb_load_bytes(skb, off, &ip6, sizeof(ip6)))
			return -1;
		if ((ip6.ver_tc_flow & bpf_htonl(0xf0000000)) != bpf_htonl(0x60000000))
			return -1;
		h->family = 6;
		h->l4_off = off + sizeof(ip6);
		h->len = sizeof(ip6) + bpf_ntohs(ip6.payload_len);
		h->protocol = ip6.nexthdr;
		__builtin_memcpy(h->tuple.saddr, ip6.saddr, sizeof(ip6.saddr));
		__builtin_memcpy(h->tuple.daddr, ip6.daddr, sizeof(ip6.daddr));
	} else {
		return -1;
	}
	h->tuple.family = h->family;

	// Trailing bytes after the IP packet would end up in the converted payload
	if (h->len + off != skb->len)
		return -1;
	return 0;
}

// Parses a TCP packet at `off`, and looks up its conversion in `map`
static __always_inline struct conversion *lookup_tcp(struct __sk_buff *skb, __u32 off, void *map,
						     struct headers *h, struct tcphdr *tcp)
{
	if (parse_ip(skb, off, h) || h->protocol != IPPROTO_TCP)
		return 0;
	if (bpf_skb_load_bytes(skb, h->l4_off, tcp, sizeof(*tcp)))
		return 0;
	h->tuple.sport = tcp->source;
	h->tuple.dport = tcp->dest;
	return bpf_map_lookup_elem(map, &h->tuple);
}

static __always_inline __u32 ip_header_len(__u32 family)
{
	return family == 4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
}

// Writes the IP header of a converted packet. `payload_len` is the length after the IP header.
static __always_inline int write_ip(struct __sk_buff *skb, __u32 off, const struct tuple *out,
				    __u8 protocol, __u32 payload_len, __u16 id)
{
	if (out->family == 4) {
		struct iphdr ip = {
			.ver_ihl = 0x45,
			.tot_len = bpf_htons(sizeof(ip) + payload_len),
			.id = bpf_htons(id),
			.frag_off = bpf_htons(IP_DF),
			.ttl = 64,
			.protocol = protocol,
			// computed by the csum action
			.check = 0,
			.saddr = out->saddr[0],
			.daddr = out->daddr[0],
		};
		return bpf_skb_store_bytes(skb, off, &ip, sizeof(ip), 0);
	}

	struct ipv6hdr ip6 = {
		.ver_tc_flow = bpf_htonl(0x60000000),
		.payload_len = bpf_htons(payload_len),
		.nexthdr = protocol,
		.hop_limit = 64,
	};
	__builtin_memcpy(ip6.saddr, out->saddr, sizeof(ip6.saddr));
	__builtin_memcpy(ip6.daddr, out->daddr, sizeof(ip6.daddr));
	return bpf_skb_store_bytes(skb, off, &ip6, sizeof(ip6), 0);
}

// Changes the addresses and ports of the TCP packet `h` to those of `to`, of the same IP version.
// The checksums are updated incrementally, which works for any checksum state, including the
// partial checksum of GRO packets.
static __always_inline int rewrite_tcp(struct __sk_buff *skb, const struct headers *h,
				       const struct tuple *to)
{
	__be16 old_ports[2] = {h->tuple.sport, h->tuple.dport};
	__be16 new_ports[2] = {to->sport, to->dport};
	__u32 check_off = h->l4_off + __builtin_offsetof(struct tcphdr, check);
	__s64 diff;

	if (h->family == 4) {
		__be32 old[2] = {h->tuple.saddr[0], h->tuple.daddr[0]};
		__be32 new[2] = {to->saddr[0], to->daddr[0]};
		diff = bpf_csum_diff(old, sizeof(old), new, sizeof(new), 0);
		if (diff < 0 ||
		    bpf_skb_store_bytes(skb, h->l3_off + __builtin_offsetof(struct iphdr, saddr), new,
					sizeof(new), 0) ||
		    bpf_l3_csum_replace(skb, h->l3_off + __builtin_offsetof(struct iphdr, check), 0,
					diff, 0))
			return -1;
	} else {
		__be32 old[8], new[8];
		__builtin_memcpy(old, h->tuple.saddr, 16);
		__builtin_memcpy(old + 4, h->tuple.daddr, 16);
		__builtin_memcpy(new, to->saddr, 16);
		__builtin_memcpy(new + 4, to->daddr, 16);
		diff = bpf_csum_diff(old, sizeof(old), new, sizeof(new), 0);
		if (diff < 0 ||
		    bpf_skb_store_bytes(skb, h->l3_off + __builtin_offsetof(struct ipv6hdr, saddr),
					new, sizeof(new), 0))
			return -1;
	}
	// The addresses are part of the pseudo header, the ports are not
	if (bpf_l4_csum_replace(skb, check_off, 0, diff, BPF_F_PSEUDO_HDR))
		return -1;
	diff = bpf_csum_diff((__be32 *)old_ports, sizeof(old_ports), (__be32 *)new_ports,
			     sizeof(new_ports), 0);
	if (diff < 0 || bpf_skb_store_bytes(skb, h->l4_off, new_ports, sizeof(new_ports), 0) ||
	    bpf_l4_csum_replace(skb, check_off, 0, diff, 0))
		return -1;
	return 0;
}

// Makes room for the headers of the converted packet: changes the IP version if the conversion
// does, and grows or shrinks the room after the IP header by `l4_diff`. Returns -1 if the packet
// is unchanged, and 1 if it has been changed but the room could not be made.
static __always_inline int make_room(struct __sk_buff *skb, const struct headers *h,
				     const struct tuple *out, __s32 l4_diff)
{
	if (out->family != h->family &&
	    bpf_skb_change_proto(skb, bpf_htons(out->family == 4 ? ETH_P_IP : ETH_P_IPV6), 0))
		return -1;
	if (bpf_skb_adjust_room(skb, l4_diff, BPF_ADJ_ROOM_NET, 0))
		return out->family != h->family ? 1 : -1;
	return 0;
}

// Copies `len` bytes at `off` of the packet into a record
static __always_inline int load_record(struct __sk_buff *skb, __u32 off, struct record *rec,
				       __u32 len)
{
	// clang would drop or merge these checks, as it knows the bounds already, but the verifier
	// needs them on the register that is passed. The upper bound comes first: the verifier only
	// excludes 0 at an end of the range, and when `len` comes from a subtraction, its range may
	// go around 0 until then, as on Linux 7.2, which tracks it as [-5, 1494] rather than as any
	// 32-bit value.
	asm volatile("" : "+r"(len));
	if (len > sizeof(rec->data))
		return -1;
	asm volatile("" : "+r"(len));
	if (len == 0)
		return -1;
	rec->len = len;
	return bpf_skb_load_bytes(skb, off, rec->data, len);
}

// Takes the next index in the current FEC group, closing it if this fills it
static __always_inline int fec_claim(struct state *s, __u32 data_shards, __u32 *group,
				     __u32 *index)
{
	for (int i = 0; i < 8; i++) {
		__u64 old = *(volatile __u64 *)&s->fec_claims;
		__u32 g = old >> 32, n = (__u32)old;
		__u64 new = n + 1 >= data_shards ? ((__u64)(g + 1)) << 32 : old + 1;
		if (__sync_val_compare_and_swap(&s->fec_claims, old, new) == old) {
			*group = g;
			*index = n;
			return 0;
		}
	}
	return -1;
}

// Turns the fake TCP packet `h` of the connection `c` into its datagram, which the redirect
// program then passes to loopback, with `mark_flags`. Returns CLS_NO_MATCH, leaving the packet
// unchanged, when it is not a plain data packet that can be converted.
static __always_inline int convert_tcp(struct __sk_buff *skb, struct headers *h,
				       const struct tcphdr *tcp, const struct conversion *c,
				       __u32 mark_flags)
{
	// Only plain data packets, everything else is for user space. PSH is optional, see fake-tcp's
	// FLAG_PSH.
	if ((c->flags & CONV_USER_RX) || skb->gso_size || tcp->doff != 0x50 || (tcp->flags & ~TCP_FLAG_PSH) != TCP_FLAG_ACK)
		return CLS_NO_MATCH;
	__u32 payload_len = h->len - (h->l4_off - h->l3_off) - sizeof(*tcp);
	if (payload_len == 0 || payload_len > MAX_PACKET_LEN)
		return CLS_NO_MATCH;

	__u32 slot = c->slot;
	struct state *s = bpf_map_lookup_elem(&states, &slot);
	if (!s)
		return CLS_NO_MATCH;

	__u32 ack = bpf_ntohl(tcp->seq) + payload_len;
	// Too much has not been acknowledged, let user space send an ACK
	if (ack - *(volatile __u32 *)&s->last_ack > MAX_UNACKED_LEN)
		return CLS_NO_MATCH;

	struct tuple out = c->out;
	__u32 payload_off = h->l4_off + sizeof(*tcp);
	// Bytes removed in front of the UDP header: the first 12 bytes of the TCP header, its last 8
	// bytes become the UDP header
	__u32 strip = HEADER_DIFF;
	struct record *rec = 0;

	if (c->fec_id) {
		__u8 fec[FEC_DATA_HEADER_LEN];
		if (payload_len <= sizeof(fec) || bpf_skb_load_bytes(skb, payload_off, fec, sizeof(fec)))
			return CLS_NO_MATCH;
		if (fec[0] != FEC_TYPE_DATA && fec[0] != FEC_TYPE_PARITY)
			return CLS_NO_MATCH;
		// When there is no room, user space gets the packet itself
		rec = bpf_ringbuf_reserve(&records, sizeof(*rec), 0);
		if (!rec)
			return CLS_NO_MATCH;
		rec->fec_id = c->fec_id;

		if (fec[0] == FEC_TYPE_PARITY) {
			// Only user space needs it, it is passed on whole and the packet is dropped
			rec->kind = RECORD_RECEIVED_PARITY;
			rec->group = 0;
			rec->index = 0;
			if (load_record(skb, payload_off, rec, payload_len)) {
				bpf_ringbuf_discard(rec, 0);
				return CLS_NO_MATCH;
			}
			bpf_ringbuf_submit(rec, 0);
			*(volatile __u32 *)&s->ack = ack;
			s->rx++;
			mark(skb, 0, 0);
			return CLS_MATCH;
		}

		rec->kind = RECORD_RECEIVED_DATA;
		rec->group = ((__u32)fec[1] << 24) | ((__u32)fec[2] << 16) | ((__u32)fec[3] << 8) | fec[4];
		rec->index = fec[5];
		payload_len -= sizeof(fec);
		if (load_record(skb, payload_off + sizeof(fec), rec, payload_len)) {
			bpf_ringbuf_discard(rec, 0);
			return CLS_NO_MATCH;
		}
		strip += sizeof(fec);
	}

	int ret = make_room(skb, h, &out, -(__s32)strip);
	if (ret < 0) {
		if (rec)
			bpf_ringbuf_discard(rec, 0);
		return CLS_NO_MATCH;
	}

	struct udphdr udp = {
		.source = out.sport,
		.dest = out.dport,
		.len = bpf_htons(sizeof(udp) + payload_len),
		// The csum action computes it, except for IPv4, where 0 means there is no checksum and
		// the action skips it. The original checksum has already been verified, if at all.
		.check = out.family == 6 ? 0xffff : 0,
	};
	// The packet has already been changed, so it can only be dropped if these fail. That does not
	// happen though, as the bytes exist.
	if (ret || write_ip(skb, h->l3_off, &out, IPPROTO_UDP, sizeof(udp) + payload_len, 0) ||
	    bpf_skb_store_bytes(skb, h->l3_off + ip_header_len(out.family), &udp, sizeof(udp), 0)) {
		// Not delivered, so it may still be recovered
		if (rec)
			bpf_ringbuf_discard(rec, 0);
		mark(skb, 0, 0);
		return CLS_MATCH;
	}

	if (rec)
		bpf_ringbuf_submit(rec, 0);
	*(volatile __u32 *)&s->ack = ack;
	// Data from the other end means it has completed the handshake, see Socket::recv_batch
	if (!(*(volatile __u32 *)&s->flags & (STATE_FLAG_PSH | STATE_FLAG_MERGE)))
		__sync_fetch_and_or(&s->flags, STATE_FLAG_PSH);
	s->rx++;
	mark(skb, LOOPBACK_IFINDEX, mark_flags);
	return CLS_MATCH;
}

// Egress of the Tun interface, so the packet starts with the IP header
SEC("classifier/tcp_to_udp")
int tcp_to_udp(struct __sk_buff *skb)
{
	struct headers h = {};
	struct tcphdr tcp;

	struct conversion *c = lookup_tcp(skb, 0, &tcp_conversions, &h, &tcp);
	if (!c)
		return CLS_NO_MATCH;
	return convert_tcp(skb, &h, &tcp, c, MARK_PUSH_ETH);
}

// Ingress of a network interface whose packets start at `l3_off`
static __always_inline int nic_ingress(struct __sk_buff *skb, __u32 l3_off, __u32 mark_flags)
{
	struct headers h = {};
	struct tcphdr tcp;

	struct conversion *c = lookup_tcp(skb, l3_off, &tcp_conversions, &h, &tcp);
	if (!c || !(c->flags & CONV_NIC))
		return CLS_NO_MATCH;
	int ret = convert_tcp(skb, &h, &tcp, c, mark_flags);
	if (ret != CLS_NO_MATCH)
		return ret;

	// Anything else goes to user space, on the Tun interface. Passing it up the stack instead
	// would not work, as conntrack has not seen the packets in between, so it might consider it
	// invalid and leave it alone rather than NAT it.
	if (c->tun.family != h.family)
		return CLS_NO_MATCH;
	if (rewrite_tcp(skb, &h, &c->tun))
		mark(skb, 0, 0);
	else
		mark(skb, c->ifindex, MARK_EGRESS);
	return CLS_MATCH;
}

SEC("classifier/nic_ingress_eth")
int nic_ingress_eth(struct __sk_buff *skb)
{
	return nic_ingress(skb, ETH_HLEN, MARK_LOOPBACK_ETH);
}

SEC("classifier/nic_ingress_l3")
int nic_ingress_l3(struct __sk_buff *skb)
{
	return nic_ingress(skb, 0, MARK_PUSH_ETH);
}

// Ingress of the loopback interface, so the packet starts with an Ethernet header
SEC("classifier/udp_to_tcp")
int udp_to_tcp(struct __sk_buff *skb)
{
	struct headers h = {};
	struct udphdr udp;

	if (skb->gso_size || parse_ip(skb, ETH_HLEN, &h) || h.protocol != IPPROTO_UDP)
		return CLS_NO_MATCH;
	if (bpf_skb_load_bytes(skb, h.l4_off, &udp, sizeof(udp)))
		return CLS_NO_MATCH;
	h.tuple.sport = udp.source;
	h.tuple.dport = udp.dest;

	struct conversion *c = bpf_map_lookup_elem(&udp_conversions, &h.tuple);
	if (!c)
		return CLS_NO_MATCH;

	struct tuple out = c->out;
	__u32 fec_id = c->fec_id, data_shards = c->fec_data_shards;
	__u32 ifindex = c->ifindex, nic = c->flags & CONV_NIC;
	__u32 grow = HEADER_DIFF + (fec_id ? FEC_DATA_HEADER_LEN : 0);
	__u32 payload_len = h.len - (h.l4_off - h.l3_off) - sizeof(udp);
	if (bpf_ntohs(udp.len) != sizeof(udp) + payload_len)
		return CLS_NO_MATCH;
	// Phantun drops empty datagrams and truncates large ones, leave both to it
	__u32 tcp_len = ip_header_len(out.family) + sizeof(udp) + grow + payload_len;
	if (payload_len == 0 || tcp_len > MAX_PACKET_LEN)
		return CLS_NO_MATCH;
	// The kernel would drop packets too large for the network interface without telling anyone,
	// let user space send them, so that they are handled like before
	__u32 mtu_len = tcp_len;
	if (nic && bpf_check_mtu(skb, ifindex, &mtu_len, 0, 0))
		return CLS_NO_MATCH;

	__u32 slot = c->slot;
	struct state *s = bpf_map_lookup_elem(&states, &slot);
	if (!s)
		return CLS_NO_MATCH;

	struct record *rec = 0;
	if (fec_id) {
		// When there is no room, user space gets the datagram itself
		rec = bpf_ringbuf_reserve(&records, sizeof(*rec), 0);
		if (!rec)
			return CLS_NO_MATCH;
		rec->fec_id = fec_id;
		rec->kind = RECORD_SENT_DATA;
		if (load_record(skb, h.l4_off + sizeof(udp), rec, payload_len)) {
			bpf_ringbuf_discard(rec, 0);
			return CLS_NO_MATCH;
		}
	}

	int ret = make_room(skb, &h, &out, grow);
	if (ret < 0) {
		if (rec)
			bpf_ringbuf_discard(rec, 0);
		return CLS_NO_MATCH;
	}

	__u32 group = 0, index = 0;
	// Without room, or very busy, give up on this one
	if (ret || (rec && fec_claim(s, data_shards, &group, &index))) {
		if (rec)
			bpf_ringbuf_discard(rec, 0);
		mark(skb, 0, 0);
		return CLS_MATCH;
	}

	__u32 seq = __sync_fetch_and_add(&s->seq, payload_len + grow - HEADER_DIFF);
	__u32 ack = *(volatile __u32 *)&s->ack;
	__u32 state_flags = *(volatile __u32 *)&s->flags;
	// Like Socket::data_ack, also when the number went back, as reordered packets do
	if (state_flags & STATE_FLAG_MERGE) {
		__u32 last_ack = *(volatile __u32 *)&s->last_ack;
		if ((__s32)(ack - last_ack) < ACK_HOLD)
			ack = last_ack;
	}
	*(volatile __u32 *)&s->last_ack = ack;

	struct tcphdr tcp = {
		.source = out.sport,
		.dest = out.dport,
		.seq = bpf_htonl(seq),
		.ack_seq = bpf_htonl(ack),
		.doff = 0x50,
		// Like Phantun, see fake-tcp's FLAG_PSH and FLAG_MERGE
		.flags = TCP_FLAG_ACK | (state_flags & STATE_FLAG_PSH ? TCP_FLAG_PSH : 0),
		.window = 0xffff,
		// computed by the csum action
		.check = 0,
	};
	__u32 l4_off = h.l3_off + ip_header_len(out.family);
	int err = write_ip(skb, h.l3_off, &out, IPPROTO_TCP,
			   sizeof(tcp) + grow - HEADER_DIFF + payload_len,
			   out.family == 4 ? __sync_fetch_and_add(&s->ip_id, 1) : 0) ||
		  bpf_skb_store_bytes(skb, l4_off, &tcp, sizeof(tcp), 0);
	if (rec) {
		__u8 fec[FEC_DATA_HEADER_LEN] = {
			FEC_TYPE_DATA, group >> 24, group >> 16, group >> 8, group, index,
		};
		err = err || bpf_skb_store_bytes(skb, l4_off + sizeof(tcp), fec, sizeof(fec), 0);
		// The index is taken, so the parity shards have to cover it even if it is not sent
		rec->group = group;
		rec->index = index;
		bpf_ringbuf_submit(rec, 0);
	}
	if (err) {
		mark(skb, 0, 0);
		return CLS_MATCH;
	}

	s->tx++;
	mark(skb, ifindex, nic ? MARK_NEIGH : 0);
	return CLS_MATCH;
}

// Writes an Ethernet header for loopback at the start of the packet, whose MAC addresses are all
// zero, like those of loopback, so that the packet is not taken for one to another host
static __always_inline int store_loopback_eth(struct __sk_buff *skb)
{
	__u8 eth[ETH_HLEN] = {};
	__be16 proto = skb->protocol;
	__builtin_memcpy(&eth[12], &proto, sizeof(proto));
	return bpf_skb_store_bytes(skb, 0, eth, sizeof(eth), 0);
}

// Ingress of the Tun interface, direct action. Sends the fake TCP packets that Phantun writes for
// connections on a network interface out of it, as udp_to_tcp does with those it converts.
SEC("classifier/tun_ingress")
int tun_ingress(struct __sk_buff *skb)
{
	struct headers h = {};
	struct tcphdr tcp;

	struct conversion *c = lookup_tcp(skb, 0, &tun_conversions, &h, &tcp);
	if (!c || c->out.family != h.family)
		return TC_ACT_UNSPEC;
	__u32 ifindex = c->ifindex, mtu_len = h.len;
	if (bpf_check_mtu(skb, ifindex, &mtu_len, 0, 0))
		return TC_ACT_UNSPEC;
	if (rewrite_tcp(skb, &h, &c->out) || bpf_skb_change_head(skb, ETH_HLEN, 0) ||
	    store_loopback_eth(skb))
		return TC_ACT_SHOT;
	return bpf_redirect_neigh(ifindex, 0, 0, 0);
}

// Direct action, after the converting filters
SEC("classifier/redirect")
int redirect(struct __sk_buff *skb)
{
	__u32 ifindex = skb->cb[1], flags = skb->cb[2];

	if (skb->cb[0] != MARK_MAGIC || skb->cb[3] != ~(MARK_MAGIC ^ ifindex ^ flags))
		return TC_ACT_UNSPEC;
	skb->cb[0] = 0;

	if (flags & (MARK_PUSH_ETH | MARK_LOOPBACK_ETH)) {
		if ((flags & MARK_PUSH_ETH) && bpf_skb_change_head(skb, ETH_HLEN, 0))
			return TC_ACT_SHOT;
		if (store_loopback_eth(skb))
			return TC_ACT_SHOT;
	}

	// A failed conversion has no target
	if (!ifindex)
		return TC_ACT_SHOT;
	if (flags & MARK_NEIGH)
		return bpf_redirect_neigh(ifindex, 0, 0, 0);
	return bpf_redirect(ifindex, flags & MARK_EGRESS ? 0 : BPF_F_INGRESS);
}

char _license[] SEC("license") = "Dual MIT/GPL";
