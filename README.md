# Phantun

A lightweight and fast UDP to TCP obfuscator.

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/dndx/phantun/rust.yml)
![docs.rs](https://img.shields.io/docsrs/fake-tcp)

# Table of Contents

* [Phantun](#phantun)
* [Latest release](#latest-release)
* [Overview](#overview)
* [Usage](#usage)
    * [1. Enable Kernel IP forwarding](#1-enable-kernel-ip-forwarding)
    * [2. Add required firewall rules](#2-add-required-firewall-rules)
        * [Client](#client)
            * [Using nftables](#using-nftables)
            * [Using iptables](#using-iptables)
        * [Server](#server)
            * [Using nftables](#using-nftables)
            * [Using iptables](#using-iptables)
    * [3. Run Phantun binaries as non-root (Optional)](#3-run-phantun-binaries-as-non-root-optional)
    * [4. Start Phantun daemon](#4-start-phantun-daemon)
        * [Server](#server)
        * [Client](#client)
* [MTU overhead](#mtu-overhead)
    * [MTU calculation for WireGuard](#mtu-calculation-for-wireguard)
* [Forward error correction (FEC)](#forward-error-correction-fec)
    * [Choosing `K:M`](#choosing-km)
    * [Burst loss](#burst-loss)
    * [Statistics](#statistics)
* [eBPF data path](#ebpf-data-path)
    * [On the network interface](#on-the-network-interface)
    * [Requirements](#requirements)
    * [Changes to the host](#changes-to-the-host)
* [Packets in batches (GSO and GRO)](#packets-in-batches-gso-and-gro)
    * [Merged packets](#merged-packets)
* [Version compatibility](#version-compatibility)
* [Documentations](#documentations)
* [Performance](#performance)
* [Future plans](#future-plans)
* [Compariation to udp2raw](#compariation-to-udp2raw)
* [License](#license)

# Latest release

[v0.8.1](https://github.com/dndx/phantun/releases/tag/v0.8.1)

<details>
  <summary>MIPS architecture support for Phantun</summary>

  [Rust only provides Tier 3 supports for MIPS based platforms](https://github.com/rust-lang/compiler-team/issues/648)
since 2023. Phantun's MIPS build are therefore built using nightly Rust toolchain and provided on a best effort basis only.
</details>

# Overview

Phantun is a project that obfuscated UDP packets into TCP connections. It aims to
achieve maximum performance with minimum processing and encapsulation overhead.

It is commonly used in environments where UDP is blocked/throttled but TCP is allowed through.

Phantun simply converts a stream of UDP packets into obfuscated TCP stream packets. The TCP stack
used by Phantun is designed to pass through most L3/L4 stateful/stateless firewalls/NAT
devices. It will **not** be able to pass through L7 proxies.
However, the advantage of this approach is that none of the common UDP over TCP performance killer
such as retransmissions and flow control will occur. The underlying UDP properties such as
out-of-order delivery are fully preserved even if the connection ends up looking like a TCP
connection from the perspective of firewalls/NAT devices.

Phantun means Phantom TUN, as it is an obfuscator for UDP traffic that does just enough work
to make it pass through stateful firewall/NATs as TCP packets.

Phantun is written in 100% safe Rust. It has been optimized extensively to scale well on multi-core
systems and has no issue saturating all available CPU resources on a fast connection.
See the [Performance](#performance) section for benchmarking results.

![Phantun benchmark results](images/phantun-vs-udp2raw-benchmark-result.png)
![Traffic flow diagram](images/traffic-flow.png)

# Usage

For the example below, it is assumed that **Phantun Server** listens for incoming Phantun Client connections at
port `4567` (the `--local` option for server), and it forwards UDP packets to UDP server at `127.0.0.1:1234`
(the `--remote` option for server).

It is also assumed that **Phantun Client** listens for incoming UDP packets at
`127.0.0.1:1234` (the `--local` option for client) and connects to Phantun Server at `10.0.0.1:4567`
(the `--remote` option for client).

Phantun creates TUN interface for both the Client and Server. For **Client**, Phantun assigns itself the IP address
`192.168.200.2` and `fcc8::2` by default.
For **Server**, it assigns `192.168.201.2` and `fcc9::2` by default. Therefore, your Kernel must have
IPv4/IPv6 forwarding enabled and setup appropriate iptables/nftables rules for NAT between your physical
NIC address and Phantun's Tun interface address.

You may customize the name of Tun interface created by Phantun and the assigned addresses. Please
run the executable with `-h` options to see how to change them.

Another way to help understand this network topology (please see the diagram above for an illustration of this topology):

Phantun Client is like a machine with private IP address (`192.168.200.2`/`fcc8::2`) behind a router.
In order for it to reach the Internet, you will need to SNAT the private IP address before it's traffic
leaves the NIC.

Phantun Server is like a server with private IP address (`192.168.201.2`/`fcc9::2`) behind a router.
In order to access it from the Internet, you need to `DNAT` it's listening port on the router
and change the destination IP address to where the server is listening for incoming connections.

In those cases, the machine/iptables running Phantun acts as the "router" that allows Phantun
to communicate with outside using it's private IP addresses.

As of Phantun v0.4.1, IPv6 is fully supported for both TCP and UDP sides.
To specify an IPv6 address, use the following format: `[::1]:1234` with
the command line options. Resolving AAAA record is also supported. Please run the program
with `-h` to see detailed options on how to control the IPv6 behavior.

[Back to TOC](#table-of-contents)

## 1. Enable Kernel IP forwarding

Edit `/etc/sysctl.conf`, add `net.ipv4.ip_forward=1` and run `sudo sysctl -p /etc/sysctl.conf`.

<details>
  <summary>IPv6 specific config</summary>

  `net.ipv6.conf.all.forwarding=1` will need to be set as well.
</details>

[Back to TOC](#table-of-contents)

## 2. Add required firewall rules


### Client

Client simply need SNAT enabled on the physical interface to translate Phantun's address into
one that can be used on the physical network. This can be done simply with masquerade.

Note: change `eth0` to whatever actual physical interface name is

[Back to TOC](#table-of-contents)

#### Using nftables

```
table inet nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        iifname tun0 oif eth0 masquerade
    }
}
```

Note: The above rule uses `inet` as the table family type, so it is compatible with
both IPv4 and IPv6 usage.

[Back to TOC](#table-of-contents)

#### Using iptables

```
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

[Back to TOC](#table-of-contents)

### Server

Server needs to DNAT the TCP listening port to Phantun's TUN interface address.

Note: change `eth0` to whatever actual physical interface name is and `4567` to
actual TCP port number used by Phantun server

[Back to TOC](#table-of-contents)

#### Using nftables

```
table inet nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iif eth0 tcp dport 4567 dnat ip to 192.168.201.2
        iif eth0 tcp dport 4567 dnat ip6 to fcc9::2
    }
}
```

[Back to TOC](#table-of-contents)

#### Using iptables

```
iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 4567 -j DNAT --to-destination 192.168.201.2
ip6tables -t nat -A PREROUTING -p tcp -i eth0 --dport 4567 -j DNAT --to-destination fcc9::2
```

[Back to TOC](#table-of-contents)

## 3. Run Phantun binaries as non-root (Optional)

It is ill-advised to run network facing applications as root user. Phantun can be run fully
as non-root user with the `cap_net_admin` capability, and `cap_bpf` for the
[eBPF data path](#ebpf-data-path).

```
sudo setcap cap_net_admin,cap_bpf=+pe phantun_server
sudo setcap cap_net_admin,cap_bpf=+pe phantun_client
```


[Back to TOC](#table-of-contents)

## 4. Start Phantun daemon

**Note:** Run Phantun executable with `-h` option to see full detailed options.

[Back to TOC](#table-of-contents)

### Server

Note: `4567` is the TCP port Phantun should listen on and must corresponds to the DNAT
rule specified above. `127.0.0.1:1234` is the UDP Server to connect to for new connections.

```
RUST_LOG=info /usr/local/bin/phantun_server --local 4567 --remote 127.0.0.1:1234
```

Or use host name with `--remote`:

```
RUST_LOG=info /usr/local/bin/phantun_server --local 4567 --remote example.com:1234
```

Note: Server by default assigns both IPv4 and IPv6 private address to the Tun interface.
If you do not wish to use IPv6, you can simply skip creating the IPv6 DNAT rule above and
the presence of IPv6 address on the Tun interface should have no side effect to the server.

[Back to TOC](#table-of-contents)

### Client

Note: `127.0.0.1:1234` is the UDP address and port Phantun should listen on. `10.0.0.1:4567` is
the Phantun Server to connect.

```
RUST_LOG=info /usr/local/bin/phantun_client --local 127.0.0.1:1234 --remote 10.0.0.1:4567
```

Or use host name with `--remote`:

```
RUST_LOG=info /usr/local/bin/phantun_client --local 127.0.0.1:1234 --remote example.com:4567
```

<details>
  <summary>IPv6 specific config</summary>

  ```
  RUST_LOG=info /usr/local/bin/phantun_client --local 127.0.0.1:1234 --remote [fdxx::1234]:4567
  ```

  Domain name with AAAA record is also supported.
</details>

[Back to TOC](#table-of-contents)

# MTU overhead

Phantun aims to keep tunneling overhead to the minimum. The overhead compared to a plain UDP packet
is the following (using IPv4 below as an example):

**Standard UDP packet:** `20 byte IP header + 8 byte UDP header = 28 bytes`

**Obfuscated packet:** `20 byte IP header + 20 byte TCP header = 40 bytes`


Note that Phantun does not add any additional header other than IP and TCP headers in order to pass through
stateful packet inspection!

Phantun's additional overhead: `12 bytes`. In other words, when using Phantun, the usable payload for
UDP packet is reduced by 12 bytes. This is the minimum overhead possible when doing such kind
of obfuscation.

![Packet header diagram](images/packet-headers.png)

[Back to TOC](#table-of-contents)

## MTU calculation for WireGuard

For people who use Phantun to tunnel [WireGuard®](https://www.wireguard.com) UDP packets, here are some guidelines on figuring
out the correct MTU to use for your WireGuard interface.

```
WireGuard MTU = Link MTU - IPv4 header (20 bytes) - TCP header (20 bytes) - WireGuard overhead (32 bytes)
```

or

```
WireGuard MTU = Link MTU - IPv6 header (40 bytes) - TCP header (20 bytes) - WireGuard overhead (32 bytes)
```

For example, for a network link with 1500 bytes MTU, the WireGuard interface MTU should be set as:

**IPv4:** `1500 (link MTU) - 20 - 20 - 32 = 1428 bytes`

**IPv6:** `1500 (link MTU) - 40 - 20 - 32 = 1408 bytes`

The resulted Phantun TCP data packet will be 1500 bytes which does not exceed the
interface MTU of 1500.

Please note **Phantun can not function correctly if
the packet size exceeds that of the link MTU**, as Phantun do not perform any IP-fragmentation
and reassembly. For the same reason, Phantun always sets the `DF` (Don't Fragment) bit
in the IP header to prevent intermediate devices performing any fragmentation on the packet.

It is also *strongly recommended* to use the same interface
MTU for both ends of a WireGuard tunnel, or unexpected packet loss may occur and these issues are
generally very hard to troubleshoot.

When [FEC](#forward-error-correction-fec) is enabled, subtract another 10 bytes, e.g.
`1418 bytes` for IPv4 and `1398 bytes` for IPv6 on a 1500 bytes MTU link.

[Back to TOC](#table-of-contents)

# Forward error correction (FEC)

Phantun never retransmits lost packets. On lossy links, FEC can be enabled to recover lost packets
without retransmission, at the cost of extra bandwidth:

```
--fec K:M           after every K packets, send M Reed-Solomon parity packets
--fec-timeout MS    send parity for a partially filled group after MS milliseconds (default: 8, max: 1000)
--fec-interval MS   spread the parity packets of a group over MS milliseconds (default: 0, off, max: 1000)
--fec-stats SECS    log packet statistics of each connection every SECS seconds (default: 300, 0: only when it closes)
```

For every group of `K` packets, the peer can recover any `M` lost packets out of the `K + M`
packets sent. Packets are forwarded as soon as they arrive, so FEC adds no latency when nothing is
lost.

A group that is not filled within `--fec-timeout` is closed early. Small groups are more likely to
lose more than their share of packets, so such a group gets as many parity packets as it needs to
be as resilient as a full group, up to `M`. E.g. with `10:9`, a single packet gets 4 parity
packets. This keeps sparse traffic, such as games or SSH, protected, at the cost of more overhead
when traffic is too slow to fill groups within `--fec-timeout`.

FEC must be enabled on **both** Client and Server, as it changes the payload format. `K:M` controls
the parity sent by each end and may differ per direction, e.g. more parity on the direction with
more loss. Bandwidth overhead is `M / K` when groups are filled, see
[Choosing `K:M`](#choosing-km) for suggestions.

FEC adds a 6 byte header to data packets and parity packets are 10 bytes larger than the largest
packet of their group, so remember to lower the [MTU](#mtu-calculation-for-wireguard) accordingly.

If only one end has FEC enabled, the tunnel does not work, and the end with FEC enabled logs a
warning once it has received a few packets that are not FEC frames.

## Choosing `K:M`

TCP inside the tunnel takes the packets still lost after FEC for congestion and slows down, so the
fewer the better. In a test with one TCP connection (CUBIC) through WireGuard over Phantun, between
network namespaces of a 4 core ARM VM, linked at 200 Mbit/s with 50 ms RTT and random loss each
way, the fastest `K:M` was always the one with the least overhead that left about 1 in 100,000
packets lost (`iperf3`, up and down alike):

| Link loss | Suggested `K:M` | Overhead | Throughput | Former suggestion       |
|-----------|-----------------|----------|------------|-------------------------|
| ~1%       | `30:4`          | 13%      | 157 Mbit/s | `20:2`: 74 Mbit/s       |
| ~2%       | `40:6`          | 15%      | 157 Mbit/s |                         |
| ~3%       | `40:8`          | 20%      | 152 Mbit/s |                         |
| ~5%       | `40:10`         | 25%      | 149 Mbit/s | `10:3`: 31 Mbit/s       |
| ~10%      | `40:16`         | 40%      | 140 Mbit/s | `10:5`: 36 Mbit/s       |
| ~20%      | `40:28`         | 70%      | 130 Mbit/s | `10:9`: 39 Mbit/s       |

Without loss, TCP reached 178 Mbit/s without FEC, but only 2 Mbit/s with 1% loss. With 150 ms RTT,
the same suggestions came out best, or tied.

* Larger groups need less overhead: a group of 40 packets is much less likely to lose more than its
  share than a group of 10. With 1% loss, `40:8` leaves 2 in 10 billion packets lost, `10:2`, with
  the same overhead, 5 in 100,000, which TCP already felt (82 Mbit/s).
* Choose `K:M` for the worst loss of the link, e.g. in the evening. With more loss than a `K:M` is
  meant for, the packets lost after FEC quickly add up, tenfold or more with half as much loss again.
  Adding a parity packet or two leaves room for that.
* The sender of a TCP connection through the tunnel, e.g. a server on the Internet, decides how it
  reacts to loss. BBR mostly ignores it: in the same test, BBR without FEC still reached 168 Mbit/s
  with 1% loss and 140 Mbit/s with 5%, no less than with FEC, which only paid off from about 10%
  (`20:8`: 138 Mbit/s, 118 Mbit/s without).
* A lost packet is only recovered once its group is complete, or after `--fec-timeout` at the
  latest, so larger groups only add latency when traffic is too slow to fill them quickly.
* The parity packets take CPU time in proportion to `M`. On aarch64 and x86_64, Reed-Solomon coding
  uses SIMD and this hardly matters: sending 200 Mbit/s of UDP on the same VM, `10:2`, `20:4` and
  `40:8` all took 1.5 times the CPU time of Phantun without FEC. On x86_64 this needs a CPU with
  AVX2 (Intel Haswell, AMD Excavator or newer), FEC crashes Phantun on older ones. Other
  architectures have no SIMD for it, and the cost grows with `M`: built without SIMD, `10:2` took
  1.8 times, `40:8` 2.4 times and `40:30` 5.3 times as much.

## Burst loss

The parity packets of a group are sent back to back, so on links that lose packets in bursts
rather than randomly, such as poor Wi-Fi or mobile links, a single burst often takes out a whole
group, and more parity does not help. `--fec-interval MS` spreads the parity packets of each group
evenly over `MS` milliseconds instead. The first parity packet is still sent right away, so an
isolated loss is recovered as quickly as before, but a packet lost in a burst may only be recovered
up to `MS` milliseconds later. Data packets are never delayed.

To help, the interval has to be longer than the bursts it should survive, which makes it a
trade-off for latency sensitive traffic such as games: a packet recovered too late may be of no use
anymore. Leave it off on links with random loss, where it only delays recovery. The peer only
remembers the last 256 groups, so keep the interval well below the time it takes to send that many.
Parity packets arriving later are counted as late in the [statistics](#statistics). Like `K:M`, it
only applies to the parity sent by the end it is set on.

Larger groups also ride out short bursts better. With 5% loss in bursts of 4 packets on average,
`10:3` still lost about 3% of the packets, `40:16` about 0.4%, and 0.2% with `--fec-interval 10`.
Against bursts of 20 packets, neither helped much.

## Statistics

Each end logs the packets of every connection every `--fec-stats` seconds, and once more for the
whole connection when it closes, or when phantun is stopped with SIGTERM or SIGINT:

```
FEC stats of (Fake TCP connection from 192.168.201.2:4567 to 10.0.0.2:40000) in the last 300s:
sent 25000 data + 7500 parity packets, received 24130 data + 7270 parity packets, recovered 812 and
lost 3 data packets (3.27% loss before FEC, 0.012% after)
```

The received and recovered packets are those sent by the peer, so the loss is the one of the
direction towards this end, which the peer's `K:M` has to cope with. Raise `M` when packets are
still lost after FEC, and lower it when the loss before FEC is well below what `K:M` is meant for.

Losses are counted once 256 newer groups have arrived, so those of the last moments only show up in
the statistics of the whole connection. Without any of its parity packets, nothing tells how many
data packets a group had. It is then taken to have as many as the last group whose parity packets
arrived, also when a burst of loss takes out every packet of a group, which shows as `N groups lost
entirely`. If they show up often, larger groups or `--fec-interval` may help, see
[Burst loss](#burst-loss).

[Back to TOC](#table-of-contents)

# eBPF data path

Normally, every packet passes through Phantun: it reads the fake TCP packets from the Tun
interface and sends their payload from a UDP socket, and the other way around. On Linux hosts that
support it, Phantun instead lets eBPF programs convert the packets of established connections
inside the kernel, which no longer have to be copied to and from Phantun. This is used
automatically, nothing needs to be configured, and the packets on the wire are the same, so either
end may use it regardless of what the other end does.

In a test with WireGuard over Phantun between two network namespaces of a 4 core ARM VM, linked
through a third one that added the delay and loss, `iperf3` reached, up / down (median of 3 runs):

| Phantun                       | No added delay     | 20 ms RTT           | 20 ms RTT, 1% loss each way, FEC `10:2` |
|-------------------------------|--------------------|---------------------|-----------------------------------------|
| Without eBPF (`--no-ebpf`)    | 1.51 / 1.50 Gbit/s | 1.03 / 1.02 Gbit/s  | 899 / 884 Mbit/s                        |
| With eBPF (the default)       | 1.76 / 1.71 Gbit/s | 1.06 / 1.02 Gbit/s  | 936 / 937 Mbit/s                        |

The veth links split and merged packets like the drivers of real network interfaces, and passed
the packets they received on to other cores (RPS), as the other host would. Without that, the
whole way from the sending WireGuard to the receiving one runs on a single core with eBPF, which
makes it look slower than it is. With no added delay, the VM spent 16.7 s of CPU time per GB
without eBPF and 16.0 s with it. With 20 ms RTT and no loss, something other than Phantun limits
the throughput. TCP inside WireGuard retransmitted nothing there, with or without eBPF; earlier
versions reordered datagrams without eBPF, so it retransmitted about 25000 segments in 10 seconds.

Earlier versions also converted packets on the Tun interface where the network interface could
not be used (`--no-ebpf-nic`), which only reached 1.23 / 1.33 Gbit/s with no added delay, and took
20.6 s of CPU time per GB: the converted packets pass the kernel's forwarding path one by one,
while Phantun passes them [in batches](#packets-in-batches-gso-and-gro). Such connections now pass
through Phantun instead.

With [FEC](#forward-error-correction-fec), the programs convert data shards and pass a copy of
them to Phantun, which computes the parity shards from them and recovers lost data shards, so only
parity shards and recovered datagrams pass through Phantun.

Phantun logs whether it is used, once at startup and then for each connection, with where the
packets are converted:

```
INFO  phantun::offload > eBPF data path enabled
INFO  phantun::offload > Packets of (Fake TCP connection from 192.168.201.2:4567 to 10.0.0.2:40000) are converted by eBPF on eth0
```

With FEC, the second line ends in `, with FEC computed by Phantun`.

Otherwise, the log says why not, and Phantun works as before, e.g. on RouterOS or in containers
without the privileges needed. `--no-ebpf` disables it.

Handshakes and anything unusual still go through Phantun, so the
[firewall rules](#2-add-required-firewall-rules) are needed all the same. To keep the receiving
kernel from merging data packets with GRO, Phantun sets the PSH flag on them, which older versions
ignore, unless the other end takes [merged packets](#merged-packets).

## On the network interface

Like [mimic](https://github.com/hack3ric/mimic), the programs convert the packets on the network
interface the fake TCP connection uses, e.g. `eth0`: fake TCP packets as they arrive, and datagrams
from the application straight into fake TCP packets that leave the interface. These packets skip
the Tun interface, routing and netfilter (conntrack, NAT and the firewall rules), so that only the
handshake passes through them. The packets that Phantun sends itself, such as FEC parity shards,
are sent the same way, and the packets that Phantun receives, such as those merged by GRO, are
passed to it on the Tun interface, with the addresses NAT would have given them.

Phantun finds the network interface the way the kernel forwards the packets from the Tun interface,
and the addresses NAT gave the connection in conntrack, and attaches the programs to the interface
when the first connection uses it. Where this is not possible, the log says why, e.g.

```
INFO  phantun::offload > Packets of (...) pass through Phantun: gre1 is of an unsupported type (778)
```

and the packets of the connection pass through Phantun, in batches. If the kernel rejects the
programs, which is logged at startup, this applies to all connections.

Network interfaces with an Ethernet header are supported, and those without one (`ARPHRD_NONE`,
PPP or raw IP), such as WireGuard. The program on the network interface looks up every TCP packet
entering it in a hash table, which costs other traffic little.

## Requirements

* Linux 5.12 or newer, with the `cls_bpf`, `act_csum` and `sch_ingress` (clsact) tc modules,
  which distributions ship. On the network interface, conntrack has to be available through
  netlink (`nf_conntrack_netlink`, loaded on demand) if the host NATs the connection.
* Root, or the `cap_net_admin` and `cap_bpf` capabilities:
  `sudo setcap cap_net_admin,cap_bpf=+pe phantun_server`.
* The UDP peer of a connection has to be on the same host (in the same network namespace), e.g.
  WireGuard listening on `127.0.0.1`, as the programs only deliver datagrams locally. Connections
  with peers on other hosts go through Phantun.
* With [FEC](#forward-error-correction-fec), a 64-bit platform or one with 64-bit atomics, so
  not MIPS32.
* Phantun built with clang 12 or newer installed. The release binaries and the Docker image are,
  except for 32-bit x86, which the eBPF library does not support. Building without clang leaves the
  eBPF data path out with a warning, `PHANTUN_REQUIRE_EBPF=1` turns that into an error.

## Changes to the host

* A `clsact` qdisc is added to the Tun and the loopback interface, and to the network interfaces
  that connections use, which stays on the latter two. Adding a qdisc drops the packets queued on
  the interface at that moment, so Phantun adds it at startup to the interfaces of the default
  routes, and of the route to the server for the client, rather than when the first connection
  uses them, which would drop the end of its handshake. This is skipped where the interface
  already has one.
* Two tc filters named `phantun:<tun name>` are added to ingress of loopback, and of each network
  interface used, at priorities 28776 and 28777. Phantun removes them when it receives SIGTERM or
  SIGINT. If it is killed, they do nothing until the next instance removes them.
* `net.ipv4.conf.lo.route_localnet` and `net.ipv4.conf.lo.accept_local` are set to 1 and not
  reverted. Without them, the kernel drops IPv4 datagrams that the programs deliver to local
  addresses. They only affect packets entering the loopback interface without a route, which
  happens when they are redirected there like these, not to ordinary local traffic.
* On the network interface, conntrack sees the handshake of a connection but none of its later
  packets, so its entry expires after the timeout of established TCP connections
  (`net.netfilter.nf_conntrack_tcp_timeout_established`, 5 days by default) even while the
  connection is in use. The packets of the connection do not depend on the entry, but traffic
  shaping or accounting with netfilter or on the Tun interface does not see them either.

[Back to TOC](#table-of-contents)

# Packets in batches (GSO and GRO)

Each packet that passes through Phantun takes a system call, and each fake TCP packet also takes
the kernel's forwarding path, with routing, conntrack and NAT. Phantun passes them to the kernel
in batches instead, where it can:

* The Tun interface has virtio-net headers (`IFF_VNET_HDR`). Datagrams of the same length that
  arrive together are written as one packet of up to 64 KB, which the kernel only splits into one
  packet per datagram on the network interface, or leaves to its hardware (TSO), so that routing,
  conntrack and NAT only see one. The other way, the kernel merges the packets that arrive
  together (GRO), and passes them to Phantun as one. Checksums are left to the kernel, or the
  hardware.
* Datagrams are received several at a time from the UDP sockets (`recvmmsg`), and those of the
  same length sent with one system call (UDP GSO).

It is used automatically, and `--no-gso` turns off the splitting and merging. The log says at
startup whether the Tun interface allows it:

```
INFO  server > Packets pass the Tun interface in batches
```

In the [same test as above](#ebpf-data-path), with no added delay, `iperf3` reached, up / down:

| Client / server                      | Packets one by one | Packets in batches | CPU time of the client per GB, one by one / in batches |
|--------------------------------------|--------------------|--------------------|--------------------------------------------------------|
| Both `--no-ebpf`                     | 481 / 489 Mbit/s   | 1.54 / 1.56 Gbit/s | 13.1 / 3.4 s up, 15.2 / 3.0 s down                     |
| `--no-ebpf` / eBPF                   | 562 / 735 Mbit/s   | 1.64 / 1.71 Gbit/s | 15.0 / 3.4 s up, 11.7 / 2.7 s down                     |
| Both `--no-ebpf`, FEC `10:2`         | 404 / 400 Mbit/s   | 1.16 / 1.17 Gbit/s | 17.5 / 5.7 s up, 18.8 / 4.2 s down                     |
| `--no-ebpf` / eBPF, FEC `10:2`       | 407 / 574 Mbit/s   | 1.16 / 1.18 Gbit/s | 21.1 / 5.8 s up, 14.8 / 5.3 s down                     |
| Both eBPF                            | 1.81 / 1.70 Gbit/s | 1.80 / 1.61 Gbit/s |                                                        |

The first column is the previous version, which passes every packet on its own.

Requirements:

* Linux 4.18 or newer for UDP GSO, which Phantun stops using, with a line in the log, if the kernel
  refuses it. Without virtio-net headers on the Tun interface, also logged, packets pass it one by
  one.
* For the packets that Phantun receives to be merged, the network interface has to support GRO,
  which most do, and the other end has to take part, see below.

## Merged packets

The kernel only merges the packets of a connection with GRO if they lack the PSH flag and carry the
same acknowledgement number, and the eBPF programs cannot convert merged packets. So during the
handshake, each end says whether it takes merged packets, with the window of its SYN or SYN + ACK
(64240 rather than 65535). If the other end does, data packets lack PSH, their acknowledgement
number only moves on every 32 KB, and datagrams of the same length are written together. Otherwise,
packets are sent as before.

An end without eBPF takes merged packets, and so does a client with eBPF on connections that it
finds it cannot convert before it connects, e.g. as their network interface is not supported. An
end with eBPF does not otherwise, except a server whose client does: it then converts the packets it sends with eBPF, and passes those it receives through
Phantun, so that the client, e.g. a router without eBPF, can send in batches. The client saves far
more than the server spends: in the test above, without FEC, the client spent 11.6 s less CPU time
per GB up and 9.0 s less down, the server 2.1 s and 0.5 s more. The log says so for each connection:

```
INFO  phantun::offload > Packets sent on (...) are converted by eBPF on eth0, those received pass through Phantun, as the other end sends them merged
INFO  phantun::forward > Packets of (...) pass in batches both ways
```

Older versions do not say anything, so the packets exchanged with them are the same as before.

[Back to TOC](#table-of-contents)

# Version compatibility

While the TCP stack is fairly stable, the general expectation is that you should run same minor versions
of Server/Client of Phantun on both ends to ensure maximum compatibility.

[Back to TOC](#table-of-contents)

# Documentations

For users who wish to use `fake-tcp` library inside their own project, refer to the documentations for the library at:
[https://docs.rs/fake-tcp](https://docs.rs/fake-tcp).

[Back to TOC](#table-of-contents)

# Performance

Performance was tested on 2 AWS `t4g.xlarge` instances with 4 vCPUs and 5 Gb/s NIC over LAN. `nftables` was used to redirect
UDP stream of `iperf3` to go through the Phantun/udp2raw tunnel between two test instances and MTU has been tuned to avoid fragmentation.

Phantun `v0.3.2` and `udp2raw_arm_asm_aes` `20200818.0` was used. These were the latest release of both projects as of Apr 2022.

Test command: `iperf3 -c <IP> -p <PORT> -R -u -l 1400 -b 1000m -t 30 -P 5`

| Mode                                                                            | Send Speed     | Receive Speed  | Overall CPU Usage                                   |
|---------------------------------------------------------------------------------|----------------|----------------|-----------------------------------------------------|
| Direct (1 stream)                                                               | 3.00 Gbits/sec | 2.37 Gbits/sec | 25% (1 core at 100%)                                |
| Phantun (1 stream)                                                              | 1.30 Gbits/sec | 1.20 Gbits/sec | 60% (1 core at 100%, 3 cores at 50%)                |
| udp2raw (`cipher-mode=none` `auth-mode=none` `disable-anti-replay`) (1 stream)  | 1.30 Gbits/sec | 715 Mbits/sec  | 40% (1 core at 100%, 1 core at 50%, 2 cores idling) |
| Direct connection (5 streams)                                                   | 5.00 Gbits/sec | 3.64 Gbits/sec | 25% (1 core at 100%)                                |
| Phantun (5 streams)                                                             | 5.00 Gbits/sec | 2.38 Gbits/sec | 95% (all cores utilized)                            |
| udp2raw (`cipher-mode=none` `auth-mode=none` `disable-anti-replay`) (5 streams) | 5.00 Gbits/sec | 770 Mbits/sec  | 50% (2 cores at 100%)                               |

Writeup on some of the techniques used in Phantun to achieve this performance result: [Writing Highly Efficient UDP Server in Rust](https://idndx.com/writing-highly-efficient-udp-server-in-rust/).

[Back to TOC](#table-of-contents)

# Future plans

* Load balancing a single UDP stream into multiple TCP streams
* Integration tests
* Auto insertion/removal of required firewall rules

[Back to TOC](#table-of-contents)

# Compariation to udp2raw
[udp2raw](https://github.com/wangyu-/udp2raw-tunnel) is another popular project by [@wangyu-](https://github.com/wangyu-)
that is very similar to what Phantun can do. In fact I took inspirations of Phantun from udp2raw. The biggest reason for
developing Phantun is because of lack of performance when running udp2raw (especially on multi-core systems such as Raspberry Pi).
However, the goal is never to be as feature complete as udp2raw and only support the most common use cases. Most notably, UDP over ICMP
and UDP over UDP mode are not supported and there is no anti-replay nor encryption support. The benefit of this is much better
performance overall and less MTU overhead because lack of additional headers inside the TCP payload.

Here is a quick overview of comparison between those two to help you choose:

|                                                  |    Phantun    |      udp2raw      |
|--------------------------------------------------|:-------------:|:-----------------:|
| UDP over FakeTCP obfuscation                     |       ✅       |         ✅         |
| UDP over ICMP obfuscation                        |       ❌       |         ✅         |
| UDP over UDP obfuscation                         |       ❌       |         ✅         |
| Multi-threaded                                   |       ✅       |         ❌         |
| Throughput                                       |     Better    |        Good       |
| Layer 3 mode                                     | TUN interface | Raw sockets + BPF |
| Tunneling MTU overhead                           |    12 bytes   |      44 bytes     |
| Seprate TCP connections for each UDP connection  | Client/Server |    Server only    |
| Anti-replay, encryption                          |       ❌       |         ✅         |
| IPv6                                             |       ✅       |          ✅        |

[Back to TOC](#table-of-contents)

# License

Copyright 2021-2025 Datong Sun (dndx@idndx.com)

Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
[https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0)> or the MIT license
<LICENSE-MIT or [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT)>, at your
option. Files in the project may not be
copied, modified, or distributed except according to those terms.

[Back to TOC](#table-of-contents)

