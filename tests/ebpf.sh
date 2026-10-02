#!/bin/bash
#
# Tests the eBPF data path end to end: a client and a server in two network namespaces exchange
# datagrams with an echo service through Phantun, and the test checks that they arrive intact and
# that the eBPF programs converted them where expected: on the network interface, on the Tun
# interface with --no-ebpf-nic, or not at all with --no-ebpf. With FEC, the link loses packets,
# which have to be recovered.
#
# Usage: sudo tests/ebpf.sh [directory with the server and client binaries, default target/debug]
#
# Needs root, iproute2, iptables, python3 and the netem qdisc. With wg (wireguard-tools), it also
# tests a network interface without an Ethernet header, by running Phantun over WireGuard.

set -euo pipefail

BIN_DIR=$(realpath "${1:-target/debug}")
WORK=$(mktemp -d)
NS_C=phantun-test-c
NS_S=phantun-test-s
COUNT=300
failed=0
# The network interfaces the fake TCP connection uses, and the program converting on them
NIC_C=phantun-tc
NIC_S=phantun-ts
NIC_PROG=nic_ingress_eth

cleanup() {
  pkill -f "^$BIN_DIR/(server|client) " 2>/dev/null || true
  pkill -f "^python3 $WORK/echo.py" 2>/dev/null || true
  ip netns del $NS_C 2>/dev/null || true
  ip netns del $NS_S 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

cat > "$WORK/echo.py" <<'EOF'
import socket, sys, time

def server(host, port):
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, port))
    while True:
        data, addr = s.recvfrom(4096)
        s.sendto(data, addr)

def client(host, port, count, size):
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.connect((host, port))
    ok = 0
    for i in range(count):
        data = (b"%d:" % i).ljust(size, bytes([i % 256]))
        s.send(data)
        try:
            # skip late replies to earlier datagrams
            while True:
                reply = s.recv(4096)
                if reply.split(b":")[0] == b"%d" % i:
                    break
            ok += reply == data
        except socket.timeout:
            pass
    print(ok)

# Counts datagrams until "end", and replies with the count
def sink(host, port):
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    # room for a burst, beyond net.core.rmem_max (SO_RCVBUFFORCE)
    s.setsockopt(socket.SOL_SOCKET, 33, 4 * 1024 * 1024)
    s.bind((host, port))
    n = 0
    while True:
        data, addr = s.recvfrom(4096)
        if data == b"end":
            s.sendto(b"%d" % n, addr)
            n = 0
        else:
            n += 1

# Sends datagrams one way, then "end", and prints how many arrived
def oneway(host, port, count, size):
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.connect((host, port))
    for i in range(count):
        s.send(bytes(size))
        time.sleep(0.001)
    s.send(b"end")
    try:
        print(int(s.recv(64)))
    except socket.timeout:
        print(0)

# Sends a datagram, waits for the connection to be set up, sends `count` more at once, then
# "end", and prints how many of those arrived
def burst(host, port, count, size):
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.connect((host, port))
    s.send(bytes(size))
    time.sleep(0.5)
    for i in range(count):
        s.send(bytes(size))
    s.send(b"end")
    try:
        print(int(s.recv(64)) - 1)
    except socket.timeout:
        print(0)

# Echoes a datagram, sends one from each of `count` other sources, which are new connections, and
# echoes again. Prints 1 if both echoes arrived.
def flood(host, port, count):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.connect((host, port))

    def echo():
        s.send(b"ping")
        try:
            return s.recv(64) == b"ping"
        except socket.timeout:
            return False

    ok = echo()
    others = []
    for i in range(count):
        o = socket.socket(family, socket.SOCK_DGRAM)
        o.sendto(b"x", (host, port))
        others.append(o)
        time.sleep(0.05)
    print(int(ok and echo()))

globals()[sys.argv[1]](sys.argv[2], *map(int, sys.argv[3:]))
EOF

setup() {
  ip netns add $NS_C
  ip netns add $NS_S
  ip link add phantun-tc type veth peer name phantun-ts
  ip link set phantun-tc netns $NS_C
  ip link set phantun-ts netns $NS_S
  ip -n $NS_C addr add 10.199.0.1/24 dev phantun-tc
  ip -n $NS_S addr add 10.199.0.2/24 dev phantun-ts
  ip -n $NS_C addr add fd99:199::1/64 dev phantun-tc nodad
  ip -n $NS_S addr add fd99:199::2/64 dev phantun-ts nodad
  for ns in $NS_C $NS_S; do
    ip -n $ns link set lo up
    ip netns exec $ns sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
  done
  ip -n $NS_C link set phantun-tc up
  ip -n $NS_S link set phantun-ts up
  ip -n $NS_C route add default via 10.199.0.2
  ip -n $NS_S route add default via 10.199.0.1
  ip -n $NS_C -6 route add default via fd99:199::2
  ip -n $NS_S -6 route add default via fd99:199::1
  ip netns exec $NS_C iptables -t nat -A POSTROUTING -s 192.168.200.2 -o phantun-tc -j MASQUERADE
  ip netns exec $NS_C ip6tables -t nat -A POSTROUTING -s fcc8::2 -o phantun-tc -j MASQUERADE
  ip netns exec $NS_S iptables -t nat -A PREROUTING -p tcp -i phantun-ts --dport 4567 -j DNAT --to-destination 192.168.201.2
  ip netns exec $NS_S ip6tables -t nat -A PREROUTING -p tcp -i phantun-ts --dport 4567 -j DNAT --to-destination fcc9::2
  # Like a real network, drop what the other end sends without NAT
  ip netns exec $NS_S iptables -t raw -A PREROUTING -s 192.168.200.0/24 -j DROP
  ip netns exec $NS_S ip6tables -t raw -A PREROUTING -s fcc8::/64 -j DROP
  ip netns exec $NS_C iptables -t raw -A PREROUTING -s 192.168.201.0/24 -j DROP
  ip netns exec $NS_C ip6tables -t raw -A PREROUTING -s fcc9::/64 -j DROP

  ip netns exec $NS_S python3 "$WORK/echo.py" server 127.0.0.1 7777 &
  ip netns exec $NS_S python3 "$WORK/echo.py" server ::1 7777 &
  ip netns exec $NS_S python3 "$WORK/echo.py" sink 127.0.0.1 7778 &
}

# setup_wg: a WireGuard link between both namespaces, over the veth link, for fake TCP
setup_wg() {
  wg genkey > "$WORK/wg-c"
  wg genkey > "$WORK/wg-s"
  ip -n $NS_C link add phantun-wc type wireguard
  ip -n $NS_S link add phantun-ws type wireguard
  ip netns exec $NS_C wg set phantun-wc private-key "$WORK/wg-c" listen-port 51001 \
    peer "$(wg pubkey < "$WORK/wg-s")" allowed-ips 0.0.0.0/0 endpoint 10.199.0.2:51002
  ip netns exec $NS_S wg set phantun-ws private-key "$WORK/wg-s" listen-port 51002 \
    peer "$(wg pubkey < "$WORK/wg-c")" allowed-ips 0.0.0.0/0 endpoint 10.199.0.1:51001
  ip -n $NS_C addr add 10.198.0.1/24 dev phantun-wc
  ip -n $NS_S addr add 10.198.0.2/24 dev phantun-ws
  ip -n $NS_C link set phantun-wc up
  ip -n $NS_S link set phantun-ws up
  ip netns exec $NS_C iptables -t nat -A POSTROUTING -s 192.168.200.2 -o phantun-wc -j MASQUERADE
  ip netns exec $NS_S iptables -t nat -A PREROUTING -p tcp -i phantun-ws --dport 4567 -j DNAT --to-destination 192.168.201.2
}

# converted <namespace> <interface> <ingress|egress> <program>: the number of fake TCP packets
# that the program converted (or passed to Phantun) on the interface, nothing without the program
converted() {
  ip netns exec "$1" tc -s filter show dev "$2" "$3" \
    | awk -v prog="$4" '/^filter / { f = $0 ~ " name " prog " " } f && /Sent/ { print $4; exit }'
}

# loss <percent>: makes the link lose packets in both directions, 0 for none
loss() {
  ip netns exec $NS_C tc qdisc replace dev phantun-tc root netem loss "$1%"
  ip netns exec $NS_S tc qdisc replace dev phantun-ts root netem loss "$1%"
}

# run <name> <server address> <echo address> <local address> <expect eBPF: nic|server|tun|no>
#   [phantun args]: with `server`, only the server converts on the network interface, and only the
#   packets it sends, as the client merges packets. SERVER_ARGS and CLIENT_ARGS are passed to one
#   side only.
run() {
  local name=$1 server=$2 remote=$3 local=$4 expect=$5
  shift 5
  echo "=== $name"
  ip netns exec $NS_S env RUST_LOG=info "$BIN_DIR/server" --local 4567 --remote "$remote" --tun phantun-ts0 "$@" \
    ${SERVER_ARGS:-} > "$WORK/server.log" 2>&1 &
  ip netns exec $NS_C env RUST_LOG=info "$BIN_DIR/client" --local "$local" --remote "$server" --tun phantun-tc0 "$@" \
    ${CLIENT_ARGS:-} > "$WORK/client.log" 2>&1 &
  sleep 1

  local host=${local%:*} port=${local##*:}
  host=${host#[}
  host=${host%]}
  local ok
  ok=$(ip netns exec $NS_C python3 "$WORK/echo.py" client "$host" "$port" $COUNT 1000)
  local s_tun c_tun s_nic c_nic
  s_tun=$(converted $NS_S phantun-ts0 egress tcp_to_udp || true)
  c_tun=$(converted $NS_C phantun-tc0 egress tcp_to_udp || true)
  s_nic=$(converted $NS_S $NIC_S ingress $NIC_PROG || true)
  c_nic=$(converted $NS_C $NIC_C ingress $NIC_PROG || true)

  pkill -f "^$BIN_DIR/(server|client) " || true
  sleep 0.5

  local result=pass
  # A few may be lost while the connection is set up
  if [ "$ok" -lt $((COUNT - 5)) ]; then
    result=fail
  fi
  # Only the first datagram takes the user space path
  case $expect in
    nic)
      if [ "${s_nic:-0}" -lt $((COUNT - 5)) ] || [ "${c_nic:-0}" -lt $((COUNT - 5)) ] \
        || [ "${s_tun:-0}" -gt 5 ] || [ "${c_tun:-0}" -gt 5 ]; then
        result=fail
      fi
      ;;
    server)
      # the program on the network interface passes those received to Phantun
      if [ "${s_nic:-0}" -lt $((COUNT - 5)) ] || [ -n "$c_nic$c_tun" ] || [ "${s_tun:-0}" -gt 5 ] \
        || ! grep -q "those received pass through Phantun" "$WORK/server.log"; then
        result=fail
      fi
      ;;
    tun)
      if [ "${s_tun:-0}" -lt $((COUNT - 5)) ] || [ "${c_tun:-0}" -lt $((COUNT - 5)) ] \
        || [ -n "$s_nic$c_nic" ]; then
        result=fail
      fi
      ;;
    no)
      if [ -n "$s_tun$c_tun$s_nic$c_nic" ] && [ "${s_tun:-0}${c_tun:-0}" != 00 ]; then
        result=fail
      fi
      ;;
  esac
  echo "echoed $ok/$COUNT, converted by eBPF on the network interface: server ${s_nic:-none}," \
    "client ${c_nic:-none}, on the Tun interface: server ${s_tun:-none}, client ${c_tun:-none}: $result"
  if [ $result = fail ]; then
    failed=1
    echo "--- server log"; cat "$WORK/server.log"
    echo "--- client log"; cat "$WORK/client.log"
  fi
  # The filters on loopback and the network interfaces are gone after a SIGTERM
  for dev in "$NS_C lo" "$NS_S lo" "$NS_C $NIC_C" "$NS_S $NIC_S"; do
    set -- $dev
    if ip netns exec "$1" tc filter show dev "$2" ingress | grep -q phantun; then
      echo "eBPF filters left on $2 in $1"
      failed=1
    fi
  done
}

# oneway <name> [phantun args]: datagrams that only go from the client to the server, more than
# the 64 KB that conntrack lets through from the client until it sees a packet from the server
# after the handshake, as the window of the SYN + ACK is not scaled
oneway() {
  local name=$1
  shift
  echo "=== $name"
  ip netns exec $NS_S env RUST_LOG=info "$BIN_DIR/server" --local 4567 --remote 127.0.0.1:7778 --tun phantun-ts0 "$@" \
    > "$WORK/server.log" 2>&1 &
  ip netns exec $NS_C env RUST_LOG=info "$BIN_DIR/client" --local 127.0.0.1:1984 --remote 10.199.0.2:4567 --tun phantun-tc0 "$@" \
    > "$WORK/client.log" 2>&1 &
  sleep 1

  local ok
  ok=$(ip netns exec $NS_C python3 "$WORK/echo.py" oneway 127.0.0.1 1984 $COUNT 1000)

  pkill -f "^$BIN_DIR/(server|client) " || true
  sleep 0.5

  local result=pass
  if [ "$ok" -lt $((COUNT - 5)) ]; then
    result=fail
    failed=1
  fi
  echo "received $ok/$COUNT: $result"
  if [ $result = fail ]; then
    echo "--- server log"; cat "$WORK/server.log"
    echo "--- client log"; cat "$WORK/client.log"
  fi
}

# tun_packets <namespace> <interface> <rx|tx>: the number of packets the interface counted
tun_packets() {
  ip -n "$1" -s -j link show "$2" \
    | python3 -c "import json, sys; print(json.load(sys.stdin)[0]['stats64']['$3']['packets'])"
}

# burst <name> [phantun args]: datagrams sent at once from the client to the server. Without
# eBPF, the client writes them to the Tun interface together for the kernel to split, and the
# server reads them merged by GRO, or here as they were written, as the veth link keeps them
# together, so both take fewer packets than there are datagrams. Expects the packets to be merged
# unless `--no-gso` is among the arguments.
burst() {
  local name=$1
  shift
  echo "=== $name"
  ip netns exec $NS_S env RUST_LOG=info "$BIN_DIR/server" --local 4567 --remote 127.0.0.1:7778 --tun phantun-ts0 "$@" \
    ${SERVER_ARGS:-} > "$WORK/server.log" 2>&1 &
  ip netns exec $NS_C env RUST_LOG=info "$BIN_DIR/client" --local 127.0.0.1:1984 --remote 10.199.0.2:4567 --tun phantun-tc0 "$@" \
    ${CLIENT_ARGS:-} > "$WORK/client.log" 2>&1 &
  sleep 1

  # written by the client, read by the server
  local c0 s0 c1 s1 ok
  c0=$(tun_packets $NS_C phantun-tc0 rx)
  s0=$(tun_packets $NS_S phantun-ts0 tx)
  ok=$(ip netns exec $NS_C python3 "$WORK/echo.py" burst 127.0.0.1 1984 $COUNT 1000)
  c1=$(tun_packets $NS_C phantun-tc0 rx)
  s1=$(tun_packets $NS_S phantun-ts0 tx)
  local written=$((c1 - c0)) read=$((s1 - s0))

  pkill -f "^$BIN_DIR/(server|client) " || true
  sleep 0.5

  local result=pass
  if [ "$ok" -lt $((COUNT - 5)) ]; then
    result=fail
  fi
  case " $* ${SERVER_ARGS:-} ${CLIENT_ARGS:-} " in
    *" --no-gso "*)
      if [ $written -lt "$ok" ] || [ $read -lt "$ok" ]; then
        result=fail
      fi
      ;;
    *)
      # how many go together depends on how far Phantun lags behind
      if [ $written -gt $((ok * 9 / 10)) ] || [ $read -gt $((ok * 9 / 10)) ]; then
        result=fail
      fi
      ;;
  esac
  echo "received $ok/$COUNT, packets written by the client: $written, read by the server: $read: $result"
  if [ $result = fail ]; then
    failed=1
    echo "--- server log"; cat "$WORK/server.log"
    echo "--- client log"; cat "$WORK/client.log"
  fi
}

# fd_limit: the server runs out of file descriptors as connections come in, and has to refuse the
# new ones while it keeps serving the others
fd_limit() {
  echo "=== Out of file descriptors"
  ip netns exec $NS_S prlimit --nofile=64 env RUST_LOG=info "$BIN_DIR/server" --local 4567 --remote 127.0.0.1:7777 \
    --tun phantun-ts0 --no-ebpf > "$WORK/server.log" 2>&1 &
  ip netns exec $NS_C env RUST_LOG=info "$BIN_DIR/client" --local 127.0.0.1:1984 --remote 10.199.0.2:4567 \
    --tun phantun-tc0 --no-ebpf > "$WORK/client.log" 2>&1 &
  sleep 1

  local ok refused
  ok=$(ip netns exec $NS_C python3 "$WORK/echo.py" flood 127.0.0.1 1984 60)
  refused=$(grep -c "Too many open files" "$WORK/server.log" || true)

  pkill -f "^$BIN_DIR/(server|client) " || true
  sleep 0.5

  local result=pass
  if [ "$ok" != 1 ] || [ "$refused" -eq 0 ]; then
    result=fail
    failed=1
  fi
  echo "first connection served: $ok, connections refused: $refused: $result"
  if [ $result = fail ]; then
    echo "--- server log"; cat "$WORK/server.log"
    echo "--- client log"; cat "$WORK/client.log"
  fi
}

# lost_ack: the ACK that ends the handshake is lost, so the server takes the first data packet for
# it, whose datagram has to arrive all the same
lost_ack() {
  echo "=== Handshake ACK lost"
  local drop=(PREROUTING -p tcp --dport 4567 --tcp-flags ALL ACK -m length --length 40 -j DROP)
  ip netns exec $NS_S iptables -t raw -I "${drop[@]}"
  ip netns exec $NS_S env RUST_LOG=info "$BIN_DIR/server" --local 4567 --remote 127.0.0.1:7777 --tun phantun-ts0 \
    --no-ebpf > "$WORK/server.log" 2>&1 &
  ip netns exec $NS_C env RUST_LOG=info "$BIN_DIR/client" --local 127.0.0.1:1984 --remote 10.199.0.2:4567 \
    --tun phantun-tc0 --no-ebpf > "$WORK/client.log" 2>&1 &
  sleep 1

  local ok
  ok=$(ip netns exec $NS_C python3 "$WORK/echo.py" client 127.0.0.1 1984 1 1000)

  pkill -f "^$BIN_DIR/(server|client) " || true
  sleep 0.5
  ip netns exec $NS_S iptables -t raw -D "${drop[@]}"

  local result=pass
  if [ "$ok" != 1 ]; then
    result=fail
    failed=1
  fi
  echo "first datagram echoed: $ok: $result"
  if [ $result = fail ]; then
    echo "--- server log"; cat "$WORK/server.log"
    echo "--- client log"; cat "$WORK/client.log"
  fi
}

setup
run "IPv4" 10.199.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 nic
run "IPv6" "[fd99:199::2]:4567" "[::1]:7777" "[::1]:1984" nic
run "IPv6 fake TCP, IPv4 UDP" "[fd99:199::2]:4567" 127.0.0.1:7777 127.0.0.1:1984 nic
run "IPv4 fake TCP, IPv6 UDP" 10.199.0.2:4567 "[::1]:7777" "[::1]:1984" nic
run "IPv4, --no-ebpf-nic" 10.199.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 tun --no-ebpf-nic
run "IPv6, --no-ebpf-nic" "[fd99:199::2]:4567" "[::1]:7777" "[::1]:1984" tun --no-ebpf-nic
run "--no-ebpf" 10.199.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 no --no-ebpf
# Through conntrack on both ends
oneway "One way, --no-ebpf-nic" --no-ebpf-nic
oneway "One way, --no-ebpf" --no-ebpf
burst "At once, --no-ebpf" --no-ebpf
burst "At once, --no-ebpf --no-gso" --no-ebpf --no-gso
# Like a router in user space with a host converting with eBPF
CLIENT_ARGS=--no-ebpf run "Client --no-ebpf" 10.199.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 server
# With an end that does not merge packets, like older versions
CLIENT_ARGS=--no-gso run "Client --no-gso" 10.199.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 nic
CLIENT_ARGS=--no-gso burst "At once, --no-ebpf, client --no-gso" --no-ebpf
CLIENT_ARGS=--no-ebpf burst "At once, client --no-ebpf"
fd_limit
lost_ack
loss 5
run "FEC with 5% loss" 10.199.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 nic --fec 4:2
run "FEC with 5% loss, IPv6" "[fd99:199::2]:4567" "[::1]:7777" "[::1]:1984" nic --fec 4:2
run "FEC with 5% loss, --no-ebpf-nic" 10.199.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 tun --fec 4:2 --no-ebpf-nic
run "FEC with 5% loss, --no-ebpf" 10.199.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 no --fec 4:2 --no-ebpf
CLIENT_ARGS=--no-ebpf run "FEC with 5% loss, client --no-ebpf" 10.199.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 server --fec 4:2
loss 0

if command -v wg > /dev/null && setup_wg 2> /dev/null; then
  NIC_C=phantun-wc NIC_S=phantun-ws NIC_PROG=nic_ingress_l3
  run "Over WireGuard" 10.198.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 nic
  loss 5
  run "Over WireGuard, FEC with 5% loss" 10.198.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 nic --fec 4:2
  loss 0
else
  echo "=== Over WireGuard: skipped, WireGuard is not available"
fi

exit $failed
