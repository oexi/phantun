#!/bin/bash
#
# Tests the eBPF data path end to end: a client and a server in two network namespaces exchange
# datagrams with an echo service through Phantun, and the test checks that they arrive intact and
# that the eBPF programs converted them, or with --no-ebpf, that they did not. With FEC, the link
# loses packets, which have to be recovered.
#
# Usage: sudo tests/ebpf.sh [directory with the server and client binaries, default target/debug]
#
# Needs root, iproute2, iptables, python3 and the netem qdisc.

set -euo pipefail

BIN_DIR=$(realpath "${1:-target/debug}")
WORK=$(mktemp -d)
NS_C=phantun-test-c
NS_S=phantun-test-s
COUNT=300
failed=0

cleanup() {
  pkill -f "^$BIN_DIR/(server|client) " 2>/dev/null || true
  pkill -f "^python3 $WORK/echo.py" 2>/dev/null || true
  ip netns del $NS_C 2>/dev/null || true
  ip netns del $NS_S 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

cat > "$WORK/echo.py" <<'EOF'
import socket, sys

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

if sys.argv[1] == "server":
    server(sys.argv[2], int(sys.argv[3]))
else:
    client(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]))
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

  ip netns exec $NS_S python3 "$WORK/echo.py" server 127.0.0.1 7777 &
  ip netns exec $NS_S python3 "$WORK/echo.py" server ::1 7777 &
}

# converted <namespace> <tun>: the number of fake TCP packets converted on the Tun interface
converted() {
  ip netns exec "$1" tc -s filter show dev "$2" egress \
    | awk '/^filter .* tcp_to_udp/ { f = 1 } f && /Sent/ { print $4; exit }'
}

# loss <percent>: makes the link lose packets in both directions, 0 for none
loss() {
  ip netns exec $NS_C tc qdisc replace dev phantun-tc root netem loss "$1%"
  ip netns exec $NS_S tc qdisc replace dev phantun-ts root netem loss "$1%"
}

# run <name> <server address> <echo address> <local address> <expect eBPF: yes|no> [phantun args]
run() {
  local name=$1 server=$2 remote=$3 local=$4 expect=$5
  shift 5
  echo "=== $name"
  ip netns exec $NS_S env RUST_LOG=info "$BIN_DIR/server" --local 4567 --remote "$remote" --tun phantun-ts0 "$@" \
    > "$WORK/server.log" 2>&1 &
  ip netns exec $NS_C env RUST_LOG=info "$BIN_DIR/client" --local "$local" --remote "$server" --tun phantun-tc0 "$@" \
    > "$WORK/client.log" 2>&1 &
  sleep 1

  local host=${local%:*} port=${local##*:}
  host=${host#[}
  host=${host%]}
  local ok
  ok=$(ip netns exec $NS_C python3 "$WORK/echo.py" client "$host" "$port" $COUNT 1000)
  local s_conv c_conv
  s_conv=$(converted $NS_S phantun-ts0 || true)
  c_conv=$(converted $NS_C phantun-tc0 || true)

  pkill -f "^$BIN_DIR/(server|client) " || true
  sleep 0.5

  local result=pass
  # A few may be lost while the connection is set up
  if [ "$ok" -lt $((COUNT - 5)) ]; then
    result=fail
  fi
  if [ "$expect" = yes ]; then
    # Only the first datagram takes the user space path
    if [ "${s_conv:-0}" -lt $((COUNT - 5)) ] || [ "${c_conv:-0}" -lt $((COUNT - 5)) ]; then
      result=fail
    fi
  elif [ -n "$s_conv$c_conv" ] && [ "${s_conv:-0}${c_conv:-0}" != 00 ]; then
    result=fail
  fi
  echo "echoed $ok/$COUNT, converted by eBPF: server ${s_conv:-none}, client ${c_conv:-none}: $result"
  if [ $result = fail ]; then
    failed=1
    echo "--- server log"; cat "$WORK/server.log"
    echo "--- client log"; cat "$WORK/client.log"
  fi
  # The filters on loopback are gone after a SIGTERM
  for ns in $NS_C $NS_S; do
    if ip netns exec $ns tc filter show dev lo ingress | grep -q phantun; then
      echo "eBPF filters left on loopback in $ns"
      failed=1
    fi
  done
}

setup
run "IPv4" 10.199.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 yes
run "IPv6" "[fd99:199::2]:4567" "[::1]:7777" "[::1]:1984" yes
run "IPv6 fake TCP, IPv4 UDP" "[fd99:199::2]:4567" 127.0.0.1:7777 127.0.0.1:1984 yes
run "IPv4 fake TCP, IPv6 UDP" 10.199.0.2:4567 "[::1]:7777" "[::1]:1984" yes
run "--no-ebpf" 10.199.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 no --no-ebpf
loss 5
run "FEC with 5% loss" 10.199.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 yes --fec 4:2
run "FEC with 5% loss, IPv6" "[fd99:199::2]:4567" "[::1]:7777" "[::1]:1984" yes --fec 4:2
run "FEC with 5% loss, --no-ebpf" 10.199.0.2:4567 127.0.0.1:7777 127.0.0.1:1984 no --fec 4:2 --no-ebpf
loss 0

exit $failed
