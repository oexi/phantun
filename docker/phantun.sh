#!/bin/bash

info() {
  local green='\e[0;32m'
  local clear='\e[0m'
  local time=$(date '+%Y-%m-%d %T')
  printf "${green}[${time}] [INFO]: ${clear}%s\n" "$*"
}

warn() {
  local yellow='\e[1;33m'
  local clear='\e[0m'
  local time=$(date '+%Y-%m-%d %T')
  printf "${yellow}[${time}] [WARN]: ${clear}%s\n" "$*" >&2
}

error() {
  local red='\e[0;31m'
  local clear='\e[0m'
  local time=$(date '+%Y-%m-%d %T')
  printf "${red}[${time}] [ERROR]: ${clear}%s\n" "$*" >&2
}

# The phantun binaries. phantun-server and phantun-client in PATH are links to this script.
PHANTUN_BIN_DIR=/usr/local/libexec/phantun

_is_server_mode() {
  [ "${1##*/}" = "phantun-server" ]
}

_is_phantun() {
  case "${1##*/}" in
    phantun-server|phantun-client)
      return 0
      ;;
  esac
  return 1
}

# _has_arg <arg> <command...>
_has_arg() {
  local want=$1 arg
  shift
  for arg in "$@"; do
    [ "$arg" = "$want" ] && return 0
  done
  return 1
}

_is_ipv4_only() {
  _has_arg -4 "$@" || _has_arg --ipv4-only "$@"
}

# _get_opt <long> <short> <command...>
# prints the option value in every form clap accepts: --local 1985, --local=1985, -l 1985, -l=1985, -l1985
_get_opt() {
  local long=$1 short=$2 value
  shift 2
  while [ $# -gt 0 ]; do
    case "$1" in
      "--${long}")
        echo "$2"
        return
        ;;
      "--${long}="*)
        echo "${1#*=}"
        return
        ;;
    esac
    if [ -n "$short" ]; then
      case "$1" in
        "-${short}")
          echo "$2"
          return
          ;;
        "-${short}"?*)
          value=${1#"-${short}"}
          echo "${value#=}"
          return
          ;;
      esac
    fi
    shift
  done
}

# _get_peer <4|6> <command...>
_get_peer() {
  local family=$1 peer
  shift
  if [ "$family" = 6 ]; then
    peer=$(_get_opt tun-peer6 "" "$@")
    _is_server_mode "$1" && echo "${peer:-fcc9::2}" || echo "${peer:-fcc8::2}"
  else
    peer=$(_get_opt tun-peer "" "$@")
    _is_server_mode "$1" && echo "${peer:-192.168.201.2}" || echo "${peer:-192.168.200.2}"
  fi
}

# _get_default_iface <4|6>
_get_default_iface() {
  ip -"$1" route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
}

# _get_addr_by_iface <4|6> <iface>
_get_addr_by_iface() {
  ip -"$1" addr show dev "$2" scope global | awk '$1 ~ /^inet/ { sub(/\/.*/, "", $2); print $2; exit }'
}

_ipt_name() {
  [ "$1" = 6 ] && echo ip6tables || echo iptables
}

# USE_IPTABLES_NFT_BACKEND=1 selects iptables-nft and 0 iptables-legacy. Otherwise, pick the one
# that holds more rules, which is the one a host sharing its network uses, and nft on a tie unless
# the kernel lacks nf_tables.
select_iptables_backend() {
  local nft legacy
  case "$USE_IPTABLES_NFT_BACKEND" in
    1)
      IPTABLES_BACKEND=nft
      return
      ;;
    0)
      IPTABLES_BACKEND=legacy
      return
      ;;
  esac

  if ! iptables-nft -w 10 -S >/dev/null 2>&1; then
    IPTABLES_BACKEND=legacy
    info "iptables backend: legacy, nf_tables is not available."
    return
  fi

  nft=$({ iptables-nft-save; ip6tables-nft-save; } 2>/dev/null | grep -c '^-A')
  legacy=$({ iptables-legacy-save; ip6tables-legacy-save; } 2>/dev/null | grep -c '^-A')
  if [ "$legacy" -gt "$nft" ]; then
    IPTABLES_BACKEND=legacy
  else
    IPTABLES_BACKEND=nft
  fi
  info "iptables backend: ${IPTABLES_BACKEND}, found ${nft} nft and ${legacy} legacy rules."
}

# _ipt <4|6> <iptables args...>
_ipt() {
  local name=$(_ipt_name "$1")
  shift
  "${name}-${IPTABLES_BACKEND}" -w 10 "$@"
}

# _ipt_save <4|6> <iptables-save args...>
_ipt_save() {
  local name=$(_ipt_name "$1")
  shift
  "${name}-${IPTABLES_BACKEND}-save" "$@"
}

# _enable_sysctl <key>
_enable_sysctl() {
  local out
  if [ "$(sysctl -n "$1" 2>/dev/null)" = 1 ]; then
    info "sysctl: $1 is already enabled."
    return
  fi
  # sysctl -w exits 0 when the write fails with EROFS or EPERM, so read the value back
  out=$(sysctl -q -w "$1=1" 2>&1)
  if [ "$(sysctl -n "$1" 2>/dev/null)" = 1 ]; then
    info "apply sysctl: $1 = 1"
  else
    error "failed to enable $1 (${out}), run the container with --privileged, or set it with --sysctl $1=1 (not available with the host network)."
  fi
}

apply_sysctl() {
  _enable_sysctl net.ipv4.ip_forward
  ! _is_ipv4_only "$@" || return

  # With forwarding enabled the kernel ignores router advertisements on interfaces with accept_ra=1,
  # so a host that gets its IPv6 default route from SLAAC would lose it once the route expires.
  local interface=$(_get_default_iface 6)
  local accept_ra="/proc/sys/net/ipv6/conf/${interface}/accept_ra"
  if [ -n "$interface" ] && [ "$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)" != 1 ] && [ "$(cat "$accept_ra" 2>/dev/null)" = 1 ]; then
    { echo 2 > "$accept_ra"; } 2>/dev/null && info "apply sysctl: net.ipv6.conf.${interface}.accept_ra = 2"
  fi
  _enable_sysctl net.ipv6.conf.all.forwarding
}

# apply_rules <4|6> <command...>
apply_rules() {
  local family=$1
  shift
  local name=$(_ipt_name "$family")
  local interface=$(_get_default_iface "$family")
  local peer=$(_get_peer "$family" "$@")

  if [ -z "$interface" ]; then
    warn "no IPv${family} default route, skip ${name} rules."
    return
  fi

  # insert rather than append, so that rejecting rules at the end of the host's chains do not win
  _ipt "$family" -I FORWARD -i "$TUN" -j ACCEPT -m comment --comment "$COMMENT" || error "${name} filter rule add failed."
  _ipt "$family" -I FORWARD -o "$TUN" -j ACCEPT -m comment --comment "$COMMENT" || error "${name} filter rule add failed."

  if _is_server_mode "$1"; then
    local address=$(_get_addr_by_iface "$family" "$interface")
    if _ipt "$family" -t nat -I PREROUTING -p tcp -i "$interface" --dport "$PORT" -j DNAT --to-destination "$peer" \
      -m comment --comment "$COMMENT"; then
      info "${name} DNAT rule added: [${COMMENT}]: ${interface} -> ${TUN}, ${address} -> ${peer}"
    else
      error "${name} DNAT rule add failed."
    fi
  else
    if _ipt "$family" -t nat -I POSTROUTING -s "$peer" -o "$interface" -j MASQUERADE \
      -m comment --comment "$COMMENT"; then
      info "${name} MASQUERADE rule added: [${COMMENT}]: ${TUN} -> ${interface} (peer ${peer})"
    else
      error "${name} MASQUERADE rule add failed."
    fi
  fi
}

# revoke_rules <4|6>
revoke_rules() {
  local family=$1
  local name=$(_ipt_name "$family")
  local table rule args count=0

  for table in filter nat; do
    while read -r rule; do
      # match the whole comment, phantun_tun0_1985 must not hit phantun_tun0_19850
      [[ "$rule " == *" --comment ${COMMENT} "* ]] || continue
      read -ra args <<< "${rule/-A/-D}"
      if _ipt "$family" -t "$table" "${args[@]}"; then
        count=$((count + 1))
      else
        error "${name} ${table} rule remove failed: ${rule}"
      fi
    done < <(_ipt_save "$family" -t "$table" 2>/dev/null)
  done

  [ "$count" = 0 ] || info "${name} rules: [${COMMENT}] ${count} removed."
}

cleanup() {
  trap '' TERM INT
  if [ -n "$pid" ] && kill "$pid" 2>/dev/null; then
    info "terminate phantun process."
    wait "$pid"
  fi
  revoke_rules 4
  revoke_rules 6
}

start_phantun() {
  if ! _is_phantun "$1"; then
    exec "$@"
  fi
  # run the binary rather than the link in PATH, which leads back here
  if [ -x "${PHANTUN_BIN_DIR}/${1##*/}" ]; then
    set -- "${PHANTUN_BIN_DIR}/${1##*/}" "${@:2}"
  fi
  if _has_arg -h "$@" || _has_arg --help "$@" || _has_arg -V "$@" || _has_arg --version "$@"; then
    exec "$@"
  fi

  local address=$(_get_opt local l "$@")
  PORT=${address##*:}
  TUN=$(_get_opt tun "" "$@")
  if [ -z "$TUN" ]; then
    # Pin the name down so the rules match the interface phantun creates, and derive it from the
    # port, so it is the same after a restart and differs between instances started together.
    _is_server_mode "$1" && TUN="phantun-s${PORT}" || TUN="phantun-c${PORT}"
    set -- "$@" --tun "$TUN"
  fi
  # The kernel lets phantun attach to an existing tun interface, which would then be shared with
  # whatever created it
  if [ -e "/sys/class/net/${TUN}" ]; then
    error "interface ${TUN} already exists, is another phantun running with it? Pick another one with --tun."
    exit 1
  fi
  # iptables-save quotes comments with other characters, which would break matching them
  COMMENT="phantun_${TUN}_${PORT}"
  COMMENT=${COMMENT//[^A-Za-z0-9_-]/_}

  select_iptables_backend

  # Signals only make the script exit and the EXIT trap does the cleanup, so the rules are also
  # removed when phantun exits on its own or a signal arrives before phantun is started.
  trap cleanup EXIT
  trap 'warn "caught SIGTERM signal, graceful stopping..."; exit 143' TERM
  trap 'warn "caught SIGINT signal, graceful stopping..."; exit 130' INT

  apply_sysctl "$@"
  # a crashed or killed container leaves its rules behind and they may not match the current config
  revoke_rules 4
  revoke_rules 6
  apply_rules 4 "$@"
  _is_ipv4_only "$@" || apply_rules 6 "$@"

  "$@" &
  pid=$!
  wait "$pid"
  local code=$?
  pid=
  warn "phantun exited with code ${code}."
  return $code
}

# Run through the phantun-server or phantun-client link, e.g. by a runtime such as RouterOS, which
# runs the command directly rather than as arguments of the entrypoint
if _is_phantun "$0"; then
  set -- "$0" "$@"
fi

start_phantun "$@"
