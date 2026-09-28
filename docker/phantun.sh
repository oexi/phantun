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

# bash does not expand aliases in scripts, so pick the backend binaries by name
if [ "$USE_IPTABLES_NFT_BACKEND" = 1 ]; then
  IPTABLES_BACKEND=nft
else
  IPTABLES_BACKEND=legacy
fi

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

# the first unused tunN, which is what the kernel picks when phantun gets an empty --tun
_next_tun() {
  local n=0
  while [ -e "/sys/class/net/tun${n}" ]; do
    n=$((n + 1))
  done
  echo "tun${n}"
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
  elif out=$(sysctl -w "$1=1" 2>&1); then
    info "apply sysctl: ${out}"
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

  _ipt "$family" -A FORWARD -i "$TUN" -j ACCEPT -m comment --comment "$COMMENT" || error "${name} filter rule add failed."
  _ipt "$family" -A FORWARD -o "$TUN" -j ACCEPT -m comment --comment "$COMMENT" || error "${name} filter rule add failed."

  if _is_server_mode "$1"; then
    local address=$(_get_addr_by_iface "$family" "$interface")
    if _ipt "$family" -t nat -A PREROUTING -p tcp -i "$interface" --dport "$PORT" -j DNAT --to-destination "$peer" \
      -m comment --comment "$COMMENT"; then
      info "${name} DNAT rule added: [${COMMENT}]: ${interface} -> ${TUN}, ${address} -> ${peer}"
    else
      error "${name} DNAT rule add failed."
    fi
  else
    if _ipt "$family" -t nat -A POSTROUTING -s "$peer" -o "$interface" -j MASQUERADE \
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
  if ! _is_phantun "$1" || _has_arg -h "$@" || _has_arg --help "$@" || _has_arg -V "$@" || _has_arg --version "$@"; then
    exec "$@"
  fi

  TUN=$(_get_opt tun "" "$@")
  if [ -z "$TUN" ]; then
    # pin the name down so the rules match the interface phantun actually creates
    TUN=$(_next_tun)
    set -- "$@" --tun "$TUN"
  fi
  local address=$(_get_opt local l "$@")
  PORT=${address##*:}
  # iptables-save quotes comments with other characters, which would break matching them
  COMMENT="phantun_${TUN}_${PORT}"
  COMMENT=${COMMENT//[^A-Za-z0-9_-]/_}

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

start_phantun "$@"
