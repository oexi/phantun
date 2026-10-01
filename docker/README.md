# phantun (docker)

## Build

```sh
docker build -t phantun -f docker/Dockerfile .
```

## Usage

It is recommended to use docker-compose, see [docker-compose.yml](docker-compose.yml) for details.

## Notes

- `phantun-server` and `phantun-client` run the setup script `phantun.sh` (the entrypoint) before
  the actual binaries in `/usr/local/libexec/phantun/`, so the setup below also happens when a
  runtime such as RouterOS runs the command directly instead of passing it to the entrypoint.
- The entrypoint enables `net.ipv4.ip_forward`, and `net.ipv6.conf.all.forwarding` unless `-4`/`--ipv4-only` is given.
  Writing sysctls needs `privileged: true`. Without it, set them with `sysctls:` (not available with
  `network_mode: host`) or on the host beforehand, otherwise the entrypoint logs an error.
- With `network_mode: host` these sysctls change the host and are not reverted. When IPv6 forwarding is turned on,
  `accept_ra` of the default IPv6 interface is raised from 1 to 2, so a default route learned from SLAAC keeps working.
- Without `--tun`, the tun interface is named `phantun-s<port>` for the server and `phantun-c<port>` for the client,
  after the port of `--local`. The entrypoint refuses to start if the interface already exists, as phantun would
  share it with its owner, e.g. another instance using the same port.
- The iptables rules are tagged with a `phantun_<tun>_<port>` comment. They are removed when the container stops or
  phantun exits, and rules left behind by a killed container are replaced on the next start.
- `USE_IPTABLES_NFT_BACKEND=1` uses `iptables-nft`, `0` uses `iptables-legacy`. By default, the backend that already
  holds more rules is used, which is the one of the host with `network_mode: host`, and `iptables-nft` if neither
  has any, unless the kernel lacks nf_tables.
- The [eBPF data path](../README.md#ebpf-data-path) is used when the kernel supports it, which needs `privileged: true`
  as well. With `network_mode: host` its tc filters and sysctls are those of the host, and the filters are removed
  when the container stops. Where it is not available, e.g. on RouterOS, every packet passes through phantun as
  before, and the log says why.
