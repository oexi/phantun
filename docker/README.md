# phantun (docker)

## Build

```sh
docker build -t phantun -f docker/Dockerfile .
```

## Usage

It is recommended to use docker-compose, see [docker-compose.yml](docker-compose.yml) for details.

## Notes

- The entrypoint enables `net.ipv4.ip_forward`, and `net.ipv6.conf.all.forwarding` unless `-4`/`--ipv4-only` is given.
  Writing sysctls needs `privileged: true`. Without it, set them with `sysctls:` (not available with
  `network_mode: host`) or on the host beforehand, otherwise the entrypoint logs an error.
- With `network_mode: host` these sysctls change the host and are not reverted. When IPv6 forwarding is turned on,
  `accept_ra` of the default IPv6 interface is raised from 1 to 2, so a default route learned from SLAAC keeps working.
- The iptables rules are tagged with a `phantun_<tun>_<port>` comment. They are removed when the container stops or
  phantun exits, and rules left behind by a killed container are replaced on the next start.
- `USE_IPTABLES_NFT_BACKEND=1` (default) uses `iptables-nft`, `0` uses `iptables-legacy`. Pick the one the host uses.
