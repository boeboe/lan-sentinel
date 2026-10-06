# LAN Sentinel

LAN Sentinel keeps a persistent, interface-aware, historical inventory of the hosts on local OT networks. It runs as a single static Go binary (`lan-sentinel`) under systemd on Linux edge devices and correlates MAC addresses, IP addresses, hostnames, services and vendor information from passive capture, the kernel neighbour table and carefully rate-limited active probes.

Its purpose is field troubleshooting: answering, after the fact, *what was using this IP at that time, with which MAC, what we thought it was, and when that changed*.

```bash
lan-sentinel hosts list --interface eth1 --active
lan-sentinel hosts find 192.168.1.200
lan-sentinel hosts history 00:0c:26:8e:1b:d6 --since 24h
lan-sentinel hosts find 192.168.1.200 --interface eth1 --at "2026-10-04 10:15"
lan-sentinel events list --type duplicate-ip
lan-sentinel watch --interface eth1
```

## How hosts are discovered

**Passive, always on.** Each monitored interface gets a receive-only packet capture that never sends a frame. A kernel filter keeps only what reveals hosts: ARP, DHCP, mDNS, DNS responses, LLDP and, with `passive.protocols.ipv6` on, NDP; other IPv4 traffic is cut to its headers to learn source addresses. Alongside it, the kernel's neighbour table (over netlink) reports each MAC and IP pair the box itself has resolved. On a switched port this sees the box's own traffic plus broadcast and multicast, which is enough for discovery; on a mirror (SPAN) port with `promiscuous: true` it sees everything. Vendors come from the embedded IEEE OUI table.

**Active, off by default and per interface.** With `active.enabled` and explicit `networks` on an interface, an ARP sweep of those networks (every 5 minutes by default) finds devices that never speak on their own; it is the main active mechanism. ICMP echo, plain TCP connects to configured ports (Modbus 502, say) and two UDP requests, NTP and EtherNet/IP ListIdentity (which can identify the device), probe known hosts only and stay off until enabled. Everything runs within OT safety limits: a global budget of 20 packets per second with per-protocol budgets beneath it, at most one probe per second to any target, excludes checked before every packet, networks wider than /24 refused unless explicitly allowed, and a kill switch (`lan-sentinel active disable`) that stops all probing at once. There is no SYN scanning, port sweeping or IPv6 sweeping. `scan plan` previews a scan and `scan run` runs one on demand.

Every source only emits observations. A single correlator turns them into hosts (one per MAC per interface), address and name bindings with first and last seen, and events such as `IP_CHANGED` or `DUPLICATE_IP_DETECTED`.

## Status

Phases 0–4 are done (passive and active discovery, read side, OT safety limits); phase 5 (releases, hardening, pilot rollout) is in progress. See `docs/IMPLEMENTATION_PLAN.md`.

## Releases

Each release on the [Releases page](https://github.com/boeboe/lan-sentinel/releases) has one tarball per target, `lan-sentinel-vX.Y.Z-linux-amd64.tar.gz` and `lan-sentinel-vX.Y.Z-linux-arm64.tar.gz`, each with the static binary, `capcheck`, the reference systemd unit and default config, and `SHA256SUMS` for the tarballs. A release is cut from `main` with the **release** workflow (Actions → release → Run workflow, choose a patch, minor or major bump; the first release is v0.0.1). Installing and upgrading: [`deploy/README.md`](deploy/README.md).

## Documentation

- [Requirements](docs/REQUIREMENTS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Data model](docs/DATA_MODEL.md)
- [CLI](docs/CLI.md)
- [Local API and metrics](docs/API.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Deployment and releases](deploy/README.md)

## Build and test

```bash
make             # list all targets
make check       # format, tidy, vet, lint, vuln, tests with coverage
make release     # dist/lan-sentinel-linux-{amd64,arm64}, SHA256SUMS
make package     # dist/release/lan-sentinel-<version>-linux-{amd64,arm64}.tar.gz, SHA256SUMS
make test-net    # network integration tests in Docker
make test-systemd # the daemon under systemd in a container
```

Binaries are static (`CGO_ENABLED=0`) and need no runtime dependencies; minimum kernel 5.10. The code base is Linux only. Every make target that runs Go runs in a Linux dev container (`build/dev.Dockerfile`), so the only requirements on a development machine (Linux or macOS) are Docker, make and git. On macOS, point your editor's gopls at Linux (`GOOS=linux`). The reference systemd unit and default config are in `deploy/`.

## Runtime layout

| Item | Path |
| --- | --- |
| Binary | `/usr/local/bin/lan-sentinel` |
| Config | `/etc/lan-sentinel/config.yaml` |
| Database | `/data/lan-sentinel/hosts.db` |
| API socket | `/run/lan-sentinel/api.sock` |
| Service | `lan-sentinel.service`, root with `CAP_NET_RAW` only; CLI commands need `sudo` |
