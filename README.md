# LAN Sentinel

LAN Sentinel keeps a persistent, interface-aware, historical inventory of the hosts on local OT networks. It runs as a single cgo-free Go binary (`lan-sentinel`) under systemd on Linux or launchd on macOS and correlates MAC addresses, IP addresses, hostnames, services and vendor information from passive capture, the kernel neighbour table and carefully rate-limited active probes.

Its purpose is field troubleshooting: answering, after the fact, *what was using this IP at that time, with which MAC, what we thought it was, and when that changed*.

```bash
lan-sentinel hosts list --interface eth1 --active
lan-sentinel hosts find 192.168.1.200
lan-sentinel hosts history 00:0c:26:8e:1b:d6 --since 24h
lan-sentinel hosts find 192.168.1.200 --interface eth1 --at "2026-10-04 10:15"
lan-sentinel events list --type duplicate-ip
lan-sentinel watch --interface eth1
```

## Status

Design complete, implementation starting. See `docs/IMPLEMENTATION_PLAN.md`.

## Documentation

- [Requirements](docs/REQUIREMENTS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Data model](docs/DATA_MODEL.md)
- [CLI](docs/CLI.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)

## Build

```bash
make release   # dist/lan-sentinel-{linux,darwin}-{amd64,arm64}, SHA256SUMS
```

Binaries are built with `CGO_ENABLED=0` and need no runtime dependencies. Linux (kernel 5.10+) and macOS (14+) are both development and delivery platforms with the same features. Linux binaries are static; macOS binaries link only the system `libSystem`. Darwin binaries are not notarised: after downloading, run `xattr -d com.apple.quarantine lan-sentinel-darwin-*`. Reference files: `deploy/linux/` (systemd unit, `sysusers.d`, `tmpfiles.d`, config) and `deploy/darwin/` (LaunchDaemon plists, `newsyslog.d`, config, setup README).

## Runtime layout

| Item | Linux | macOS |
| --- | --- | --- |
| Binary | `/usr/local/bin/lan-sentinel` | `/usr/local/bin/lan-sentinel` |
| Config | `/etc/lan-sentinel/config.yaml` | `/usr/local/etc/lan-sentinel/config.yaml` |
| Database | `/data/lan-sentinel/hosts.db` | `/usr/local/var/lan-sentinel/hosts.db` |
| API socket | `/run/lan-sentinel/api.sock` | `/var/run/lan-sentinel/api.sock` |
| Service | `lan-sentinel.service`, user `lan-sentinel`, `CAP_NET_RAW` only | LaunchDaemon `lan-sentinel`, user `_lan-sentinel` in `access_bpf`, never root |
