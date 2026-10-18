# LAN Sentinel

LAN Sentinel keeps a persistent, historical inventory of the hosts on local OT (industrial) networks. It is a single static binary for Linux edge devices (Raspberry Pi CM4, RevPi Connect, amd64 edge boxes), runs under systemd, and needs nothing else installed.

It answers, after the fact: *what was using this IP at that time, with which MAC, what we thought it was, and when that changed*.

```bash
sudo lan-sentinel hosts list --interface eth1 --active
sudo lan-sentinel hosts find 192.168.1.200
sudo lan-sentinel hosts find 192.168.1.200 --interface eth1 --at "2026-10-04 10:15"
sudo lan-sentinel hosts history 00:0c:26:8e:1b:d6 --since 24h
sudo lan-sentinel events list --type duplicate-ip --since 7d
sudo lan-sentinel watch --interface eth1
journalctl -u lan-sentinel -f
```

## What it does

- **Listens, by default.** Each monitored interface gets a receive-only capture that never sends a frame. It learns hosts from ARP, DHCP, mDNS, DNS answers, LLDP, CDP, NetBIOS, SSDP, WS-Discovery and the source addresses of IPv4 traffic (NDP too, with IPv6 switched on), and from the kernel's own neighbour table. On a switched port it sees the box's own traffic plus broadcast and multicast; on a mirror (SPAN) port it sees everything.
- **Remembers.** Every host is a MAC on one interface. Its addresses and names are kept as intervals with first and last seen, so you can ask who had an address at any past moment. Address and name history is kept for good; events for two years, hourly evidence roll-ups for 90 days and raw observations for 7 days by default, within a 200 MB database cap.
- **Tells you what changed.** State changes become events: a new host, an IP change, a duplicate IP, a MAC moving between interfaces, a host going missing, an unexpected DHCP server. Each event is written to the database and to the systemd journal.
- **Identifies devices.** Vendors come from the embedded IEEE OUI table. Device types, models, firmware and OS versions come from what devices announce: mDNS services, DHCP options, LLDP and CDP (which also name the switch port the box is plugged into), NetBIOS, SSDP and WS-Discovery (ONVIF camera models).
- **Probes only when you allow it.** Active discovery is off until you enable it on an interface for explicitly listed networks: an ARP sweep, optionally ICMP echo, plain TCP connects to chosen ports (Modbus 502, say) and NTP or EtherNet/IP ListIdentity requests to known hosts. Everything stays inside OT safety limits: 20 packets per second in total, at most one probe per second to any device, excludes checked before every packet, nothing wider than a /24 unless explicitly allowed, and a kill switch (`lan-sentinel active disable`). There is no SYN scanning, port sweeping or IPv6 sweeping. Identification probes that send a payload (Modbus FC 43/14, HTTP, TLS, SNMPv2c, SSH banner, Telnet, FTP) are a separate opt-in per interface and run once per device.
- **Stays on the box.** A command-line client, a local REST API on a Unix socket, and optional Prometheus metrics on `127.0.0.1`. No data leaves the device.

## Requirements

- Linux on amd64 or arm64, kernel 5.10 or newer, with systemd. Tested on Debian 11, 12 and 13 (Raspberry Pi OS and RevPi images are Debian based).
- `sudo` to install. The daemon runs as root, limited by its systemd unit to the single capability `CAP_NET_RAW` and a read-only view of the system.
- Under 50 MB of memory (about 27 MB in a simulated 90-day run of a 50-host network) and up to 200 MB of disk for the database.

## Install the latest release

Download the latest release for the board's architecture and verify it:

```bash
VERSION=$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/boeboe/lan-sentinel/releases/latest | sed 's|.*/||')
case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "unsupported: $(uname -m)" ;; esac
cd "$(mktemp -d)"
curl -fsSLO "https://github.com/boeboe/lan-sentinel/releases/download/$VERSION/lan-sentinel-$VERSION-linux-$ARCH.tar.gz"
curl -fsSLO "https://github.com/boeboe/lan-sentinel/releases/download/$VERSION/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf "lan-sentinel-$VERSION-linux-$ARCH.tar.gz" && cd "lan-sentinel-$VERSION-linux-$ARCH"
```

Then install it from the unpacked directory. The same commands upgrade an installed release: they replace the binary and the unit, keep an existing `/etc/lan-sentinel/config.yaml`, and restart the daemon.

```bash
sha256sum --check SHA256SUMS
sudo install -D -m 0755 lan-sentinel /usr/local/bin/lan-sentinel
sudo test -e /etc/lan-sentinel/config.yaml || sudo install -D -m 0640 config.yaml /etc/lan-sentinel/config.yaml
sudo install -d -m 0750 /data/lan-sentinel
sudo lan-sentinel config validate --config /etc/lan-sentinel/config.yaml
sudo install -D -m 0644 lan-sentinel.service /etc/systemd/system/lan-sentinel.service
sudo systemctl daemon-reload
sudo systemctl enable lan-sentinel
sudo systemctl restart lan-sentinel
```

Before an upgrade, copy the database so you can roll back: see [Upgrade and rollback](deploy/README.md#upgrade-and-rollback). Releases are listed on the [Releases page](https://github.com/boeboe/lan-sentinel/releases); each has one tarball per architecture (the binary, the `capcheck` privilege check, the systemd unit and the default config) and `SHA256SUMS`.

## First steps

The default configuration listens passively on `eth0`. Name the site's interfaces in `/etc/lan-sentinel/config.yaml`:

```yaml
version: 1
interfaces:
  - name: eth0
    passive: { enabled: true }
  - name: eth1
    passive: { enabled: true }
```

Check the file and restart the daemon (adding an interface needs a restart; most other changes apply with `sudo lan-sentinel config reload`):

```bash
sudo lan-sentinel config validate
sudo systemctl restart lan-sentinel
sudo lan-sentinel daemon status
```

Within a few minutes, hosts appear:

```bash
sudo lan-sentinel hosts list
sudo lan-sentinel interfaces list
sudo lan-sentinel events list --since 1h
```

Active discovery stays off until you review the site's devices and enable it per interface with explicit networks; preview what it would send with `sudo lan-sentinel scan plan --interface eth1`. The [user guide](docs/USER_GUIDE.md) walks through configuration, every common command with example output, the journal, active discovery, identification and troubleshooting.

## Files on the device

| Item | Path |
| --- | --- |
| Binary | `/usr/local/bin/lan-sentinel` |
| Configuration | `/etc/lan-sentinel/config.yaml` |
| Database | `/data/lan-sentinel/hosts.db` |
| API socket | `/run/lan-sentinel/api.sock` |
| Service | `lan-sentinel.service`; logs and events: `journalctl -u lan-sentinel` |

The socket and the database belong to root: run `lan-sentinel` commands with `sudo`. `sudo lan-sentinel --offline ...` reads the database directly when the daemon is not running.

## Documentation

For operators:

- [User guide](docs/USER_GUIDE.md): configuration, commands, journal, active discovery, identification, troubleshooting
- [CLI reference](docs/CLI.md) and [local API and metrics](docs/API.md)
- [Installation, upgrade, rollback and rollout](deploy/README.md)
- [Hardware test plan](docs/TEST_PLAN.md) for validating a new board type

For developers:

- [Requirements](docs/REQUIREMENTS.md), [architecture](docs/ARCHITECTURE.md), [data model](docs/DATA_MODEL.md) and [architecture decision records](docs/adr/README.md)
- [Status](docs/STATUS.md), [backlog](docs/BACKLOG.md) (what is not built) and the [implementation plan](docs/IMPLEMENTATION_PLAN.md)
- For coding agents: [AGENTS.md](AGENTS.md) and the [repository map](docs/AI_REPO_MAP.md)

## Building from source

Every make target runs Go in a Linux dev container, so a development machine (Linux or macOS) needs only Docker, make and git.

```bash
make              # list all targets
make check        # format, tidy, vet, lint, vulnerabilities, race tests, coverage >= 90%
make build        # bin/lan-sentinel for the Docker host's architecture
make package      # release tarballs into dist/release/ (VERSION=vX.Y.Z)
make test-net     # network tests in Docker, with CAP_NET_RAW only
make test-systemd # the daemon under systemd on Debian 11, 12 and 13
make chaos        # the daemon under a seeded storm of traffic, LAN changes and operator actions
make stress       # every test package in random order, repeated, at 1 and 4 CPUs
make soak         # 90 simulated days of a 50-host LAN
```

Binaries are static (`CGO_ENABLED=0`) with no runtime dependencies. Releases are cut from `main` by the maintainer with the **release** workflow ([Cutting a release](deploy/README.md#cutting-a-release)).
