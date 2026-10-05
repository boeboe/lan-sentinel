# LAN Sentinel — Architecture

Every collector emits normalised observations onto one bus; a single correlation goroutine owns identity and state, so collectors never touch the database directly.

## 1. Data flow

```text
                      ┌──────────────────────────────┐
                      │      Interface manager       │
                      │ links, addresses, contexts   │
                      └──────────────┬───────────────┘
            ┌────────────────────────┼────────────────────────┐
            ▼                        ▼                        ▼
   ┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
   │ Passive capture │     │ Kernel neighbour │     │  Active probes   │
   │ AF_PACKET / BPF │     │ netlink / route  │     │ scheduler, rate  │
   │ ARP IPv4 IPv6   │     │ socket, resync   │     │ limit, jitter    │
   │ NDP DHCP mDNS   │     │ link/addr events │     │ ARP ICMP TCP     │
   │ DNS LLDP        │     │                  │     │ proto-aware UDP  │
   └────────┬────────┘     └────────┬─────────┘     └────────┬─────────┘
            └────────────────────────┼────────────────────────┘
                                     ▼
                      ┌──────────────────────────────┐
                      │ Observation bus (bounded,    │
                      │ drop counter)                │
                      └──────────────┬───────────────┘
                                     ▼
                      ┌──────────────────────────────┐
                      │ Correlation / identity engine│
                      │ single goroutine             │
                      └───────┬──────────────┬───────┘
                              ▼              ▼
                     ┌──────────────┐  ┌──────────────┐
                     │ Current state│  │ Event engine │────────┐
                     └──────┬───────┘  └──────┬───────┘        │
                            └───────┬─────────┘                │
                                    ▼                          ▼
                      ┌──────────────────────────────┐   ┌──────────┐
                      │ SQLite (WAL), single writer  │   │ log sink │
                      │ hosts.db (platform path)     │   └──────────┘
                      └───────┬──────────────┬───────┘
                              ▼              ▼
                     ┌──────────────┐  ┌──────────────┐
                     │ REST API     │  │ Prometheus   │
                     │ Unix socket  │  │ /metrics     │
                     │ → CLI, watch │  │              │
                     └──────────────┘  └──────────────┘
```

Only the correlator writes state and events. journald receives state transitions straight from the event engine, never raw observations.

LAN Sentinel is Linux only, and so is the code base. The kernel-facing parts (interface manager, capture, neighbour monitoring, probe transmission) sit behind small interfaces (§3, Platform layer) so everything above them can be tested against fakes. A replay collector can stand in for live collection, e.g. in the dev container.

## 2. Key decisions

| Decision | Choice | Why |
| --- | --- | --- |
| Host identity | Within a context, host = MAC (one-to-one); internal UUID `host_id` as record key; no merge/split | The MAC is the only reliable same-device evidence on L2; multi-NIC devices are several hosts, a NIC swap is a new host |
| Network scoping | Every host keyed by `network_context` = interface; subnets kept as history | Same IP or MAC on `eth0` and `eth1` is not the same host; readdressing does not split history |
| Data flow | Collectors → observation channel → correlator → state + events → SQLite | Collectors stay independent and testable; one writer avoids lock contention |
| Concurrency | One correlator goroutine; collectors and probes in their own goroutines under `errgroup` | Deterministic ordering of state changes |
| Storage | SQLite in WAL mode, single writer, batched transactions | Atomic, crash-safe, one portable file, queryable |
| SQLite driver | `modernc.org/sqlite` (pure Go) | No cgo; static cross-compile |
| Packet capture | `AF_PACKET` TPACKET_V3 via `gopacket/afpacket`, classic-BPF filter (`golang.org/x/net/bpf`) | No cgo, no libpcap; kernel-side filtering keeps CPU low |
| Neighbours and interfaces | `vishvananda/netlink` dump + `RTM_NEWNEIGH`/`RTM_DELNEIGH`, link and address subscriptions, resync after `ENOBUFS` and periodically | Event-driven, no `ip neigh` polling |
| ARP/NDP send | Raw `AF_PACKET` socket (`mdlayher/arp`, `mdlayher/ndp`) | Needs only `CAP_NET_RAW` |
| TCP probes | Plain `net.Dialer` connect with timeout, immediate close, bound to the interface with `SO_BINDTODEVICE` | Safe for OT; classifies OPEN / REFUSED / TIMEOUT / UNREACHABLE; leaves via the probed interface |
| Presence | ACTIVE / RECENT / STALE / MISSING, configurable thresholds | Quiet PLCs are not offline |
| Logging | `log/slog` with a journald handler; text or JSON on a terminal or in a container; transitions only | No journal spam |
| Service manager | systemd, `Type=notify` with watchdog | Readiness, supervision and sandboxing in one place |
| CLI | One binary with cobra subcommands; client over Unix socket, `--offline` reads DB | Single static operational tool |
| Build | Go 1.26+, `CGO_ENABLED=0`, `linux/amd64` and `linux/arm64`; minimum kernel 5.10 | Fits target hardware; static binary, no runtime deps |
| Development | Linux-only code base; every build, lint and test runs in a Linux dev container via `make` (§9), on Linux or macOS hosts | One toolchain and one OS everywhere; no stubs or build tags |
| Replay | pcap/pcapng or JSONL replay through the real decoders and correlator, with a simulated clock | Reproduce site behaviour and run golden tests on any machine |
| Delivery | Two static binaries + checksums; reference files in `deploy/` | No packaging requirement |

## 3. Components

### Interface manager (`internal/iface`)
Enumerates links and addresses through netlink, derives one network context per configured interface name, records the interface's own prefixes over time (`context_prefixes`), follows link and address changes at runtime, and emits `INTERFACE_UP`, `INTERFACE_DOWN` and `SUBNET_CHANGED`. The current prefixes feed the correlator's on-link check (`DATA_MODEL.md` §5.2). Collectors start and stop per interface as links come and go.

### Observation bus (`internal/observation`)
A bounded Go channel of `Observation` values (see `DATA_MODEL.md` §2). When full, new observations are dropped and `lan_sentinel_bus_dropped_total` increments; collectors never block on the correlator.

### Passive capture (`internal/collect/capture`)
One `AF_PACKET` TPACKET_V3 ring per interface with a classic-BPF filter restricted to ARP, NDP/ICMPv6, DHCP (67/68), mDNS (5353), DNS (53) responses, LLDP (EtherType 0x88cc), and IPv4/IPv6 headers for source-address learning. Promiscuous mode is set with `PACKET_ADD_MEMBERSHIP` when enabled. Decoders are pure functions from frame to zero or more observations, shared with replay.

On a switched port, capture sees traffic to/from the box, broadcast, multicast, ARP, mDNS, IPv6 multicast and some switch control traffic, but not unicast between other devices unless the port is mirrored. That is expected and sufficient for discovery.

### Replay collector (`internal/collect/replay`)
Reads a pcap/pcapng file (via the pure-Go `gopacket/pcapgo` reader, frames decoded by the capture package's decoders) or a JSONL file of `Observation` values, and emits them for the configured interface with their recorded source and timestamp. In `speed: 0` mode it advances a simulated clock (`internal/clock`) to each observation's timestamp before emitting it and blocks until the correlator has consumed it, so presence and expiry timers fire exactly as they would have at the site; `speed: N` replays in real time × N. When every replay source is exhausted the daemon keeps serving the API (or exits with `replay.exit_when_done: true`, used by tests).

### Clock (`internal/clock`)
All components that read time (correlator, presence ticker, expiry, scheduler, compaction) take a `clock.Clock`. Production uses the wall clock; replay and tests use a simulated clock.

### Platform layer (`internal/platform`)
Four small interfaces over the kernel facilities. Nothing outside `internal/platform` and `internal/service` uses AF_PACKET, netlink or raw sockets directly, so collectors, the scheduler and the daemon are tested against fakes.

| Interface | Methods (sketch) | Linux implementation |
| --- | --- | --- |
| `Capturer` | `Open(iface, filter, promisc) (FrameSource, error)`, `Stats()` | `AF_PACKET` TPACKET_V3 ring |
| `NeighborSource` | `Snapshot(ctx) ([]Neighbor, error)`, `Watch(ctx) (<-chan NeighborEvent, error)` | rtnetlink neighbour dump and subscription |
| `InterfaceMonitor` | `List(ctx)`, `Watch(ctx) (<-chan LinkEvent, error)` | rtnetlink link and address dump and subscription |
| `Transmitter` | `SendFrame(iface, frame)`, `DialTCP(iface, addr, timeout)`, `ICMPConn(iface, ipv6)` | `AF_PACKET` write, `SO_BINDTODEVICE`, ping or raw ICMP socket |

Each backend reports availability per interface (`running`, `disabled`, `unsupported`, `failed` with error) to the collector registry, which feeds `daemon status` and `lan_sentinel_collector_up`. Shared tests run against fake implementations of these interfaces; the Linux implementations are tested in Docker (§9).

### Neighbour collector (`internal/collect/neighbor`)
Dumps the neighbour table at startup, then subscribes to `RTM_NEWNEIGH`/`RTM_DELNEIGH`, and takes a fresh dump after notification loss (`ENOBUFS`) and every `neighbor.resync_interval` (default 10 min). Emits source `kernel_neighbor` with the NUD state as `neighbor_state`. `STALE` means unconfirmed reachability, not offline.

### Active probes (`internal/probe`)
A scheduler runs independent probe engines (ARP, ICMP, NDP, TCP, UDP) per interface; engines build packets themselves and transmit through the platform `Transmitter`. Each engine draws from its own protocol token bucket and from one global token bucket (packets/s; a TCP connect costs 3 tokens), and holds a slot of one global semaphore (concurrency). TCP additionally holds a per-interface and a per-target-host semaphore, and every target has a minimum spacing between probes. The scheduler applies startup delay, jitter, randomised target order, excludes, the prefix guard, timeout back-off and the kill switch. The same planner computes `scan plan` dry runs and gates `scan run`. See §5.

### Correlator (`internal/correlate`) and state (`internal/state`)
Single goroutine. Applies the correlation rules (`DATA_MODEL.md` §5), maintains in-memory current state, runs the presence state machine and binding expiry on a ticker, derives `preferred_name`, and hands state changes to the store and events to the event engine. Observations that match no host are stored unbound and counted.

### Event engine (`internal/events`)
Builds events from state transitions, attaches the evidence snapshot (`DATA_MODEL.md` §7), writes them to the store and to journald.

### Store (`internal/store`)
Owns the single SQLite writer goroutine, migrations, repositories, batched commits (target 5 s), retention, roll-up and compaction (hourly, small batches). Exposes read-only query functions used by the API and by `--offline`; the offline open procedure is specified in `CLI.md` §1. On clean shutdown the writer runs `PRAGMA wal_checkpoint(TRUNCATE)` and closes, so the WAL is removed.

### Identification (`internal/identify`)
OUI lookup from an embedded table generated from IEEE MA-L/MA-M/MA-S by `data/oui` tooling, plus an optional override file. Plugin interface (`Identify(evidence) []Identification`) reserved for phase 6+.

### API (`internal/api`) and CLI (`internal/cli`)
REST over `/run/lan-sentinel/api.sock` (mode 0660, owner `lan-sentinel`), optional `127.0.0.1` listener that also serves `/metrics`. The CLI is an API client by default and a read-only DB reader with `--offline`. Endpoints are listed in `IMPLEMENTATION_PLAN.md` phase 3; commands in `CLI.md`.

### Metrics (`internal/metrics`)
`lan_sentinel_hosts{interface,presence}`, `lan_sentinel_events_total{type}`, `lan_sentinel_probe_total{interface,protocol,port,result}`, `lan_sentinel_scan_duration_seconds`, `lan_sentinel_observations_total{source}`, `lan_sentinel_bus_dropped_total`, `lan_sentinel_capture_drops_total{interface}`, `lan_sentinel_db_size_bytes`, `lan_sentinel_observations_unbound_total{source}`, `lan_sentinel_active_disabled` (0/1), `lan_sentinel_probe_throttled_total{protocol,reason}`, `lan_sentinel_collector_up{interface,collector}`. No MAC, IP, hostname or host-ID labels.

## 4. Repository layout

```text
lan-sentinel/
├── cmd/lan-sentinel/            main.go: cobra root, daemon + CLI subcommands
├── internal/
│   ├── config/                  YAML schema, env (LAN_SENTINEL_*), flags, defaults, validation, SIGHUP reload
│   ├── platform/                Capturer, NeighborSource, InterfaceMonitor, Transmitter; fakes in platform/fake
│   ├── service/                 sd_notify notifier and journald slog handler
│   ├── iface/                   interface manager: contexts, prefixes, up/down (via platform.InterfaceMonitor)
│   ├── observation/             Observation type, Source enum, bounded bus with drop counters
│   ├── clock/                   wall clock and simulated clock
│   ├── collect/
│   │   ├── capture/             capture loop over platform.Capturer; decoders/: arp, ipv4, ipv6, ndp, dhcp, mdns, dns, lldp
│   │   ├── neighbor/            snapshot + watch + resync over platform.NeighborSource
│   │   └── replay/              pcap/pcapng and JSONL replay
│   ├── probe/
│   │   ├── scheduler/           intervals, jitter, startup delay, global rate limiter, excludes
│   │   ├── arp/  icmp/  ndp/  tcp/  udp/   (transmit via platform.Transmitter)
│   ├── correlate/               identity engine: match observation → host, conflicts
│   ├── state/                   in-memory current state, presence state machine, name preference
│   ├── events/                  event types, emitter, journald sink
│   ├── store/                   SQLite: migrations, repositories, batching, retention/compaction
│   ├── identify/                OUI lookup; plugin interface for later identification
│   ├── api/                     REST over Unix socket + optional 127.0.0.1 TCP
│   ├── buildinfo/               version, commit, date stamped via -ldflags
│   ├── daemon/                  lifecycle: config, store, collectors, SIGHUP reload, watchdog, shutdown
│   ├── logging/                 slog handler selection (journald, text, json)
│   ├── metrics/                 Prometheus registry, low-cardinality collectors
│   └── cli/                     API client, offline DB reader, table/json/jsonl/csv output
├── migrations/                  numbered .sql files embedded with go:embed
├── data/oui/                    generated OUI database + generator tool
├── build/                       dev container (dev.Dockerfile) and the scripts make runs in it
├── deploy/                      systemd unit, sysusers.d, tmpfiles.d, default config, config.dev.yaml (replay)
├── test/
│   ├── golden/                  golden observation streams + expected bindings, events, queries
│   ├── net/                     Docker network tests: run.sh + Go tests (build tag nettest)
│   └── fixtures/                pcap fixtures from real sites
├── tools/capcheck/              privilege and feasibility check (Linux; not released)
├── docs/
├── Makefile
└── CLAUDE.md
```

Tooling: a `Makefile` (`make` lists every target) whose Go commands all run in the Linux dev container (`build/dev.Dockerfile`: Go toolchain, pinned golangci-lint; caches on a named volume; runs as the calling user). Targets: `release` (static `linux/amd64` and `linux/arm64` binaries, version, commit and build date via `-ldflags`, static-linking check, `SHA256SUMS`); hygiene targets `fmt`/`fmt-check`, `tidy`/`tidy-check`, `mod-verify`, `vet`, `lint` (golangci-lint) and `vuln` (`govulncheck`, pinned as a Go tool in `go.mod`); `test`, `coverage`/`cover`, `fuzz` (every `Fuzz*` target, `FUZZTIME` each); the Docker suites `test-net` and `test-systemd` (§9); the gates `check` and `check-all`; `shell` and `run-dev`. CI runs the same targets: `make mod-verify check`, `make fuzz`, the Docker suites and `make release tools`.

## 5. OT safety controls

| Control | Default | Enforcement |
| --- | --- | --- |
| Active discovery | Disabled | Must be enabled per interface |
| Scan scope | Configured `networks` only | Discovered subnets are never scanned automatically |
| Max auto-scan prefix | /24 IPv4 | Wider prefixes refused at config validation unless `allow_wide_scan: true` |
| IPv6 sweeping | Never | Only NDP to addresses already observed |
| Packet rate | 20 pps total | Token bucket shared by all probe engines; a TCP connect costs 3 tokens |
| Per-protocol rate | ARP 10 pps, ICMP 5, NDP 5, UDP 5, TCP 5 connects/s | One bucket per engine beneath the global one |
| Concurrency | 10 probes | Semaphore across engines |
| TCP concurrency | 4 per interface, 1 per target host | Extra semaphores in the TCP engine |
| Per-target spacing | ≥ 1 s between any two probes to one IP | Checked before every send |
| Dry run | `scan plan` | Same planner as `scan run`; refuses identically |
| Startup delay | 30 s + jitter | Avoids ~1,000 boxes probing at once after a fleet update |
| Interval jitter | ±10% | Desynchronises sites over time |
| Target order | Randomised | Avoids sequential hammering |
| Excludes | Empty list | IPs/CIDRs never probed, checked before every send |
| TCP probe style | Full connect, immediate close | No SYN scans, no payload |
| Back-off | On | A host returning TIMEOUT 3 times is probed at 4× interval |
| Kill switch | `LAN_SENTINEL_ACTIVE_DISABLED=1`, API or `active disable` | Stops all probes within one tick without restart; API/CLI setting persists across restarts |

Passive capture opens sockets for receive only, never injects frames, and promiscuous mode is a per-interface opt-in.

## 6. Configuration

Precedence: flags → `LAN_SENTINEL_*` environment → `/etc/lan-sentinel/config.yaml` (or `$LAN_SENTINEL_CONFIG`) → compiled defaults. SIGHUP reloads probes, intervals, thresholds and log level; interface, storage, API, metrics and log-format changes require a restart and are reported as not applied.

If `logging.format` is left at its default (`journald`) and stderr is a terminal, the daemon logs text to stderr. If journald is configured but its socket is unreachable (e.g. `daemon run` outside systemd or in a container), it logs text to stderr with a warning.

```yaml
version: 1
interfaces:
  - name: eth0
    passive: { enabled: true, promiscuous: false }
    active:  { enabled: false }
  - name: eth1
    passive: { enabled: true, promiscuous: false }   # true only on a mirror/SPAN port
    active:
      enabled: true
      networks: [192.168.110.0/24]
      exclude:  [192.168.110.1]
passive:
  protocols: { arp: true, ipv4: true, ipv6: false, dhcp: true, mdns: true, dns: true, lldp: true }
neighbor:
  resync_interval: 10m              # full neighbour-table dump in addition to notifications
active:
  startup_delay: 30s
  jitter: 0.1
  max_packets_per_second: 20       # global ceiling; a TCP connect costs 3
  max_concurrent_probes: 10
  min_target_interval: 1s          # spacing between probes to one IP
  budgets:                         # each <= the global ceiling; tcp connects × 3 <= it too
    arp:  { packets_per_second: 10 }
    icmp: { packets_per_second: 5 }
    ndp:  { packets_per_second: 5 }
    udp:  { packets_per_second: 5 }
    tcp:  { connects_per_second: 5, max_concurrent_per_interface: 4, max_concurrent_per_host: 1 }
  max_auto_scan_prefix_v4: 24
  allow_wide_scan: false
  arp:  { enabled: true,  interval: 5m }
  icmp: { enabled: false, interval: 10m }
  tcp:
    enabled: true
    interval: 5m
    targets:
      - { port: 502, name: modbus, timeout: 750ms }
profiles:
  modbus:
    arp: true
    tcp: [502]
presence: { active: 5m, recent: 30m, stale: 24h }
identity:
  hostname_preference: [mdns, dhcp, dns_ptr, lldp]
  address_overlap: 5m         # older open IPv4 binding is replaced, not kept alongside
  address_expiry: 24h         # unconfirmed binding closed while host is otherwise seen
  name_expiry: 168h
  proxy_arp_threshold: 16
  oui_override: ""            # optional path
storage:
  path: /data/lan-sentinel/hosts.db
  retention:
    observations: 168h    # raw
    rollups: 2160h        # hourly roll-ups
    events: 17520h
    max_db_size: 200MB    # prune observations, then roll-ups, then oldest events
api:
  socket: /run/lan-sentinel/api.sock
  listen: ""              # e.g. 127.0.0.1:9734 (also serves /metrics)
metrics: { enabled: true }
logging:
  level: info               # trace | debug | info | warn | error
  format: journald          # journald | json | text
```

Replay interface (works on any development machine; `deploy/config.dev.yaml` uses this):

```yaml
version: 1
interfaces:
  - name: eth1
    prefixes: [192.168.110.0/24]            # replaces the interface manager
    replay:
      file: test/fixtures/site-a-eth1.pcapng  # .pcap, .pcapng or .jsonl
      speed: 0                               # 0 = simulated clock, as fast as possible; N = real time x N
replay: { exit_when_done: false }
storage: { path: ./dev/hosts.db }
api:     { socket: ./dev/api.sock }
logging: { level: debug, format: text }
```

`replay` is mutually exclusive with `passive` and `active` on the same interface.

## 7. Logging

Each event is one journald entry with structured fields (`EVENT=ip_changed`, `IFACE`, `MAC`, `OLD_IP`, `NEW_IP`, `HOST_ID`, `SOURCE`) and a readable `MESSAGE`. Priority: notice for changes, warning for `DUPLICATE_IP_DETECTED`, `MAC_MOVED`, `ACTIVE_DISABLED` and `INTERFACE_DOWN`, error for daemon faults. `journalctl -u lan-sentinel EVENT=ip_changed` works directly. Observations are never logged.

## 8. systemd and privileges

```ini
[Unit]
Description=LAN Sentinel
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/lan-sentinel daemon run --config /etc/lan-sentinel/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
User=lan-sentinel
Group=lan-sentinel
UMask=0027
WatchdogSec=60
Restart=on-failure
RuntimeDirectory=lan-sentinel
RuntimeDirectoryMode=0750
ReadWritePaths=/data/lan-sentinel
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectProc=invisible
ProcSubset=pid
PrivateIPC=true
DevicePolicy=closed
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM
MemoryMax=128M
CPUQuota=20%

[Install]
WantedBy=multi-user.target
```

`CAP_NET_ADMIN` is expected not to be needed: netlink neighbour, link and address dumps and multicast subscriptions work unprivileged, and promiscuous mode is set through `PACKET_ADD_MEMBERSHIP` (`PACKET_MR_PROMISC`) on the packet socket rather than `SIOCSIFFLAGS` (which would need `CAP_NET_ADMIN`). This is an assumption until the phase 0 capability check passes on each target kernel under this exact unit:

| Operation | Expected requirement |
| --- | --- |
| `AF_PACKET` socket, TPACKET_V3 ring, BPF attach | `CAP_NET_RAW` |
| `PACKET_ADD_MEMBERSHIP` with `PACKET_MR_PROMISC` | `CAP_NET_RAW` |
| ARP / NDP transmit on `AF_PACKET` | `CAP_NET_RAW` |
| ICMP via ping socket | none, if GID within `net.ipv4.ping_group_range` |
| ICMP via raw socket | `CAP_NET_RAW` |
| rtnetlink dump and `RTNLGRP_NEIGH`/`LINK`/`IPV4_IFADDR`/`IPV6_IFADDR` subscribe | none |
| TCP `connect()` | none |
| `SO_BINDTODEVICE` on probe sockets | `CAP_NET_RAW` (kernels < 5.7), none on newer |

Run `tools/capcheck` under the reference unit's identity on each target board (`tools/capcheck/README.md`) and record kernel version, board and results below. `make test-net` runs the same check in Docker on every change. If any row needs `CAP_NET_ADMIN` or root, stop and decide before continuing.

| System | Kernel | Date | Result |
| --- | --- | --- | --- |
| Docker test network (`make test-net`), uid 65534, ambient `CAP_NET_RAW` only | 7.0.14-linuxkit arm64 | 2026-10-05 | PASS, every row above, including ARP/NDP transmit, ping and raw ICMP, bound TCP connect; AF_PACKET refused without `CAP_NET_RAW` |
| systemd in a container (`make test-systemd`), transient unit with this unit's `[Service]` settings | 7.0.14-linuxkit arm64, systemd 252 | 2026-10-05 | PASS, every row above; daemon runs as `lan-sentinel` with `CapEff`/`CapBnd` = `CAP_NET_RAW`; `systemd-analyze security` exposure 1.6 |
| RevPi Connect | (pending) | | |
| amd64 edge box | (pending) | | |

The process stays in the foreground; systemd owns its lifecycle (no double-fork). `make test-systemd` runs this unit unchanged in a systemd container on every change and fails if the exposure rises above 2.5 or capcheck fails under its sandbox.

## 9. Development and testing

The code base is Linux only. Every make target that runs Go runs in the Linux dev container (`build/dev.Dockerfile`), so development machines, Linux or macOS, need only Docker, make and git, and CI runs exactly the same commands. The container runs as the calling user with Go, lint and module caches on the `lan-sentinel-cache` volume; `make shell` opens a shell in it and `make run-dev` runs the daemon there on a replay file. On macOS, editors should run gopls with `GOOS=linux`.

| Layer | Command |
| --- | --- |
| Format, tidy, vet, lint, vulnerabilities, unit and golden tests with race and coverage | `make check` |
| Fuzz targets (every `Fuzz*`) | `make fuzz` |
| Network integration (Docker test network, `CAP_NET_RAW` only) | `make test-net` |
| systemd unit, sandbox and privileges (systemd container) | `make test-systemd` |
| Privilege check on real hardware | `tools/capcheck` on the target boards (§8) |

`make test-net` builds the test binaries in the dev container (`build/test-bins.sh`, for the Docker host's architecture), then `test/net/run.sh` creates a bridge network with fixed subnets (`172.31.250.0/24`, `fd5e:5e:1::/64`) standing in for an OT LAN. Simulated hosts are `busybox` containers: one with a TCP listener on port 502 (`.10`), one without (`.11`, REFUSED), and an unused address (`.99`, TIMEOUT). The runner container starts with only `CAP_NET_RAW` (plus the capabilities `setpriv` needs to drop privileges) and runs the tests as uid 65534 with ambient `CAP_NET_RAW`, mirroring the systemd unit. It runs `capcheck` with and without the capability, then every Go test package under `test/net` built with the `nettest` tag; those read the network layout from `LS_TEST_*` environment variables.

Docker's kernel is not the target kernel, so the board check in §8 stays mandatory.
