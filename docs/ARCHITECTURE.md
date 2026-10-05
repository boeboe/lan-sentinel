# LAN Sentinel — Architecture

Every collector emits normalised observations onto one bus, on Linux and darwin alike; a single correlation goroutine owns identity and state, so collectors never touch the database directly.

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

Only the correlator writes state and events. The log sink (journald on Linux, JSON lines on darwin) receives state transitions straight from the event engine, never raw observations.

The interface manager, capture, neighbour and probe-transmit layers each have a Linux and a darwin backend behind a small interface (§3, Platform layer). Everything else, including the probe scheduler and budgets, is shared code. A replay collector can stand in for live collection on either platform.

## 2. Key decisions

| Decision | Choice | Why |
| --- | --- | --- |
| Host identity | Within a context, host = MAC (one-to-one); internal UUID `host_id` as record key; no merge/split | The MAC is the only reliable same-device evidence on L2; multi-NIC devices are several hosts, a NIC swap is a new host |
| Network scoping | Every host keyed by `network_context` = interface; subnets kept as history | Same IP or MAC on `eth0` and `eth1` is not the same host; readdressing does not split history |
| Data flow | Collectors → observation channel → correlator → state + events → SQLite | Collectors stay independent and testable; one writer avoids lock contention |
| Concurrency | One correlator goroutine; collectors and probes in their own goroutines under `errgroup` | Deterministic ordering of state changes |
| Storage | SQLite in WAL mode, single writer, batched transactions | Atomic, crash-safe, one portable file, queryable |
| SQLite driver | `modernc.org/sqlite` (pure Go) | No cgo; supports all four targets |
| Packet capture | Linux: `AF_PACKET` TPACKET_V3 via `gopacket/afpacket`. Darwin: `/dev/bpf*` via `golang.org/x/sys/unix` ioctls. Same classic-BPF filter (`golang.org/x/net/bpf`) on both | No cgo, no libpcap; kernel-side filtering keeps CPU low |
| Neighbours and interfaces | Linux: `vishvananda/netlink` subscriptions. Darwin: `golang.org/x/net/route` (routing socket + `sysctl` RIB dumps). Periodic resync on both | Event-driven where the kernel allows; resync covers missed notifications |
| ARP/NDP send | Linux: `AF_PACKET` (`mdlayher/arp`, `mdlayher/ndp`). Darwin: frames encoded with `gopacket/layers` and written to a BPF device (`BIOCSHDRCMPLT`) | Linux needs only `CAP_NET_RAW`; darwin needs only BPF device access |
| TCP probes | Plain `net.Dialer` connect with timeout, immediate close, bound to the interface (`SO_BINDTODEVICE` / `IP_BOUND_IF`) | Safe for OT; classifies OPEN / REFUSED / TIMEOUT / UNREACHABLE; leaves via the probed interface |
| Presence | ACTIVE / RECENT / STALE / MISSING, configurable thresholds | Quiet PLCs are not offline |
| Logging | `log/slog`: journald handler on Linux, JSON lines on stderr under launchd on darwin, text on a terminal; transitions only | No journal spam; no cgo needed for macOS unified logging |
| Service manager | systemd (`Type=notify`, watchdog) on Linux; launchd LaunchDaemon (`KeepAlive`) on darwin | Native supervisor on each OS |
| CLI | One binary with cobra subcommands; client over Unix socket, `--offline` reads DB | Single static operational tool |
| Build | Go 1.23+, `CGO_ENABLED=0`, `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`; minimum Linux 5.10, macOS 14 | One executable per target, no third-party runtime deps; static on Linux, `libSystem` on darwin (Apple does not support static executables) |
| Platforms | Linux and darwin are both development and delivery platforms with full feature parity; OS code behind small interfaces in `_linux.go` / `_darwin.go` files | Linux assumptions cannot leak into the core |
| Replay | pcap/pcapng or JSONL replay through the real decoders and correlator, with a simulated clock | Reproduce site behaviour and run golden tests on any platform |
| Delivery | Four binaries + checksums; reference files in `deploy/` | No packaging requirement |

## 3. Components

### Interface manager (`internal/iface`)
Enumerates links and addresses (netlink on Linux; `net.Interfaces` plus routing-socket `RTM_IFINFO`/`RTM_NEWADDR`/`RTM_DELADDR` on darwin), derives one network context per configured interface name, records the interface's own prefixes over time (`context_prefixes`), follows link and address changes at runtime, and emits `INTERFACE_UP`, `INTERFACE_DOWN` and `SUBNET_CHANGED`. The current prefixes feed the correlator's on-link check (`DATA_MODEL.md` §5.2). Collectors start and stop per interface as links come and go.

### Observation bus (`internal/observation`)
A bounded Go channel of `Observation` values (see `DATA_MODEL.md` §2). When full, new observations are dropped and `lan_sentinel_bus_dropped_total` increments; collectors never block on the correlator.

### Passive capture (`internal/collect/capture`)
One capture handle per interface with a classic-BPF filter restricted to ARP, NDP/ICMPv6, DHCP (67/68), mDNS (5353), DNS (53) responses, LLDP (EtherType 0x88cc), and IPv4/IPv6 headers for source-address learning. Decoders are pure functions from frame to zero or more observations, shared by both backends and by replay.

- **Linux:** `AF_PACKET` TPACKET_V3 ring; promiscuous mode via `PACKET_ADD_MEMBERSHIP`.
- **Darwin:** a cloned `/dev/bpf*` device bound with `BIOCSETIF`, `BIOCIMMEDIATE`, `BIOCSBLEN`, `BIOCSETF`, `BIOCSSEESENT=0`; promiscuous mode via `BIOCPROMISC`. Capture drops come from `BIOCGSTATS`. Requires read access to `/dev/bpf*` (§9).

On a switched port, capture sees traffic to/from the box, broadcast, multicast, ARP, mDNS, IPv6 multicast and some switch control traffic, but not unicast between other devices unless the port is mirrored. That is expected and sufficient for discovery.

### Replay collector (`internal/collect/replay`)
Portable. Reads a pcap/pcapng file (via the pure-Go `gopacket/pcapgo` reader, frames decoded by the capture package's decoders) or a JSONL file of `Observation` values, and emits them for the configured interface with their recorded source and timestamp. In `speed: 0` mode it advances a simulated clock (`internal/clock`) to each observation's timestamp before emitting it and blocks until the correlator has consumed it, so presence and expiry timers fire exactly as they would have at the site; `speed: N` replays in real time × N. When every replay source is exhausted the daemon keeps serving the API (or exits with `replay.exit_when_done: true`, used by tests).

### Clock (`internal/clock`)
All components that read time (correlator, presence ticker, expiry, scheduler, compaction) take a `clock.Clock`. Production uses the wall clock; replay and tests use a simulated clock.

### Platform layer (`internal/platform`)
Four small interfaces, each with a `_linux.go` and a `_darwin.go` implementation; nothing outside these packages and the service glue imports OS-specific code:

| Interface | Methods (sketch) | Linux | Darwin |
| --- | --- | --- | --- |
| `Capturer` | `Open(iface, filter, promisc) (FrameSource, error)`, `Stats()` | `AF_PACKET` ring | `/dev/bpf*` |
| `NeighborSource` | `Snapshot(ctx) ([]Neighbor, error)`, `Watch(ctx) (<-chan NeighborEvent, error)` | rtnetlink | routing socket + `sysctl` |
| `InterfaceMonitor` | `List(ctx)`, `Watch(ctx) (<-chan LinkEvent, error)` | rtnetlink | routing socket |
| `Transmitter` | `SendFrame(iface, frame)`, `DialTCP(iface, addr, timeout)`, `PingSocket(iface)` | `AF_PACKET`, `SO_BINDTODEVICE`, ping/raw socket | BPF write, `IP_BOUND_IF`, datagram ICMP socket |

Each backend reports availability per interface (`running`, `disabled`, `unsupported`, `failed` with error) to the collector registry, which feeds `daemon status` and `lan_sentinel_collector_up`. Service glue (`sd_notify`, journald) is likewise split, with no-ops on darwin. Shared tests run against fake implementations of these interfaces.

### Neighbour collector (`internal/collect/neighbor`)
Reads the kernel neighbour table at startup, then follows notifications (`RTM_NEWNEIGH`/`RTM_DELNEIGH` on Linux; routing-socket `RTM_ADD`/`RTM_DELETE`/`RTM_CHANGE` for `RTF_LLINFO` routes on darwin) and resynchronises with a full snapshot after notification loss and every `neighbor.resync_interval`. Emits source `kernel_neighbor` with `Meta{backend, raw_state}` and a normalised state. `STALE` means unconfirmed reachability, not offline. Darwin notification coverage is validated in the phase 0 spike; the darwin resync default is short (60 s) until then.

### Active probes (`internal/probe`)
A shared scheduler runs independent probe engines (ARP, ICMP, NDP, TCP, UDP) per interface; engines build packets in shared code and transmit through the platform `Transmitter`. Each engine draws from its own protocol token bucket and from one global token bucket (packets/s; a TCP connect costs 3 tokens), and holds a slot of one global semaphore (concurrency). TCP additionally holds a per-interface and a per-target-host semaphore, and every target has a minimum spacing between probes. The scheduler applies startup delay, jitter, randomised target order, excludes, the prefix guard, timeout back-off and the kill switch. The same planner computes `scan plan` dry runs and gates `scan run`. See §5.

### Correlator (`internal/correlate`) and state (`internal/state`)
Single goroutine. Applies the correlation rules (`DATA_MODEL.md` §5), maintains in-memory current state, runs the presence state machine and binding expiry on a ticker, derives `preferred_name`, and hands state changes to the store and events to the event engine. Observations that match no host are stored unbound and counted.

### Event engine (`internal/events`)
Builds events from state transitions, attaches the evidence snapshot (`DATA_MODEL.md` §7), writes them to the store and to the log sink.

### Store (`internal/store`)
Owns the single SQLite writer goroutine, migrations, repositories, batched commits (target 5 s), retention, roll-up and compaction (hourly, small batches). Exposes read-only query functions used by the API and by `--offline`; the offline open procedure is specified in `CLI.md` §1. On clean shutdown the writer runs `PRAGMA wal_checkpoint(TRUNCATE)` and closes, so the WAL is removed.

### Identification (`internal/identify`)
OUI lookup from an embedded table generated from IEEE MA-L/MA-M/MA-S by `data/oui` tooling, plus an optional override file. Plugin interface (`Identify(evidence) []Identification`) reserved for phase 6+.

### API (`internal/api`) and CLI (`internal/cli`)
REST over the platform socket path (§6; mode 0660, owned by the service user and group), optional `127.0.0.1` listener that also serves `/metrics`. The CLI is an API client by default and a read-only DB reader with `--offline`. Endpoints are listed in `IMPLEMENTATION_PLAN.md` phase 3; commands in `CLI.md`.

### Metrics (`internal/metrics`)
`lan_sentinel_hosts{interface,presence}`, `lan_sentinel_events_total{type}`, `lan_sentinel_probe_total{interface,protocol,port,result}`, `lan_sentinel_scan_duration_seconds`, `lan_sentinel_observations_total{source}`, `lan_sentinel_bus_dropped_total`, `lan_sentinel_capture_drops_total{interface}`, `lan_sentinel_db_size_bytes`, `lan_sentinel_observations_unbound_total{source}`, `lan_sentinel_active_disabled` (0/1), `lan_sentinel_probe_throttled_total{protocol,reason}`, `lan_sentinel_collector_up{interface,collector}`. No MAC, IP, hostname or host-ID labels.

## 4. Repository layout

```text
lan-sentinel/
├── cmd/lan-sentinel/            main.go: cobra root, daemon + CLI subcommands
├── internal/
│   ├── config/                  YAML schema, env (LAN_SENTINEL_*), flags, defaults, validation, SIGHUP reload
│   ├── platform/                Capturer, NeighborSource, InterfaceMonitor, Transmitter; *_linux.go, *_darwin.go
│   ├── service/                 sd_notify + journald (linux), launchd/JSON glue (darwin), daemon prepare (darwin)
│   ├── iface/                   interface manager: contexts, prefixes, up/down (via platform.InterfaceMonitor)
│   ├── observation/             Observation type, Source enum, bounded bus with drop counters
│   ├── clock/                   wall clock and simulated clock
│   ├── collect/
│   │   ├── capture/             capture loop over platform.Capturer; decoders/: arp, ipv4, ipv6, ndp, dhcp, mdns, dns, lldp
│   │   ├── neighbor/            snapshot + watch + resync over platform.NeighborSource
│   │   └── replay/              pcap/pcapng and JSONL replay (portable)
│   ├── probe/
│   │   ├── scheduler/           intervals, jitter, startup delay, global rate limiter, excludes
│   │   ├── arp/  icmp/  ndp/  tcp/  udp/   (transmit via platform.Transmitter)
│   ├── correlate/               identity engine: match observation → host, conflicts
│   ├── state/                   in-memory current state, presence state machine, name preference
│   ├── events/                  event types, emitter, log sink
│   ├── store/                   SQLite: migrations, repositories, batching, retention/compaction
│   ├── identify/                OUI lookup; plugin interface for later identification
│   ├── api/                     REST over Unix socket + optional 127.0.0.1 TCP
│   ├── metrics/                 Prometheus registry, low-cardinality collectors
│   └── cli/                     API client, offline DB reader, table/json/jsonl/csv output
├── migrations/                  numbered .sql files embedded with go:embed
├── data/oui/                    generated OUI database + generator tool
├── deploy/
│   ├── linux/                   systemd unit, sysusers.d, tmpfiles.d, default config
│   ├── darwin/                  LaunchDaemon plists (daemon, prepare), newsyslog.d, default config, setup README
│   └── config.dev.yaml          replay config for local development
├── test/                        netns (linux) and feth (darwin) integration tests, pcap fixtures, golden streams
├── docs/
├── Makefile
└── CLAUDE.md
```

Tooling: `golangci-lint` (run for `GOOS=linux` and `GOOS=darwin`); a `Makefile` `release` target producing binaries for `linux/amd64`, `linux/arm64`, `darwin/amd64` and `darwin/arm64` with version, commit and build date stamped via `-ldflags`, plus `SHA256SUMS`; `run-dev` running the daemon with `deploy/config.dev.yaml`; CI on a Linux and a macOS runner running unit and golden tests with `-race`, `go vet` and lint, plus the native network suite on each (`make test-net`: network namespaces + veth on Linux, `feth` pairs on darwin; both need root). The Linux suite can also run in a Linux VM on a Mac (OrbStack, Colima or Lima).

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

Precedence: flags → `LAN_SENTINEL_*` environment → config file → compiled defaults. Compiled default paths are per platform:

| Item | Linux | darwin |
| --- | --- | --- |
| Binary | `/usr/local/bin/lan-sentinel` | `/usr/local/bin/lan-sentinel` |
| Config | `/etc/lan-sentinel/config.yaml` | `/usr/local/etc/lan-sentinel/config.yaml` |
| Database | `/data/lan-sentinel/hosts.db` | `/usr/local/var/lan-sentinel/hosts.db` |
| API socket | `/run/lan-sentinel/api.sock` | `/var/run/lan-sentinel/api.sock` |
| Log | journald | `/var/log/lan-sentinel/daemon.log` (JSON lines, `newsyslog`) |
| Log format default | `journald` | `json` (or `text` on a terminal) |
| Service user/group | `lan-sentinel` | `_lan-sentinel` (+ `access_bpf`) |

Development runs on either OS use `deploy/config.dev.yaml` (paths under `./dev/`).

Darwin limits Unix socket paths to 103 bytes; config validation rejects longer paths. SIGHUP reloads probes, intervals, thresholds and log level; interface and storage changes require a restart.

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
  resync_interval: 10m              # platform default: 10m Linux, 60s darwin
darwin:
  bpf_devices: 8                    # darwin only: /dev/bpf* clones prepared at boot
active:
  startup_delay: 30s
  jitter: 0.1
  max_packets_per_second: 20       # global ceiling; a TCP connect costs 3
  max_concurrent_probes: 10
  min_target_interval: 1s          # spacing between probes to one IP
  budgets:                         # each must be <= the global ceiling
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
logging: { level: info, format: journald }   # journald | text | json
```

Replay interface (both platforms; `deploy/config.dev.yaml` uses this):

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

Each event is one journald entry (Linux) or one JSON line (darwin) with the same structured fields (`EVENT=ip_changed`, `IFACE`, `MAC`, `OLD_IP`, `NEW_IP`, `HOST_ID`, `SOURCE`) and a readable `MESSAGE`. Priority: notice for changes, warning for `DUPLICATE_IP_DETECTED`, `MAC_MOVED`, `ACTIVE_DISABLED` and `INTERFACE_DOWN`, error for daemon faults. `journalctl -u lan-sentinel EVENT=ip_changed` works directly on Linux; on darwin the log file is filterable with `jq`. Observations are never logged.

## 8. systemd and privileges (Linux)

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
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET AF_NETLINK
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
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

Results (kernel version, board, pass/fail) are recorded in this table. If any row needs `CAP_NET_ADMIN` or root, stop and decide before continuing. The process stays in the foreground; systemd owns its lifecycle (no double-fork).

## 9. launchd and privileges (darwin)

Two LaunchDaemons in `/Library/LaunchDaemons/`, reference copies in `deploy/darwin/`:

| Job | Runs as | What it does |
| --- | --- | --- |
| `lan-sentinel-prepare` | root, `RunAtLoad`, exits | `lan-sentinel daemon prepare`: pre-creates `/dev/bpf*` clones up to the configured count (`darwin.bpf_devices`, default 8), sets them `root:access_bpf 0660`, creates `/var/run/lan-sentinel` owned by `_lan-sentinel` (0750). The same approach as Wireshark's ChmodBPF; compatible with it if installed. |
| `lan-sentinel` | `_lan-sentinel:_lan-sentinel`, member of `access_bpf` | `lan-sentinel daemon run`; `KeepAlive` (restart on exit), `ProcessType=Background`, `Umask=23` (0027), `StandardErrorPath=/var/log/lan-sentinel/daemon.log`. |

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>lan-sentinel</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/lan-sentinel</string>
    <string>daemon</string><string>run</string>
    <string>--config</string><string>/usr/local/etc/lan-sentinel/config.yaml</string>
  </array>
  <key>UserName</key><string>_lan-sentinel</string>
  <key>GroupName</key><string>_lan-sentinel</string>
  <key>Umask</key><integer>23</integer>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardErrorPath</key><string>/var/log/lan-sentinel/daemon.log</string>
</dict>
</plist>
```

User, group, `access_bpf` membership and directories are created once by the operator following `deploy/darwin/README.md` (`dscl`/`dseditgroup` commands); there is no installer. Reload: `sudo launchctl kill HUP system/lan-sentinel`.

Expected privileges, verified in the phase 0 darwin spike on macOS 14 and the current release, results recorded here:

| Operation | Expected requirement |
| --- | --- |
| Open `/dev/bpf*`, `BIOCSETIF`, `BIOCSETF`, read | read/write on the device (group `access_bpf`) |
| `BIOCPROMISC` | same device access |
| ARP / NDP transmit via BPF write (`BIOCSHDRCMPLT`) | same device access |
| ICMP echo via `SOCK_DGRAM`/`IPPROTO_ICMP` | none |
| Routing socket (`AF_ROUTE`) read and `sysctl` RIB/`NET_RT_FLAGS`+`RTF_LLINFO` dumps | none |
| TCP `connect()` with `IP_BOUND_IF` | none |

If any operation needs root in the long-running daemon, stop and decide before continuing.
