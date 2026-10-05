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
   │ Passive capture │     │     Netlink      │     │  Active probes   │
   │ AF_PACKET + BPF │     │ neighbour dump + │     │ scheduler, rate  │
   │ ARP IPv4 IPv6   │     │ NEW/DELNEIGH,NUD │     │ limit, jitter    │
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
                      │ SQLite (WAL), single writer  │   │ journald │
                      │ /data/lan-sentinel/hosts.db  │   └──────────┘
                      └───────┬──────────────┬───────┘
                              ▼              ▼
                     ┌──────────────┐  ┌──────────────┐
                     │ REST API     │  │ Prometheus   │
                     │ Unix socket  │  │ /metrics     │
                     │ → CLI, watch │  │              │
                     └──────────────┘  └──────────────┘
```

Only the correlator writes state and events. journald receives state transitions straight from the event engine, never raw observations.

## 2. Key decisions

| Decision | Choice | Why |
| --- | --- | --- |
| Host identity | Within a context, host = MAC (one-to-one); internal UUID `host_id` as record key; no merge/split | The MAC is the only reliable same-device evidence on L2; multi-NIC devices are several hosts, a NIC swap is a new host |
| Network scoping | Every host keyed by `network_context` = interface; subnets kept as history | Same IP or MAC on `eth0` and `eth1` is not the same host; readdressing does not split history |
| Data flow | Collectors → observation channel → correlator → state + events → SQLite | Collectors stay independent and testable; one writer avoids lock contention |
| Concurrency | One correlator goroutine; collectors and probes in their own goroutines under `errgroup` | Deterministic ordering of state changes |
| Storage | SQLite in WAL mode, single writer, batched transactions | Atomic, crash-safe, one portable file, queryable |
| SQLite driver | `modernc.org/sqlite` (pure Go) | No cgo; static cross-compile |
| Packet capture | `AF_PACKET` with BPF filter via `gopacket/afpacket` (no libpcap) | No cgo; kernel-side filtering keeps CPU low |
| Netlink | `vishvananda/netlink` neighbour + link + address subscriptions | Event-driven, no `ip neigh` polling |
| ARP/NDP send | Raw `AF_PACKET` socket (`mdlayher/arp`, `mdlayher/ndp`) | Needs only `CAP_NET_RAW` |
| TCP probes | Plain `net.Dialer` connect with timeout, immediate close | Safe for OT; classifies OPEN / REFUSED / TIMEOUT / UNREACHABLE |
| Presence | ACTIVE / RECENT / STALE / MISSING, configurable thresholds | Quiet PLCs are not offline |
| Logging | `log/slog` with a journald handler; transitions only | No journal spam |
| CLI | One binary with cobra subcommands; client over Unix socket, `--offline` reads DB | Single static operational tool |
| Build | Go 1.23+, `CGO_ENABLED=0`, `linux/amd64` and `linux/arm64` | Fits target hardware; no runtime deps |
| Delivery | Static binaries + checksums; reference files in `deploy/` | No packaging requirement |

## 3. Components

### Interface manager (`internal/iface`)
Enumerates links and addresses through netlink, derives one network context per configured interface name, records the interface's own prefixes over time (`context_prefixes`), follows link and address changes at runtime, and emits `INTERFACE_UP`, `INTERFACE_DOWN` and `SUBNET_CHANGED`. The current prefixes feed the correlator's on-link check (`DATA_MODEL.md` §5.2). Collectors start and stop per interface as links come and go.

### Observation bus (`internal/observation`)
A bounded Go channel of `Observation` values (see `DATA_MODEL.md` §2). When full, new observations are dropped and `lan_sentinel_bus_dropped_total` increments; collectors never block on the correlator.

### Passive capture (`internal/collect/capture`)
One `AF_PACKET` TPACKET_V3 ring per interface with a BPF filter restricted to ARP, NDP/ICMPv6, DHCP (67/68), mDNS (5353), DNS (53) responses, LLDP (EtherType 0x88cc), and IPv4/IPv6 headers for source-address learning. Promiscuous mode is set with `PACKET_ADD_MEMBERSHIP` when enabled. Decoders are pure functions from frame to zero or more observations.

On a switched port, capture sees traffic to/from the box, broadcast, multicast, ARP, mDNS, IPv6 multicast and some switch control traffic, but not unicast between other devices unless the port is mirrored. That is expected and sufficient for discovery.

### Netlink neighbour collector (`internal/collect/neighbor`)
Dumps the neighbour table at startup, then subscribes to `RTM_NEWNEIGH`/`RTM_DELNEIGH`. NUD state is metadata; `STALE` means unconfirmed reachability, not offline.

### Active probes (`internal/probe`)
A scheduler runs independent probe engines (ARP, ICMP, TCP, UDP) per interface. Each engine draws from its own protocol token bucket and from one global token bucket (packets/s; a TCP connect costs 3 tokens), and holds a slot of one global semaphore (concurrency). TCP additionally holds a per-interface and a per-target-host semaphore, and every target has a minimum spacing between probes. The scheduler applies startup delay, jitter, randomised target order, excludes, the prefix guard, timeout back-off and the kill switch. The same planner computes `scan plan` dry runs and gates `scan run`. See §5.

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
`lan_sentinel_hosts{interface,presence}`, `lan_sentinel_events_total{type}`, `lan_sentinel_probe_total{interface,protocol,port,result}`, `lan_sentinel_scan_duration_seconds`, `lan_sentinel_observations_total{source}`, `lan_sentinel_bus_dropped_total`, `lan_sentinel_capture_drops_total{interface}`, `lan_sentinel_db_size_bytes`, `lan_sentinel_observations_unbound_total{source}`, `lan_sentinel_active_disabled` (0/1), `lan_sentinel_probe_throttled_total{protocol,reason}`. No MAC, IP, hostname or host-ID labels.

## 4. Repository layout

```text
lan-sentinel/
├── cmd/lan-sentinel/            main.go: cobra root, daemon + CLI subcommands
├── internal/
│   ├── config/                  YAML schema, env (LAN_SENTINEL_*), flags, defaults, validation, SIGHUP reload
│   ├── iface/                   interface manager: links, addresses, subnets, up/down via netlink
│   ├── observation/             Observation type, Source enum, bounded bus with drop counters
│   ├── collect/
│   │   ├── capture/             AF_PACKET + BPF, decoders: arp, ipv4, ipv6, ndp, dhcp, mdns, dns, lldp
│   │   └── neighbor/            netlink neighbour dump + RTM_NEWNEIGH/DELNEIGH subscription
│   ├── probe/
│   │   ├── scheduler/           intervals, jitter, startup delay, global rate limiter, excludes
│   │   ├── arp/  icmp/  tcp/  udp/
│   ├── correlate/               identity engine: match observation → host, conflicts
│   ├── state/                   in-memory current state, presence state machine, name preference
│   ├── events/                  event types, emitter, journald sink
│   ├── store/                   SQLite: migrations, repositories, batching, retention/compaction
│   ├── identify/                OUI lookup; plugin interface for later identification
│   ├── api/                     REST over Unix socket + optional 127.0.0.1 TCP
│   ├── metrics/                 Prometheus registry, low-cardinality collectors
│   └── cli/                     API client, offline DB reader, table/json/jsonl/csv output
├── migrations/                  numbered .sql files embedded with go:embed
├── data/oui/                    generated OUI database + generator tool
├── deploy/                      reference systemd unit, sysusers.d, tmpfiles.d, default config
├── test/                        netns integration tests, pcap fixtures
├── docs/
├── Makefile
└── CLAUDE.md
```

Tooling: `golangci-lint`; a `Makefile` `release` target producing static binaries for `linux/amd64` and `linux/arm64` with version, commit and build date stamped via `-ldflags`, plus `SHA256SUMS`; CI running unit tests with `-race`, `go vet`, lint and the netns integration suite.

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

Precedence: flags → `LAN_SENTINEL_*` environment → `/etc/lan-sentinel/config.yaml` → compiled defaults. SIGHUP reloads probes, intervals, thresholds and log level; interface and storage changes require a restart.

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
logging: { level: info, format: journald }
```

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

Results (kernel version, board, pass/fail) are recorded in this table. If any row needs `CAP_NET_ADMIN` or root, stop and decide before continuing. The process stays in the foreground; systemd owns its lifecycle (no double-fork).
