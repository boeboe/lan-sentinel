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
| ARP send | Request frames built with `gopacket/layers`, sent and received on an `AF_PACKET` socket bound to the interface behind the platform `Transmitter` (no `mdlayher` libraries); NDP probing deferred (v1 is IPv4-first) | Needs only `CAP_NET_RAW`; protocol logic stays out of the platform layer, so engines are tested against fakes |
| TCP probes | Bare connect: plain `net.Dialer` connect with timeout, bound to the interface with `SO_BINDTODEVICE`, SYN retransmissions capped (`TCP_SYNCNT` 2), closed at once with a RST (`SO_LINGER` 0). The RST close is for bare connects only; a protocol-specific TCP probe that exchanges data (none in v1) closes orderly with FIN | Safe for OT: no payload, at most 3 packets per connect (§5), no connection left in `TIME_WAIT` or `CLOSE_WAIT` on either side; classifies OPEN / REFUSED / TIMEOUT / UNREACHABLE; leaves via the probed interface |
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
Enumerates links and addresses through netlink, derives one network context per configured interface name, records the interface's own prefixes over time (`context_prefixes`), follows link and address changes at runtime, and publishes each configured interface's state (present, up, own prefixes) on the observation bus. The correlator turns changes into `context_prefixes` history and `INTERFACE_UP`, `INTERFACE_DOWN` and `SUBNET_CHANGED` events, in order with observations, so the on-link check (`DATA_MODEL.md` §5.2) always uses the prefixes in effect at the time.

### Observation bus (`internal/observation`)
A bounded Go channel carrying `Observation` values (see `DATA_MODEL.md` §2), interface states and barriers. When full, new observations from live collectors are dropped and `lan_sentinel_bus_dropped_total` increments; collectors never block on the correlator. Interface states and replayed observations are never dropped (they wait). A barrier returns once everything before it has been processed; shutdown and replay use it to drain the bus.

### Passive capture (`internal/collect/capture`)
One receive-only `AF_PACKET` TPACKET_V3 ring per interface (`passive.ring_size`, default 2 MiB, in 128 KiB blocks handed over at least every 100 ms) with a classic-BPF filter built from `passive.protocols`: ARP, LLDP (EtherType 0x88cc), NDP (ICMPv6 133–137), DHCP (67/68), mDNS (from 5353) and DNS responses (from 53) are captured whole; other IPv4 and IPv6 frames are truncated to their first 96 bytes for source-address learning; everything else is dropped in the kernel. `ipv6: false` drops every IPv6 frame, NDP and mDNS or DNS over IPv6 included. Frames of a VLAN are dropped too (VLANs are out of scope in v1): the kernel strips 802.1Q tags before the filter runs, so the filter checks the tag through the BPF VLAN extensions and keeps only untagged and priority-tagged (VLAN ID 0, common with PROFINET devices) frames. The host's own frames are never evidence: the filter drops what the kernel marks `PACKET_OUTGOING`, and the capture source skips frames from the interface's own MAC, which a bridge port in hairpin mode reflects back, as well as frames that reached the ring before the filter was attached. Promiscuous mode is set with `PACKET_ADD_MEMBERSHIP` when enabled and dropped with the socket. An administratively down interface is not opened; when the interface goes down or disappears the ring is closed. Either way capture retries with back-off (1 s doubling to 30 s, starting over only once frames arrive), shows as failed meanwhile, and logs each distinct failure once. Kernel receive and drop counters are kept per interface across reopens (`lan_sentinel_capture_drops_total`).

Decoders (`capture/decoders`) are pure functions from an Ethernet frame to zero or more observations, shared with pcap replay, each with a fuzz target. The MAC evidence is the ARP sender hardware address, the NDP link-layer address option, the DHCP `chaddr`, the LLDP chassis MAC (when the chassis ID is a MAC) or else the frame's source MAC. DNS PTR answers carry no MAC: they name the holder of an address (`DATA_MODEL.md` §5.1). LLDP management addresses, mDNS services and TXT data, DHCP client identifier, parameter request list and vendor class go into `meta` (`DATA_MODEL.md` §2). DHCP keeps provenance apart: a server's ACK with a `yiaddr` is a lease (`passive_dhcp_lease`, with lease time and server identifier), a client's REQUEST or INFORM `ciaddr` only its claim (`passive_dhcp`). Every server reply (OFFER, ACK, NAK) is also a `passive_dhcp_server` observation of its sender, the server or the relay that forwarded it, with the server identifier (option 54) kept apart from the sender, `giaddr`, and the router, DNS servers and subnet mask it advertises; the correlator turns these into `dhcp_servers` rows and the DHCP server events (`DATA_MODEL.md` §5.6). One mDNS hostname is kept per packet (the one for the packet's source address), so aliases do not flip the host's name. Identical observations (same source, MAC, IP, name and metadata) are emitted at most once per 2 minutes per interface, which keeps presence fresh (ACTIVE is 5 min) while bounding the volume written to `observations`.

On a switched port, capture sees traffic to/from the box, broadcast, multicast, ARP, mDNS, IPv6 multicast and some switch control traffic, but not unicast between other devices unless the port is mirrored. That is expected and sufficient for discovery.

### Replay collector (`internal/collect/replay`)
Reads JSONL files of `Observation` values, or pcap/pcapng captures (Ethernet link type; `.pcap.gz` and `.pcapng.gz` are read compressed) decoded by the capture decoders with the same refresh suppression as live capture, skipping packets a pcapng file records as outbound (a classic pcap records no direction, so a capture taken on the box includes its own frames), merges every replay interface's file into one time-ordered stream, and emits them with their recorded source and timestamp. Paths are relative to the working directory. Replay and live interfaces cannot be mixed: a replay runs the whole daemon on recorded time. In `speed: 0` mode it advances a simulated clock (`internal/clock`) to each observation's timestamp before emitting it and blocks until the correlator has consumed it, so presence and expiry timers fire exactly as they would have at the site; `speed: N` replays in real time × N. When every replay source is exhausted the daemon commits its last batch (the writer's flush ticker runs on the simulated clock, which stops), logs `replay data committed`, and keeps serving the API (or exits with `replay.exit_when_done: true`, used by tests).

### Clock (`internal/clock`)
All components that read time (correlator, presence ticker, expiry, scheduler, compaction) take a `clock.Clock`. Production uses the wall clock; replay and tests use a simulated clock.

### Platform layer (`internal/platform`)
Four small interfaces over the kernel facilities. Nothing outside `internal/platform` and `internal/service` uses AF_PACKET, netlink or raw sockets directly, so collectors, the scheduler and the daemon are tested against fakes.

| Interface | Methods (sketch) | Linux implementation |
| --- | --- | --- |
| `Capturer` | `Open(iface, filter, promisc) (FrameSource, error)`, `Stats()` | `AF_PACKET` TPACKET_V3 ring |
| `NeighborSource` | `Snapshot(ctx) ([]Neighbor, error)`, `Watch(ctx) (<-chan NeighborEvent, error)`; entries carry the NUD state and the confirmation age | rtnetlink neighbour dump and subscription |
| `InterfaceMonitor` | `List(ctx)`, `Watch(ctx) (<-chan LinkEvent, error)` | rtnetlink link and address dump and subscription |
| `Transmitter` | `Frames(iface, etherType) FrameConn` (write and read frames; each read frame carries its interface), `DialTCP(iface, addr, timeout)`, `DialUDP(iface, addr)`, `ICMPConn(iface) EchoConn`, `Backend(transport)` (`afpacket` for frames, `ping socket` or `raw socket` for ICMP, `socket` for TCP and UDP) | `AF_PACKET` socket bound to the interface and EtherType (the host's own and outgoing frames are not read back), `SO_BINDTODEVICE` TCP and UDP sockets, a ping socket or, where `net.ipv4.ping_group_range` forbids it, a raw ICMP socket bound to the interface |

Each backend reports availability per interface (`running`, `disabled`, `unsupported`, `failed` with error) to the collector registry, which feeds `daemon status` and `lan_sentinel_collector_up`; the scheduler adds each probe's last periodic pass (sent, answered, blocked, duration) for `daemon status`, and never logs passes. Shared tests run against fake implementations of these interfaces; the Linux implementations are tested in Docker (§9).

### Neighbour collector (`internal/collect/neighbor`)
Dumps the neighbour table at startup, then subscribes to `RTM_NEWNEIGH`/`RTM_DELNEIGH`, and takes a fresh dump after notification loss (`ENOBUFS`: the backend resubscribes and signals a resync) and every `neighbor.resync_interval` (default 10 min). Emits source `kernel_neighbor` with the NUD state as `neighbor_state` for resolved entries only (REACHABLE, STALE, DELAY, PROBE; not INCOMPLETE, FAILED, NOARP or PERMANENT). Each observation is stamped with the time the kernel last confirmed reachability (`ndm_confirmed`), and an entry is emitted again only when it is reconfirmed or its MAC changes. A STALE entry that lingers therefore never makes a switched-off device look present, and STALE is never read as offline either.

### Active probes (`internal/probe`)
Four engines, ARP (`probe/arp`), ICMP (`probe/icmp`), TCP (`probe/tcp`) and protocol-specific UDP (`probe/udp`), build their packets themselves and send through the platform `Transmitter`; IPv6 NDP probing is deferred (v1 is IPv4-first). Engines only emit observations (`arp_scan`, `icmp_scan`, `tcp_connect`, `udp_probe`) on the bus; they never touch state. ARP sweeps the configured networks and is the primary discovery mechanism; ICMP, TCP and UDP probe known hosts only, the open IPv4 bindings inside those networks (plus, in an operator scan, the hosts that answered its ARP sweep). A UDP probe is one well-formed request of its protocol, NTP mode 3 (123) or EtherNet/IP ListIdentity (44818), matched to its reply by a random token; a reply is service evidence with details (NTP version, stratum, leap indicator, reference ID, root delay and dispersion) and, for ListIdentity, the device's identity claims (product name, device type; vendor ID, product code, revision, serial number, status and state as details). No reply means nothing. A new UDP probe is one more `Prober`.

Before every send an engine acquires the shared budget (`probe.Budget`), which checks the policy (kill switch, active discovery on the interface, target inside the configured networks, IPv4, not excluded) before it waits and again right before it returns, takes a slot of the global concurrency semaphore (TCP also the per-interface and per-host ones), waits for the target's spacing (without holding up probes to other targets), and books the send time: the earliest moment that respects the target's spacing, the protocol budget and the global packet budget (a TCP connect costs 3), booked in all three at once. Budgets are paced (the next send is due cost/rate after the previous one, 2% below the rate) and enforced over a sliding window of 1.02 s; a probe that leaves late (a timer that fired late, a goroutine not scheduled at once) is re-booked at the moment it actually leaves, so the budgets count real send times and no one-second window on the wire ever holds more than the budget. Every wait is counted per protocol and reason (`lan_sentinel_probe_throttled_total`).

The scheduler (`probe/scheduler`) runs one loop per configured interface and protocol; a loop probes while its interface has active discovery enabled, which follows reloads. The first pass waits for the startup delay plus a random share, up to `jitter`, of the interval; later passes follow the interval ±`jitter`; targets go in random order. An ARP sweep is never listed: its addresses (the networks less excludes and the interface's own addresses, `internal/netrange`) are counted and walked in a random order by a keyed permutation, so a sweep needs constant memory however wide it is. ICMP, TCP and UDP passes skip targets in back-off. Back-off is kept per interface, address, probe type and port (TCP) or probe (UDP), so one probe that goes unanswered never slows another: after three unanswered probes in a row (no reply, TIMEOUT or UNREACHABLE) that probe goes to the address at four times its interval. An answer to it ends the back-off; fresh positive evidence for the address (the open binding confirmed after the last miss: passive traffic, the neighbour table, an answer to another probe) eases it, so the next probe goes at the normal interval and one more miss brings the back-off back at once. ARP sweeps are not backed off. TCP passes go port by port, UDP passes probe by probe. A reload applies new budgets at once and new intervals, enabled probes and each interface's `active` settings at each loop's next step; the policy checks every probe against the new configuration at once, so disabling an interface or narrowing its networks stops the probes it no longer allows immediately. A reload that enables an interface starts its passes after the startup delay and jitter, as at start-up. The kill switch cancels running passes and scans at once; the loops then wait for it to clear. Operator scans (`scan run`) go through the same budgets, one interface after another: the ARP sweep, then ICMP, TCP port by port and UDP probe by probe on the known hosts and the ARP responders, in one random order for every phase. The scheduler records a scan through the correlator (an operator message on the bus: a `scans` row, `SCAN_STARTED`, `SCAN_COMPLETED` with counts), as the daemon does the kill switch (`runtime_state`, `ACTIVE_DISABLED`/`ACTIVE_ENABLED`); once the correlator has stopped, the bus is closed and such requests fail rather than wait. The planner (`probe.Compute`) computes `scan plan` and gates `scan run` identically. Its estimate replays the budget's pacing on a simulated clock (the first 20,000 addresses of a longer sweep, extrapolated at the pace reached) and gives two durations with the assumptions behind them: the estimated typical duration (known hosts answer at once; most swept addresses are empty, so only the sweep waits out its reply timeout) and the estimated no-response duration (every phase waits out its reply timeout). See §5.

### Correlator (`internal/correlate`) and state (`internal/state`)
Single goroutine. Loads the current state (contexts, hosts, open bindings, services, DHCP servers) at startup, applies the correlation rules (`DATA_MODEL.md` §5) to each bus message in order, derives `preferred_name`, and hands state changes to the store and events to the event engine. Time is data-driven: rules use the observation's time and timer transitions (presence, expiry) are stamped with the moment their threshold was crossed. A ticker re-evaluates them in live mode (every 15 s); replay has no ticker, so results are identical however fast it runs. The correlator assigns row ids itself, so it can refer to rows the writer has not committed yet. Observations that match no host are stored unbound and counted.

### Event engine (`internal/events`)
Builds events from state transitions, attaches the evidence snapshot (`DATA_MODEL.md` §7), writes them to the store and to journald.

### Store (`internal/store`)
Owns the single SQLite writer goroutine, migrations, repositories, batched commits (target 5 s), retention, roll-up and compaction (`DATA_MODEL.md` §9). Compaction runs at start-up and hourly (not in replay mode, so a replay's database depends only on the recorded data); each step touches at most 2,000 rows and is one committed op in the writer's queue, so it never holds the writer for long. The size cap compares the data size (pages minus free pages) with `max_db_size`; new databases use `auto_vacuum=INCREMENTAL`, so compaction returns freed pages to the file system. At start-up the store runs `PRAGMA quick_check`; a database that fails it, or is not a database at all, is renamed with its `-wal` and `-shm` files to `<path>.corrupt-<UTC time>` and a new one is created, which the daemon logs as an error and the correlator records as `DATABASE_RECREATED` (FR-ST-4). Exposes read-only query functions used by the API and by `--offline`; the offline open procedure is specified in `CLI.md` §1. On clean shutdown the writer runs `PRAGMA wal_checkpoint(TRUNCATE)` and closes, so the WAL is removed.

### Identification (`internal/identify`)
OUI lookup (longest prefix: MA-S, MA-M, MA-L) from a precomputed table embedded in the binary (`data/oui/oui.bin`, about 54,000 assignments, 1.2 MB; format in `internal/ouitable`: sorted keys per prefix length, name offsets and each distinct name once), searched in place by binary search, so start-up parses nothing and the table takes no heap (parsing the text registry took about 0.6 s of CPU on a CM4, 6 s under the unit's `CPUQuota=20%`). `make oui` downloads the IEEE registries each release, writes them readable as `data/oui/oui.tsv.gz` and derives `oui.bin` from them; a test keeps the two in step and checks that every lookup answers as the text registry does. An optional override file (`identity.oui_override`: lines `PREFIX[/bits] Name`, e.g. `00:1B:1B Siemens` or `02-42-AC-1F/24 Lab`). The locally-administered bit is recorded per host. Passive identifiers (phase 6) implement `Identifier` (`Name()`, `Identify(observation) []Claim`): pure functions over evidence already captured, mDNS service types and model, the DHCP client's vendor class and request list, device-chosen hostnames and LLDP capabilities, each claiming `device_type`, `os` or `model` with a confidence and its evidence. The correlator applies the enabled ones (`identity.identifiers`, reloadable) to every observation of a present host and adopts a claim only when it is more confident than the source's current value (`DATA_MODEL.md` §5.7). Active identification (Modbus FC 43/14, HTTP, TLS, SNMP) would send payloads and is not built.

### API (`internal/api`) and CLI (`internal/cli`)
REST over `/run/lan-sentinel/api.sock` (mode 0660, owner root under the reference unit), optional `127.0.0.1` listener that also serves `/metrics`; specified in `API.md`. The API answers from `store.Reader` on a read-only connection pool, the same queries `--offline` runs on the database file, so online and offline answers are identical; it sees what the writer has committed (at most one 5 s batch behind), and `/v1/events/stream` is fed live by the event engine. The CLI (`CLI.md`) is an API client by default and a read-only DB reader with `--offline`; both behind one interface, so every read command works both ways. Changes go through the daemon only: the operator endpoints (kill switch, scans, configuration reload, host descriptions) hand their action to the correlator as an operator message on the bus and answer once it is committed, so the single writer holds.

### Metrics (`internal/metrics`)
`lan_sentinel_hosts{interface,presence}`, `lan_sentinel_events_total{type}`, `lan_sentinel_probe_total{interface,protocol,port,result}`, `lan_sentinel_scan_duration_seconds`, `lan_sentinel_observations_total{source}`, `lan_sentinel_bus_dropped_total`, `lan_sentinel_capture_drops_total{interface}`, `lan_sentinel_db_size_bytes`, `lan_sentinel_observations_unbound_total{source}`, `lan_sentinel_active_disabled` (0/1), `lan_sentinel_probe_throttled_total{protocol,reason}`, `lan_sentinel_collector_up{interface,collector}`, `lan_sentinel_dhcp_servers{interface,status}` (`API.md` lists their meaning). A small writer for the Prometheus text format, gathered at scrape time; it refuses any label outside a fixed low-cardinality list, so no MAC, IP, hostname or host-ID label can appear.

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
│   │   ├── capture/             capture loop over platform.Capturer, BPF filter; decoders/: arp, ip, ndp, dhcp, dns (mDNS, DNS), lldp
│   │   ├── neighbor/            snapshot + watch + resync over platform.NeighborSource
│   │   └── replay/              pcap/pcapng and JSONL replay
│   ├── netrange/                IPv4 range arithmetic: sweep sizes, excludes, a random walk without a list
│   ├── probe/                   budget (rates, concurrency, spacing), policy and kill switch, targets, back-off, planner
│   │   ├── scheduler/           periodic passes per interface and protocol, operator scans
│   │   ├── arp/  icmp/  tcp/  udp/   engines (transmit via platform.Transmitter); udp: NTP, EtherNet/IP ListIdentity
│   ├── correlate/               identity engine: match observation → host, conflicts
│   ├── state/                   in-memory current state, presence state machine, name preference
│   ├── events/                  event types, emitter, journald sink
│   ├── store/                   SQLite: migrations, writer, batching, retention/compaction, integrity; read model and
│   │                            queries (Reader) for the API and --offline; storetest/ seeds test databases
│   ├── identify/                OUI lookup; passive identifiers (mDNS, DHCP, hostname, LLDP)
│   ├── api/                     REST over Unix socket + optional 127.0.0.1 TCP (server and the CLI's client)
│   ├── buildinfo/               version, commit, date stamped via -ldflags
│   ├── daemon/                  lifecycle: config, store, collectors, SIGHUP reload, watchdog, shutdown
│   ├── logging/                 slog handler selection (journald, text, json)
│   ├── metrics/                 Prometheus registry, low-cardinality collectors
│   └── cli/                     API client, offline DB reader, table/json/jsonl/csv output
├── migrations/                  numbered .sql files embedded with go:embed
├── data/oui/                    OUI registry (oui.tsv.gz), the precomputed table it embeds (oui.bin) + generator tool
├── build/                       dev container (dev.Dockerfile) and the scripts make runs in it
├── deploy/                      systemd unit, default config, config.dev.yaml (replay), install guide
├── test/
│   ├── golden/                  golden observation streams + expected bindings, events, queries
│   ├── net/                     Docker network tests: run.sh + Go tests (build tag nettest); inject/ frame injector
│   ├── frames/                  frame builders (gopacket) for tests, fixtures and the injector
│   └── fixtures/                pcap fixtures (synthetic, `make fixtures`; real site captures later)
├── tools/capcheck/              privilege and feasibility check (Linux; not released)
├── docs/
├── Makefile
└── CLAUDE.md
```

Tooling: a `Makefile` (`make` lists every target) whose Go commands all run in the Linux dev container (`build/dev.Dockerfile`: Go toolchain, pinned golangci-lint; caches on a named volume; runs as the calling user). Targets: `release` (static `linux/amd64` and `linux/arm64` binaries, version, commit and commit date via `-ldflags`, so a commit always builds the same bytes, static-linking check, `SHA256SUMS`); hygiene targets `fmt`/`fmt-check`, `tidy`/`tidy-check`, `mod-verify`, `vet`, `lint` (golangci-lint) and `vuln` (`govulncheck`, pinned as a Go tool in `go.mod`); `test`, `coverage`/`cover` (coverage of `internal/` from every test package, failing below 90%), `fuzz` (every `Fuzz*` target, `FUZZTIME` each); the Docker suites `test-net` and `test-systemd` (§9); the gates `check` and `check-all`; `shell` and `run-dev`. `package` (after `release` and `tools`) packs one reproducible tarball per target, `dist/release/lan-sentinel-<version>-linux-<arch>.tar.gz` (binary, `capcheck`, the reference deploy files and their `SHA256SUMS`), with `SHA256SUMS` for the tarballs. CI runs the same targets: `make mod-verify check`, `make fuzz`, the Docker suites and `make package`. Releases are cut from `main` by the manual `release` workflow (`.github/workflows/release.yml`): it takes a patch, minor or major bump, computes the next version from the highest `vX.Y.Z` tag (`build/next-version.sh`; the first is v0.0.1), runs the CI gates on the commit, builds the tarballs twice and compares their checksums, checks the binary reports the version, then creates the annotated tag on that commit and publishes the GitHub Release with the two tarballs and `SHA256SUMS`.

## 5. OT safety controls

| Control | Default | Enforcement |
| --- | --- | --- |
| Active discovery | Disabled | Must be enabled per interface |
| Scan scope | Configured `networks` only | ARP sweeps the configured networks; ICMP, TCP and UDP probe only known hosts inside them. Discovered subnets are never scanned automatically |
| Max auto-scan prefix | /24 IPv4 | Wider prefixes refused at config validation unless `allow_wide_scan: true` |
| Sweep size | 65,536 targets per interface | With `allow_wide_scan`, the limit is a target count, not a prefix: an interface's networks, less excludes, may hold at most `max_sweep_targets` addresses (default 65,536: a /16, or 256 /24s). Above the default is an expert override: it needs `allow_wide_scan`, and the global and ARP rates and the concurrency cap may not exceed their defaults, so a wider sweep only takes longer, never sends faster. `config validate` shows each interface's sweep size and duration; an operator sweep of more than 65,536 addresses is refused until repeated with `--allow-wide` after its `scan plan` preview. Validation keeps the value at most 2^24 (a /8) |
| IPv6 | No active probes | v1 is IPv4-first: no IPv6 sweeping, NDP probing deferred; IPv6 and NDP are still decoded passively |
| Packet rate | 20 pps total | One budget shared by all engines and interfaces, paced and enforced over a sliding 1.02 s window; a TCP connect costs 3 packets. The ARP the kernel sends to resolve a probed known host is not counted: known hosts are usually in the neighbour cache, and back-off keeps probes to vanished hosts rare |
| Per-protocol rate | ARP 10 pps, ICMP 5, UDP 5, TCP 5 connects/s | One budget per protocol beneath the global one (`budgets.ndp` is reserved for NDP probing) |
| Concurrency | 10 probes | Semaphore across engines |
| TCP concurrency | 4 per interface, 1 per target host | Extra semaphores in the shared budget, taken by TCP probes |
| Per-target spacing | ≥ 1 s between any two probes to one IP on one interface | Booked with the send time |
| Dry run | `scan plan` | Same planner as `scan run`; refuses identically; estimated typical and no-response durations with their assumptions |
| Startup delay | 30 s + up to `jitter` × interval | Avoids ~1,000 boxes probing at once after a fleet update |
| Interval jitter | ±10% | Desynchronises sites over time |
| Target order | Randomised | Avoids sequential hammering |
| Excludes | Empty list | IPs/CIDRs never probed, checked before every send |
| TCP probe style | Bare connect, immediate close with RST (`SO_LINGER` 0), SYN retransmissions capped at 2 | No SYN scans, no payload; at most 3 packets per connect (below). Protocol-specific TCP probes (none in v1) close with FIN after their exchange and are charged for what they send |
| UDP probes | NTP and EtherNet/IP ListIdentity, off by default | Protocol-specific requests to known hosts only; no generic UDP port scanning; no reply means nothing |
| Back-off | On | Per interface, address, probe type and port or UDP probe: 3 unanswered probes in a row (no reply, TIMEOUT, UNREACHABLE) and that probe goes at 4× interval; an answer ends it, fresh positive evidence for the address eases it (next probe at the normal interval, back at the next miss); other probes are not affected; ARP sweeps are exempt |
| Kill switch | `LAN_SENTINEL_ACTIVE_DISABLED=1`, API or `active disable` | Checked before every send; running passes and scans are cancelled at once, without restart; the API/CLI setting persists across restarts |

A bare TCP connect is charged 3 packets of the global budget before it is sent, whatever its outcome:

| Outcome | Sent by the probe | Notes |
| --- | --- | --- |
| OPEN (connected) | SYN, ACK, RST: 3 | The handshake completes and the probe aborts at once; no data, no FIN exchange |
| REFUSED | SYN: 1 | The target's RST ends it; the budget keeps the 2 unused packets |
| TIMEOUT | SYN plus at most 2 retransmissions: up to 3 | Retransmissions at about 1 s and 3 s (`TCP_SYNCNT` 2), so a timeout of 1 s or less sends 1 SYN, up to 3 s sends 2, longer sends 3; the kernel gives up at about 7 s, which caps the wait |
| UNREACHABLE | none, or the SYNs as for TIMEOUT | The kernel found no neighbour (its own ARP is not counted, see above) or got an ICMP unreachable |

Passive capture opens sockets for receive only, never injects frames, and promiscuous mode is a per-interface opt-in.

## 6. Configuration

Precedence: flags → `LAN_SENTINEL_*` environment → `/etc/lan-sentinel/config.yaml` (or `$LAN_SENTINEL_CONFIG`) → compiled defaults. SIGHUP (`systemctl reload`) and `lan-sentinel config reload` (`POST /v1/config/reload`) re-read the file, all or nothing (FR-CFG-3): probes, each interface's `active` and `dhcp` settings, intervals, budgets, thresholds, identity settings and the log level take effect at once (a DHCP allowlist at each server's next reply). Adding, removing or renaming interfaces, their passive settings, `passive`, `storage`, `api`, `metrics`, `logging.format` and `replay` require a restart; those keys keep their running values, the API answer lists them, and the merged configuration is validated again before it applies. Reloads are serialised; the daemon logs each with its caller and the applied keys. The message itself (what `journalctl` shows) says what active discovery now runs, e.g. `configuration reloaded; active discovery: arp every 5m on eth0 (192.168.0.0/24)`, `off`, or `stopped by the kill switch (…)`; start-up logs the same as `active discovery: …`. Passes and sweeps are never logged.

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
  ring_size: 2MiB                   # AF_PACKET ring per captured interface (256KiB-256MiB)
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
  max_sweep_targets: 65536         # addresses one interface's sweep may cover (with allow_wide_scan); above: expert override
  allow_wide_scan: false
  arp:  { enabled: true,  interval: 5m }
  icmp: { enabled: false, interval: 10m }
  tcp:
    enabled: true
    interval: 5m
    targets:
      - { port: 502, name: modbus, timeout: 750ms }
  udp:                             # protocol-specific probes only; no reply means nothing
    enabled: false
    interval: 15m
    probes: [ntp, enip]            # NTP (123), EtherNet/IP ListIdentity (44818)
profiles:
  modbus:
    arp: true
    tcp: [502]
  identify:
    udp: [enip]
presence: { active: 5m, recent: 30m, stale: 24h }
identity:
  hostname_preference: [mdns, dhcp, dns_ptr, lldp]
  address_overlap: 5m         # older open IPv4 binding is replaced, not kept alongside
  address_expiry: 24h         # unconfirmed binding closed while host is otherwise seen
  name_expiry: 168h           # names not confirmed this long show as stale; they are never closed by time
  proxy_arp_threshold: 16
  oui_override: ""            # optional path
  identifiers: { mdns: true, dhcp: true, hostname: true, lldp: true }   # passive identification, DATA_MODEL.md §5.7
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
      file: test/fixtures/site-a-eth1.pcapng  # .pcap, .pcapng (optionally .gz) or .jsonl
      speed: 0                               # 0 = simulated clock, as fast as possible; N = real time x N
replay: { exit_when_done: false }
storage: { path: ./dev/hosts.db }
api:     { socket: ./dev/api.sock }
logging: { level: debug, format: text }
```

`replay` is mutually exclusive with `passive` and `active` on the same interface.

## 7. Logging

Each event is one journald entry with structured fields (`EVENT=ip_changed`, `IFACE`, `HOST_ID`, `MAC`, `IP` from the evidence, `OLD_VALUE`, `NEW_VALUE`, `RELATED_HOST_ID`, `SOURCE` = the cause, `TS` = event time) and a readable `MESSAGE` such as `IP_CHANGED eth1 00:1b:1b:aa:bb:01 192.168.110.50 -> 192.168.110.51`. Priority: notice for changes, warning for `DUPLICATE_IP_DETECTED`, `MAC_MOVED`, `ACTIVE_DISABLED`, `INTERFACE_DOWN` and `DATABASE_RECREATED`, error for daemon faults (such as a corrupt database being quarantined). `journalctl -u lan-sentinel EVENT=ip_changed` works directly. Observations are never logged.

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
# Runs as root (decided 6 Oct 2026), but the bounding set below leaves root
# only CAP_NET_RAW, and the sandbox keeps the rest of the system read-only.
UMask=0027
WatchdogSec=60
Restart=on-failure
RuntimeDirectory=lan-sentinel
RuntimeDirectoryMode=0750
ReadWritePaths=/data/lan-sentinel
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateMounts=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
# The daemon reads the kernel clock's sync state with a read-only adjtimex
# (NFR-REL-2), which ProtectClock=true would block. The clock still cannot
# be changed: no CAP_SYS_TIME (the kernel refuses any change without it),
# the call filter below allows no other @clock call, and PrivateDevices
# hides /dev/rtc.
ProtectClock=false
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
# Read-only clock sync state (see ProtectClock= above); listed after the
# deny line because @privileged contains @clock.
SystemCallFilter=adjtimex
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
| `adjtimex` read (modes 0: clock sync state, NFR-REL-2) | none; allowed by the unit's call filter, which is why `ProtectClock=` is off |

The clock check is a read-only `adjtimex` of the kernel's NTP status (`STA_UNSYNC`, `STA_CLOCKERR`, `TIME_ERROR`), so it works whichever NTP client keeps the clock (chrony on the deployed devices; ntpd or systemd-timesyncd elsewhere) and depends on none of them. Every event records the state at write time: `synced`, `unsynced` or `unknown` (the state could not be read, or a replay). `systemd-analyze security` charges the exception three times, 0.2 each (it counts `adjtimex` as an allowed `@privileged` and `@clock` call, and `ProtectClock=` as off), partly offset by `PrivateMounts=true`: the unit scored 2.0 on systemd 247, 252 and 257 (`make test-systemd`, Debian 11, 12 and 13; 1.6 before the exception). Running as root instead of a service user adds 0.3 (2.3 on each), below the 2.5 limit of NFR-SEC-1. It costs no capability: changing the clock needs `CAP_SYS_TIME`, which the bounding set does not hold. On systemd 247 (Debian 11) `PrivateIPC=` does not exist yet; the unit runs without it there, with a warning in the journal.

Run `tools/capcheck` under the reference unit's sandbox on each target board (`tools/capcheck/README.md`) and record kernel version, board and results below. `make test-net` runs the same check in Docker on every change. If any row needs `CAP_NET_ADMIN` or root, stop and decide before continuing.

| System | Kernel | Date | Result |
| --- | --- | --- | --- |
| Docker test network (`make test-net`), uid 65534, ambient `CAP_NET_RAW` only | 7.0.14-linuxkit arm64 | 2026-10-05 | PASS, every row above, including ARP/NDP transmit, ping and raw ICMP, bound TCP connect; AF_PACKET refused without `CAP_NET_RAW` |
| systemd in a container (`make test-systemd`), transient unit with this unit's `[Service]` settings | 7.0.14-linuxkit arm64, systemd 252 | 2026-10-05 | PASS, every row above; daemon runs as `lan-sentinel` with `CapEff`/`CapBnd` = `CAP_NET_RAW`; `systemd-analyze security` exposure 1.6 |
| systemd in containers (`make test-systemd`) on Debian 11, 12 and 13, with the read-only `adjtimex` exception | 7.0.14-linuxkit arm64, systemd 247, 252, 257 | 2026-10-06 | PASS, every row above including the `adjtimex` read under the sandbox; clock state readable (`unsynced` in the Docker VM); exposure 2.0 on each |
| systemd in containers (`make test-systemd`) on Debian 11, 12 and 13, daemon as root, installed with the commands in `deploy/README.md` | 7.0.14-linuxkit arm64, systemd 247, 252, 257 | 2026-10-06 | PASS, every row above; uid 0 with `CapEff`/`CapBnd` = `CAP_NET_RAW`; socket `root:root` 0660; exposure 2.3 on each |
| Raspberry Pi Compute Module 4 Rev 1.1, Debian 11 (systemd 247), daemon installed from the v0.0.2 release | 6.1.21-v8+ aarch64 | 2026-10-06 | PASS: capcheck under the installed unit's sandbox (`tools/capcheck/README.md`), every row including ARP transmit, ping and raw ICMP, bound TCP connect and the `adjtimex` read (NDP transmit skipped: IPv6 probing is deferred); running daemon `CapEff`/`CapBnd` = `CAP_NET_RAW`, nothing ambient; `systemd-analyze security` exposure 2.3. Without capabilities exactly the `CAP_NET_RAW` rows fail; `net.ipv4.ping_group_range` is `0-2147483647` |
| RevPi Connect | (pending) | | |
| amd64 edge box | (pending) | | |

The process stays in the foreground; systemd owns its lifecycle (no double-fork). `make test-systemd` runs this unit unchanged in a systemd container for each target release (Debian 11 bullseye, 12 bookworm, 13 trixie) on every change and fails if the exposure rises above 2.5, the clock state cannot be read, or capcheck fails under its sandbox.

## 9. Development and testing

The code base is Linux only. Every make target that runs Go runs in the Linux dev container (`build/dev.Dockerfile`), so development machines, Linux or macOS, need only Docker, make and git, and CI runs exactly the same commands. The container runs as the calling user with Go, lint and module caches on the `lan-sentinel-cache` volume; `make shell` opens a shell in it and `make run-dev` runs the daemon there on a replay file. On macOS, editors should run gopls with `GOOS=linux`.

| Layer | Command |
| --- | --- |
| Format, tidy, vet, lint, vulnerabilities, unit and golden tests with race and coverage | `make check` |
| Fuzz targets (every `Fuzz*`) | `make fuzz` |
| Network integration (Docker test network, `CAP_NET_RAW` only) | `make test-net` |
| systemd unit, sandbox and privileges (systemd container) | `make test-systemd` |
| Privilege check on real hardware | `tools/capcheck` on the target boards (§8) |

`make test-net` builds the test binaries in the dev container (`build/test-bins.sh`, for the Docker host's architecture), then `test/net/run.sh` creates a bridge network with fixed subnets (`172.31.250.0/24`, `fd5e:5e:1::/64`) standing in for an OT LAN, plus a second network (`172.31.251.0/24`). Simulated hosts are `busybox` containers with fixed MACs: one with a TCP listener on port 502 (`.10`), one without (`.11`, REFUSED), one that is swapped for a host with another MAC on request (`.12`), one that is stopped on request (`.13`), a "PLC" with a real Siemens OUI MAC for vendor lookup (`.14`), one that active discovery learns and that is then stopped (`.130`), and an unused address (`.99`). On the second network a host carries the same MAC as `.10`, so per-interface scoping is tested. Go tests ask for such changes by writing request files (`<action>@<id>.request`, holding the action's arguments) into a shared directory; `run.sh` performs them (swap, stop, connect or disconnect the second network, inject frames, add an administratively down interface to the runner's namespace from a helper container) and acknowledges with `<action>@<id>.done`. To inject, a test writes a pcap file of frames from other MACs (DHCP, mDNS, DNS, LLDP, ARP, NDP) and `run.sh` sends it from a separate container with `test/net/inject`; LLDP goes to the broadcast address in these tests because Linux bridges do not forward the 802.1D reserved group addresses. The capture tests check decoding of every protocol, that the box's own frames and VLAN frames are not captured (priority-tagged ones are), that a down interface is refused until it comes up, promiscuous mode with only `CAP_NET_RAW`, the kernel drop counter on an overflowing ring, and the daemon naming hosts from captured frames. The active-discovery test runs operator scans through the daemon while a counter (an unfiltered `AF_PACKET` ring in the runner) records every frame the runner sends with kernel timestamps: no one-second window exceeds the global or a protocol budget, excluded addresses and addresses outside the configured network see nothing, two probes to one target are a second apart, the measured scan's packets and duration are within 10% of `scan plan`, TCP results are classified (OPEN, REFUSED, and UNREACHABLE for a known host that is stopped on request, `.130`), the prefix guard refuses, and the kill switch stops a running sweep within one second and survives a restart. The runner container starts with only `CAP_NET_RAW` (plus the capabilities `setpriv` needs to drop privileges) and runs the tests as uid 65534 with ambient `CAP_NET_RAW`: stricter than the reference unit (root with a `CAP_NET_RAW` bounding set), so the daemon is known to need neither root nor another capability. It runs `capcheck` with and without the capability, then every Go test package under `test/net` built with the `nettest` tag; those read the network layout from `LS_TEST_*` environment variables.

Docker's kernel is not the target kernel, so the board check in §8 stays mandatory.
