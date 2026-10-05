# LAN Sentinel — Implementation Plan

Six phases, each ending in a shippable build. Passive discovery lands before any active probing so the first field deployments cannot disturb OT equipment. Every phase delivers its scope on Linux and darwin; a phase is not done until its exit criterion holds on both. Estimates assume one experienced Go engineer: 19–26 weeks of build (about 5–8 of them for the darwin backends, launchd and the second native test suite) plus about 4 weeks of pilot and soak time that overlaps later phases.

| Phase | Scope | Estimate | Exit gate |
| --- | --- | --- | --- |
| 0 | Foundations, platform layer, feasibility spikes | 3 weeks | Daemon runs under systemd and launchd; capability spikes pass on both OSes |
| 1 | Observation pipeline, interfaces, neighbours | 3–4 weeks | Hosts appear from the neighbour table with vendor, scoped per interface, on both OSes |
| 2 | Passive capture | 4–6 weeks | **v0.1 field release:** passive only, 7-day pilot on 3 sites |
| 3 | API, CLI and metrics | 2–3 weeks | Historical-reconstruction acceptance test passes through the CLI on both OSes |
| 4 | Active discovery with OT safety | 4–6 weeks | No faults in OT device soak; packet-rate limits verified on both OSes |
| 5 | Release builds, hardening, rollout | 2–3 weeks | **v1.0** on the full fleet; active discovery enabled per site |
| 6+ | Identification plugins | ongoing | — |

## Phase 0 — Foundations, platform layer, feasibility spikes (3 weeks)

- [ ] Repo skeleton, Go module `lan-sentinel`, `golangci-lint`, CI, `Makefile` with `build`, `release`, `test`, `test-net`, `run-dev`, `lint`
- [ ] Cross-compiled `CGO_ENABLED=0` builds for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, version/commit/date via `-ldflags`, `SHA256SUMS`
- [ ] CI on a Linux and a macOS runner: build all four targets, unit and golden tests with `-race`, lint for both `GOOS` values, native network suite (`test-net`) on each
- [ ] Platform layer: the four interfaces in `ARCHITECTURE.md` §3 with fakes for tests, `_linux.go`/`_darwin.go` convention, collector registry with availability states, per-platform default paths (`ARCHITECTURE.md` §6)
- [ ] `internal/clock` (wall and simulated) used by everything that reads time
- [ ] Config loader: YAML + `LAN_SENTINEL_*` env + flags + defaults, strict validation (unknown keys fail)
- [ ] Commands: `daemon run`, `config validate`, `config show [--sources]`, `version`
- [ ] `slog` logging: journald handler on Linux, JSON lines on darwin, text on a terminal
- [ ] SQLite store (`modernc.org/sqlite`) with embedded migrations, WAL, single writer goroutine, batched commits
- [ ] Daemon lifecycle: context cancellation, `sd_notify` READY/WATCHDOG on Linux, launchd `KeepAlive` on darwin, graceful shutdown, SIGHUP reload; `daemon prepare` (darwin)
- [ ] Capability check on each target board/kernel under the reference unit with only `CAP_NET_RAW`: every row of the table in `ARCHITECTURE.md` §8; record results there. Any failure stops the project for a decision.
- [ ] Darwin feasibility spike on macOS 14 and the current release, as `_lan-sentinel` in `access_bpf` after `daemon prepare`: BPF capture with filter and `BIOCPROMISC`, ARP/NDP frame transmit via BPF, datagram ICMP, `IP_BOUND_IF` connect, routing-socket neighbour and interface notifications (which ARP add/expire/delete cases arrive, and with what delay). Record results in `ARCHITECTURE.md` §9 and set the darwin `neighbor.resync_interval` default from them. Any need for root in the daemon stops the project for a decision.
- [ ] Golden reconstruction scenario (`DATA_MODEL.md` §10) committed under `test/golden/reconstruction/` as observation stream + expected bindings, events and query answers; a test harness that runs it (failing until phase 1)
- [ ] `deploy/linux/`: reference unit, `sysusers.d`, `tmpfiles.d`, default config
- [ ] `deploy/darwin/`: LaunchDaemon plists (daemon, prepare), `newsyslog.d` entry, default config, `README.md` with user/group/directory setup

**Exit:** the daemon starts under systemd as `lan-sentinel` with only `CAP_NET_RAW`, and under launchd as `_lan-sentinel`; on both it creates `hosts.db`, reloads config on SIGHUP and shuts down cleanly; all four targets build in CI; Linux capability check and darwin feasibility spike passed and recorded; golden scenario committed.

## Phase 1 — Observation pipeline, interfaces, neighbours (3–4 weeks)

- [ ] `Observation` type, `Source` enum, bounded bus, drop counter
- [ ] Replay collector, JSONL input: simulated-clock and real-time modes, `exit_when_done`; golden scenario harness runs through it on Linux and darwin; `deploy/config.dev.yaml` and `make run-dev`
- [ ] Interface manager over `InterfaceMonitor` (netlink backend; routing-socket backend): one network context per interface name, `context_prefixes` history, follow changes, emit `INTERFACE_UP/DOWN`, `SUBNET_CHANGED`
- [ ] Neighbour collector over `NeighborSource` (netlink backend; routing-socket + `sysctl` backend): snapshot, watch, resync on loss and on interval, source `kernel_neighbor` with backend/raw state in metadata
- [ ] Native tests for both backends: netns + veth on Linux, `feth` pairs on darwin
- [ ] Correlator v1: `DATA_MODEL.md` §5.1 (host = context + MAC, unbound observations), §5.2 on-link check, §5.3 open/replace/takeover/expiry with interval semantics of §3; `HOST_DISCOVERED`, `IP_ADDED`, `IP_CHANGED`, `IP_REMOVED`, `MAC_MOVED`
- [ ] Schema constraints and partial unique indexes from `DATA_MODEL.md` §4
- [ ] Presence state machine with configurable thresholds; `HOST_DISAPPEARED`, `HOST_REAPPEARED`
- [ ] Event engine writing to `events` (with `cause` and `evidence_json` snapshot) and the log sink
- [ ] OUI vendor lookup (IEEE MA-L/MA-M/MA-S) with a generator that builds a compact embedded table; optional override file; locally administered flag

**Exit:** `make run-dev` replays the golden stream on both OSes and the resulting database matches the expected bindings; on a test LAN, a Linux and a darwin host each see hosts appear from the kernel neighbour table alone, with vendor and correct per-interface scoping; the golden scenario passes at correlator level except the conflict steps (phase 2).

## Phase 2 — Passive capture (4–6 weeks)

- [ ] Capture loop over `Capturer` with a shared classic-BPF filter, optional promiscuous mode, capture-drop metric
- [ ] Linux backend: `AF_PACKET` TPACKET_V3, ring sizing
- [ ] Darwin backend: `/dev/bpf*` with `BIOCSETIF`/`BIOCSETF`/`BIOCIMMEDIATE`/`BIOCSBLEN`/`BIOCPROMISC`, `BIOCGSTATS` drops, buffer parsing of `bpf_hdr` records
- [ ] Native capture tests on both OSes (frames injected on the peer of a veth/`feth` pair)
- [ ] Decoders: ARP (incl. gratuitous), IPv4 source, IPv6 + NDP, DHCP (option 12 hostname, 61 client-id, 55 parameter list kept for later fingerprinting), mDNS (A/AAAA/PTR/SRV/TXT), DNS responses, LLDP
- [ ] Fuzz target per decoder; pcap fixtures from real sites
- [ ] Replay collector, pcap/pcapng input through the same decoders (portable)
- [ ] Name bindings (`DATA_MODEL.md` §5.4) and `preferred_name` precedence; `HOSTNAME_ADDED/CHANGED/REMOVED`
- [ ] Conflict handling: `DUPLICATE_IP_DETECTED` / `DUPLICATE_IP_RESOLVED` (conflicting ARP replies or gratuitous ARP), `conflict` flag; proxy-ARP flagging
- [ ] Retention, hourly roll-up and compaction job; `max_db_size` enforcement; golden scenario re-run after simulated 7-day compaction gives identical answers and evidence
- [ ] Startup integrity check with quarantine and recreate

**Exit:** full golden scenario passes at correlator level; passive-only build runs 7 days on 3 pilot sites with < 5% CPU and < 50 MB RSS on a RevPi, and 7 days on a darwin lab host within the RSS budget, and both reconstruct an injected IP change and duplicate IP correctly. First field-deployable release (v0.1).

## Phase 3 — Read side: API, CLI, metrics (2–3 weeks)

- [ ] REST API over the platform socket path (0660, service user/group), optional `127.0.0.1` listener; `/v1/status` includes per-collector state
- [ ] Endpoints: `/v1/status`, `/v1/interfaces`, `/v1/hosts`, `/v1/hosts/{id}`, `/v1/hosts/{id}/history`, `/v1/hosts/{id}/evidence`, `/v1/hosts/find?q=&interface=&at=`, `/v1/history?q=&interface=&since=&until=` (IP/MAC/name timelines), `/v1/observations?host=&interface=&mac=&ip=&source=&unbound=&since=&until=&rollups=`, `/v1/events`, `/v1/events/stream` (JSON lines, backs `watch`), `/v1/services`, `/v1/config`, `/v1/db` (scan and kill-switch endpoints in phase 4)
- [ ] CLI per `CLI.md`: subcommand tree, query auto-detection, `find --at` result cases (0 / 1 / ≥2 holders, unconfirmed, replaced-by), IP history, `hosts evidence`, `observations list`, `table`/`json`/`jsonl`/`csv` output, exit codes
- [ ] `--offline` per the contract in `CLI.md` §1, tested for: live DB beside the writer, no `-wal` (immutable open), unreadable `-wal`, busy timeout
- [ ] Prometheus `/metrics` on the local listener, low-cardinality metrics only

**Exit:** the golden scenario's queries pass end to end through the CLI, online and with `--offline`, on both OSes.

## Phase 4 — Active discovery with OT safety (4–6 weeks)

- [ ] Probe scheduler: per-probe intervals, startup delay, jitter, randomised target order, global and per-protocol token buckets, concurrency cap, TCP per-interface and per-host caps, per-target spacing, excludes, timeout back-off
- [ ] Kill switch: env, `POST /v1/active/disable` and `/v1/active/enable`, persisted in `runtime_state`, `ACTIVE_DISABLED/ENABLED` events, `active disable|enable` CLI
- [ ] Scan planner shared by `scan plan` (`POST /v1/scans/plan`, and offline from config) and `scan run` (`POST /v1/scans`), with identical refusal rules
- [ ] `Transmitter` backends: Linux (`AF_PACKET`, `SO_BINDTODEVICE`, ping/raw ICMP); darwin (BPF write with `BIOCSHDRCMPLT`, `IP_BOUND_IF`/`IPV6_BOUND_IF`, datagram ICMP)
- [ ] ARP sweep (native Go) within configured networks only; `max_auto_scan_prefix_v4` guard
- [ ] TCP connect probes bound to the interface, with OPEN/REFUSED/TIMEOUT/UNREACHABLE; `SERVICE_OPENED/CLOSED`
- [ ] ICMP echo via unprivileged datagram sockets (Linux where allowed, else raw with `CAP_NET_RAW`; darwin always)
- [ ] IPv6 NDP solicitation for known addresses (no IPv6 sweeping)
- [ ] UDP framework that only runs protocol-specific probes; no generic UDP open/closed claims
- [ ] Scan profiles from config; `scan run` CLI; `SCAN_STARTED/COMPLETED` events and `scans` rows

**Exit:** active probing defaults to off, and when enabled never exceeds the global, per-protocol and per-host limits on a traffic-counting test rig, measured separately for the Linux and darwin backends; `scan plan` estimates match measured packets within 10%; the kill switch stops probing within one tick and survives a restart; soak test against real OT devices (PLC, inverter, HMI) shows no faults.

## Phase 5 — Release builds, hardening, pilot rollout (2–3 weeks)

- [ ] Release artifacts: binaries for `linux/amd64`, `linux/arm64`, `darwin/amd64` and `darwin/arm64` with SHA-256 checksums; no `.deb`, `.pkg` or other packages; darwin binaries ad-hoc signed by the Go linker, not notarised
- [ ] Hardened unit, capability audit, `systemd-analyze security` exposure ≤ 2.5
- [ ] Darwin privilege audit: daemon never runs as root; only `daemon prepare` does; `deploy/darwin/README.md` setup verified on a clean macOS 14 and current-release machine
- [ ] Clock-jump handling: mark events written before NTP sync
- [ ] Staged fleet rollout (below)

**Exit:** v1.0 on the full fleet with active discovery enabled per site.

## Phase 6+ — Identification plugins (ongoing)

Plugin interface in `internal/identify` taking a host's evidence and returning (field, value, confidence, evidence). Candidates in order of expected value: mDNS service types, Modbus Device Identification (FC 43/14), HTTP `Server` header and title, TLS certificate subject, DHCP fingerprint, SNMP `sysDescr`, hostname patterns.

## Testing strategy

| Layer | How | What it proves |
| --- | --- | --- |
| Decoders | Table tests over captured pcaps from real sites (ARP, DHCP, mDNS, LLDP, NDP), on Linux and darwin | Parsing of real OT device traffic, including malformed frames |
| Replay | Site pcaps replayed through the daemon with a simulated clock, compared with expected inventories | End-to-end behaviour on any platform, reproducible field issues |
| Platforms | CI matrix: Linux and macOS runners; four-target build | Darwin build never breaks; platform code isolated |
| Correlator | Golden tests: observation sequence in → expected bindings and events out, starting with the reconstruction scenario (`DATA_MODEL.md` §10) | IP change, takeover, duplicate IP and resolution, MAC move, NIC swap (new host), same IP on two interfaces, routed source IPs ignored, unbound probe results |
| Store | Migrations on empty and previous-version DBs; compaction; kill -9 during write | Crash safety and upgrade path |
| Probes and platform backends | Linux: `ip netns` + veth pairs; darwin: `feth` pairs; fake hosts answering ARP/TCP; both in CI | Capture, neighbour, interface and transmit backends on each OS; rate limits, excludes, scope guards, result classification |
| Fuzzing | `go test -fuzz` on every decoder | No panics on hostile input |
| Soak | 7 days on a lab rig with real PLC, inverter and HMI | Memory stable, no device faults, DB growth within budget |
| Acceptance | Scripted: change an IP, swap a device, inject a duplicate, then `hosts find --at` and `hosts history` | The reconstruction requirement |

Performance budgets on a RevPi Connect: < 5% average CPU, < 50 MB RSS, DB < 200 MB after 90 days on a 50-host LAN.

## Rollout (each release)

1. Lab rig, passive only, full soak.
2. 3 pilot sites passive only for 2 weeks; compare inventory against what field support knows is there.
3. 50 sites (5%) passive only; watch capture drops, CPU and DB size in Prometheus.
4. Whole fleet passive only.
5. Active discovery enabled on the pilot sites, then per site after review of that site's device mix.

Each collector has a config flag so a misbehaving decoder can be switched off fleet-wide through config without a new build.

## Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Fragile OT device faults under probing | Site outage, loss of trust | Passive-first rollout, low default pps, back-off, excludes, kill switch |
| Wrong attribution (proxy ARP, gateway MAC on routed traffic, duplicate IPs) | Misleading history | Host = MAC per interface, no merges; on-link check; proxy-ARP flagging; conflicts kept as parallel bindings |
| Data model drifts from the acceptance criterion | Rework late in the project | Golden reconstruction scenario from phase 0, run on every change |
| A capture or netlink path needs `CAP_NET_ADMIN` | Security model and unit change | Capability check on target boards in phase 0 |
| Capture drops on busy mirrored ports | Missed observations | BPF filter to discovery protocols only, ring sizing, drop metric |
| SD card wear from SQLite writes | Storage failure | Batched commits every 5 s, compaction, `synchronous=NORMAL` in WAL |
| Clock jumps on boxes without RTC | Broken timelines | Mark events written before NTP sync |
| OS-specific imports leak into shared packages | Platform assumptions spread through the core | Platform interfaces only; lint per `GOOS`; Linux and macOS CI runners |
| Darwin neighbour notifications incomplete | Missed or late `kernel_neighbor` observations | Phase 0 spike measures coverage; resync interval; passive ARP capture covers the same evidence |
| BPF device access on darwin misconfigured | Capture/probes fail on darwin hosts | `daemon prepare` at boot; collector state and degraded status in `daemon status` |
| Two backends double the network-code surface | Schedule slip, platform-specific bugs | Small platform interfaces, shared decoders/scheduler, native tests on both OSes in CI |
| OUI data goes stale | Unknown vendors | Regenerate each release; optional override file |
