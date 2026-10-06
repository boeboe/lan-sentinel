# LAN Sentinel — Implementation Plan

Six phases, each ending in a shippable build. Passive discovery lands before any active probing so the first field deployments cannot disturb OT equipment. LAN Sentinel and its code base are Linux only; every build and test runs in a Linux dev container via `make`, on Linux or macOS development machines. Estimates assume one experienced Go engineer: 15–19 weeks of build plus about 4 weeks of pilot and soak time that overlaps later phases.

| Phase | Scope | Estimate | Exit gate |
| --- | --- | --- | --- |
| 0 | Foundations, platform layer, test infrastructure | 2–3 weeks | Daemon runs under systemd with only `CAP_NET_RAW` and reloads on SIGHUP |
| 1 | Observation pipeline, interfaces, neighbours | 2–3 weeks | Hosts appear from the neighbour table with vendor, scoped per interface |
| 2 | Passive capture | 3–4 weeks | **v0.1 field release:** passive only, 7-day pilot on 3 sites |
| 3 | API, CLI and metrics | 2–3 weeks | Historical-reconstruction acceptance test passes through the CLI |
| 4 | Active discovery with OT safety | 3–4 weeks | No faults in OT device soak; packet-rate limits verified |
| 5 | Release builds, hardening, rollout | 2 weeks | **v1.0** on the full fleet; active discovery enabled per site |
| 6+ | Identification plugins | ongoing | — |

## Open hardware and field checks

Deferred checks that need real hardware or data from real sites. Each closes a phase task or exit criterion; the Docker or replay equivalent already passes on every change, so development continues meanwhile. Record results where noted and tick here.

| | Check | Closes | Docker equivalent (passing) | Record results in |
| --- | --- | --- | --- | --- |
| [ ] | `tools/capcheck` under the reference unit on each target board (RevPi Connect, amd64 edge box): every row passes with only `CAP_NET_RAW` | Phase 0 exit | `make test-net` (capcheck with and without `CAP_NET_RAW`), `make test-systemd` (capcheck under the unit's sandbox) | `ARCHITECTURE.md` §8 table |
| [ ] | Daemon on a target board on a real test LAN: hosts appear from the kernel neighbour table alone, with vendor and per-interface scoping (config with `passive: { enabled: false }`) | Phase 1 exit | `TestDaemonFindsHosts` in `make test-net`: two networks, real-OUI vendor, same MAC on both networks as two hosts with `MAC_MOVED` | Phase 1 exit note below |
| [ ] | pcap captures from the pilot sites (ARP, DHCP, mDNS, LLDP, NDP from real OT devices) added to `test/fixtures` with decoder table tests | Phase 2 task | Synthetic `test/fixtures/site-a-eth1.pcapng` (`make fixtures`) replayed by `TestCaptureScenario`; decoder tests on gopacket-built frames; fuzz targets | `test/fixtures`, decoder tests |
| [ ] | Passive-only build for 7 days on 3 pilot sites: < 5% CPU and < 50 MB RSS on a RevPi; an injected IP change and duplicate IP reconstructed | Phase 2 exit | `TestCaptureScenario` (IP change, takeover, duplicate IP and its resolution reconstructed from frames through the daemon); capture tests in `make test-net` | Phase 2 exit note below |

## Phase 0 — Foundations, platform layer, test infrastructure (2–3 weeks)

- [x] Repo skeleton, Go module `lan-sentinel`, `golangci-lint`, CI, self-documenting `Makefile` (`make` lists targets)
- [x] Hygiene gate `make check`: `fmt-check`, `tidy-check`, `vet`, `lint`, `vuln` (`govulncheck` pinned as a Go tool), tests with race and coverage of `internal/` ≥ 90%; `make fuzz` runs every `Fuzz*` target; `make check-all` adds the Docker suites
- [x] Static cross-compiled builds for `linux/amd64` and `linux/arm64` (`CGO_ENABLED=0`), version/commit/date via `-ldflags`, `SHA256SUMS`
- [x] Linux dev container (`build/dev.Dockerfile`): every make target that runs Go runs in it, as the calling user, with a cache volume; no macOS stubs or build tags
- [x] CI: `make mod-verify check`, `make fuzz`, `make test-net test-systemd`, `make release tools`, all in the dev container — *green on GitHub*
- [x] Platform layer: the four interfaces in `ARCHITECTURE.md` §3 with fakes for tests, collector registry with availability states
- [x] `internal/clock` (wall and simulated) used by everything that reads time
- [x] Config loader: YAML + `LAN_SENTINEL_*` env + flags + defaults, strict validation (unknown keys fail)
- [x] Commands: `daemon run`, `config validate`, `config show [--sources]`, `version`
- [x] `slog` logging with journald handler and text/JSON fallback
- [x] SQLite store (`modernc.org/sqlite`) with embedded migrations, WAL, single writer goroutine, batched commits
- [x] Daemon lifecycle: context cancellation, `sd_notify` READY/WATCHDOG, graceful shutdown, SIGHUP reload — *verified under systemd in a container (`make test-systemd`)*
- [x] systemd container test (`make test-systemd`): reference unit unchanged, `Type=notify`, identity and capabilities, reload, clean stop, capcheck under the unit's sandbox, `systemd-analyze security` ≤ 2.5 (now 1.6)
- [x] Docker network test harness (`make test-net`, `ARCHITECTURE.md` §9): test network with simulated hosts, runner as uid 65534 with only `CAP_NET_RAW`, `tools/capcheck` with and without the capability
- [ ] Capability check under the reference unit with only `CAP_NET_RAW`: every row of `ARCHITECTURE.md` §8, in Docker and on each target board; record results there. Any failure stops the project for a decision. — *Docker and systemd container: passed; boards deferred, tracked under Open hardware and field checks*
- [x] Golden reconstruction scenario (`DATA_MODEL.md` §10) committed under `test/golden/reconstruction/` as observation stream + expected bindings, events and query answers; a harness that validates the fixture (including that the expected answers follow from the expected bindings) and runs it through the correlator (skipped until phase 1, so CI stays green)
- [x] `deploy/`: reference unit, `sysusers.d`, `tmpfiles.d`, default config, replay `config.dev.yaml`

**Exit:** daemon starts under systemd as `lan-sentinel` with only `CAP_NET_RAW`, creates `hosts.db`, reloads config on SIGHUP, shuts down cleanly; capability check passed in Docker and on every target board; golden scenario committed.

## Phase 1 — Observation pipeline, interfaces, neighbours (2–3 weeks)

- [x] `Observation` type, `Source` enum, JSONL encoding, bounded bus with drop counter, ordered interface states and barriers
- [x] Replay collector, JSONL input: time-ordered merge of several files, simulated-clock and real-time modes, `exit_when_done`; replay and live interfaces cannot be mixed; `make run-dev`
- [x] Interface manager over `InterfaceMonitor` (netlink): one network context per interface name, `context_prefixes` history, follow changes, emit `INTERFACE_UP/DOWN`, `SUBNET_CHANGED` (applied by the correlator, in order with observations)
- [x] Neighbour collector over `NeighborSource` (netlink): startup dump, `RTM_NEWNEIGH`/`RTM_DELNEIGH` subscription, resubscribe and resync on loss and on interval, source `kernel_neighbor` with NUD state, stamped with the kernel's confirmation time
- [x] Docker network tests for the netlink backends: neighbours appearing, changing MAC (gratuitous ARP) and expiring (unresolvable, and a host that disappears); a network connected to and disconnected from the runner (link and address events); the daemon on two test networks finding hosts with their vendor (a real Siemens OUI), scoped per interface (the same MAC on both networks is two hosts with `MAC_MOVED`)
- [x] Correlator v1: `DATA_MODEL.md` §5.1 (host = context + MAC, unbound observations), §5.2 on-link check, §5.3 open/replace/takeover/conflict/expiry with interval semantics of §3, late-observation rule, §5.5 services; data-driven time; state loaded at startup; `HOST_DISCOVERED`, `IP_ADDED`, `IP_CHANGED`, `IP_REMOVED`, `MAC_MOVED`, `DUPLICATE_IP_DETECTED/RESOLVED`, `SERVICE_OPENED/CLOSED`
- [x] Schema constraints and partial unique indexes from `DATA_MODEL.md` §4 (in the phase 0 migration)
- [x] Presence state machine with configurable thresholds; `HOST_DISAPPEARED`, `HOST_REAPPEARED`
- [x] Event engine writing to `events` (with `cause` and `evidence_json` snapshot) and journald
- [x] OUI vendor lookup (IEEE MA-L/MA-M/MA-S, longest prefix) with a generator (`make oui`) that builds a compact embedded table; optional override file; locally administered flag

**Exit:** `make run-dev` replays the golden stream and the resulting database matches the expected bindings; in the Docker test network and on a test LAN, hosts appear from the kernel neighbour table alone, with vendor and correct per-interface scoping; the golden scenario passes at correlator level except the conflict steps (phase 2). — *Status: replay, golden scenario (including the conflict steps, implemented early) and Docker test network met; real test LAN deferred, tracked under Open hardware and field checks.*

## Phase 2 — Passive capture (3–4 weeks)

- [x] `AF_PACKET` capture per interface, BPF filter, optional promiscuous mode, ring buffer sizing (`passive.ring_size`), capture-drop counters; the host's own frames are never captured; reopen with back-off when the interface goes away
- [x] Docker network tests for capture: frames from other MACs injected from another container, own frames not captured, promiscuous mode with only `CAP_NET_RAW`, drop counter on an overflowing ring, the daemon naming hosts from captured frames
- [x] Decoders: ARP (incl. gratuitous and probes), IPv4 source, IPv6 + NDP, DHCP (option 12 hostname, 61 client-id, 55 parameter list and 60 vendor class kept for later fingerprinting), mDNS (A/AAAA/PTR/SRV/TXT), DNS PTR responses, LLDP; repeats suppressed for 2 minutes
- [x] Fuzz target per decoder (and for whole frames)
- [ ] pcap fixtures from real sites — *synthetic fixture in place (`make fixtures`); real captures tracked under Open hardware and field checks*
- [x] Replay collector, pcap/pcapng input through the same decoders and refresh suppression
- [x] Name bindings (`DATA_MODEL.md` §5.4) and `preferred_name` precedence; `HOSTNAME_ADDED/CHANGED/REMOVED`; DNS PTR names attach without presence
- [x] Conflict detection from capture (conflicting ARP replies, gratuitous ARP) feeding the correlator's conflict handling (done in phase 1); proxy-ARP flagging (`DATA_MODEL.md` §5.2)
- [x] Retention, hourly roll-up and compaction job; `max_db_size` enforcement; golden scenario re-run after simulated 7-day compaction gives identical answers and evidence
- [x] Startup integrity check with quarantine and recreate; `DATABASE_RECREATED`

**Exit:** full golden scenario passes at correlator level; passive-only build runs 7 days on 3 pilot sites with < 5% CPU and < 50 MB RSS on a RevPi, and reconstructs an injected IP change and duplicate IP correctly. First field-deployable release (v0.1). — *Status: golden scenario passes at correlator level, also after a simulated 7-day compaction; the site capture replayed through the daemon reconstructs the IP change and the duplicate IP from frames; capture verified in Docker with only `CAP_NET_RAW`. The pilot run is pending, tracked under Open hardware and field checks.*

## Phase 3 — Read side: API, CLI, metrics (2–3 weeks)

- [ ] REST API over `/run/lan-sentinel/api.sock` (0660, `lan-sentinel`), optional `127.0.0.1` listener; `/v1/status` includes per-collector state
- [ ] Endpoints: `/v1/status`, `/v1/interfaces`, `/v1/hosts`, `/v1/hosts/{id}`, `/v1/hosts/{id}/history`, `/v1/hosts/{id}/evidence`, `/v1/hosts/find?q=&interface=&at=`, `/v1/history?q=&interface=&since=&until=` (IP/MAC/name timelines), `/v1/observations?host=&interface=&mac=&ip=&source=&unbound=&since=&until=&rollups=`, `/v1/events`, `/v1/events/stream` (JSON lines, backs `watch`), `/v1/services`, `/v1/config`, `/v1/db` (scan and kill-switch endpoints in phase 4)
- [ ] CLI per `CLI.md`: subcommand tree, query auto-detection, `find --at` result cases (0 / 1 / ≥2 holders, unconfirmed, replaced-by), IP history, `hosts evidence`, `observations list`, `table`/`json`/`jsonl`/`csv` output, exit codes
- [ ] `--offline` per the contract in `CLI.md` §1, tested for: live DB beside the writer, no `-wal` (immutable open), unreadable `-wal`, busy timeout
- [ ] Prometheus `/metrics` on the local listener, low-cardinality metrics only

**Exit:** the golden scenario's queries pass end to end through the CLI, online and with `--offline`.

## Phase 4 — Active discovery with OT safety (3–4 weeks)

- [ ] Probe scheduler: per-probe intervals, startup delay, jitter, randomised target order, global and per-protocol token buckets, concurrency cap, TCP per-interface and per-host caps, per-target spacing, excludes, timeout back-off
- [ ] Kill switch: env, `POST /v1/active/disable` and `/v1/active/enable`, persisted in `runtime_state`, `ACTIVE_DISABLED/ENABLED` events, `active disable|enable` CLI
- [ ] Scan planner shared by `scan plan` (`POST /v1/scans/plan`, and offline from config) and `scan run` (`POST /v1/scans`), with identical refusal rules
- [ ] `Transmitter`: `AF_PACKET` frame writes, `SO_BINDTODEVICE` TCP connects, ping or raw ICMP sockets
- [ ] ARP sweep (native Go) within configured networks only; `max_auto_scan_prefix_v4` guard
- [ ] TCP connect probes bound to the interface, with OPEN/REFUSED/TIMEOUT/UNREACHABLE; `SERVICE_OPENED/CLOSED`
- [ ] ICMP echo via unprivileged ping sockets where allowed, else raw with `CAP_NET_RAW`
- [ ] IPv6 NDP solicitation for known addresses (no IPv6 sweeping)
- [ ] UDP framework that only runs protocol-specific probes; no generic UDP open/closed claims
- [ ] Scan profiles from config; `scan run` CLI; `SCAN_STARTED/COMPLETED` events and `scans` rows
- [ ] Docker network tests for probes: packet counting per protocol and per target against the budgets, excludes, prefix guard, result classification

**Exit:** active probing defaults to off, and when enabled never exceeds the global, per-protocol and per-host limits on a traffic-counting test rig; `scan plan` estimates match measured packets within 10%; the kill switch stops probing within one tick and survives a restart; soak test against real OT devices (PLC, inverter, HMI) shows no faults.

## Phase 5 — Release builds, hardening, pilot rollout (2 weeks)

- [ ] Release artifacts: static binaries for `linux/amd64` and `linux/arm64` with SHA-256 checksums; no `.deb` or other packages
- [ ] Capability audit on the boards; `systemd-analyze security` exposure ≤ 2.5 on the target systemd versions (1.6 in the container test)
- [ ] Clock-jump handling: mark events written before NTP sync. Note: the hardened unit's `ProtectClock=true` blocks `adjtimex` (the `@clock` syscall group), so sync detection needs another source (e.g. systemd-timesyncd's `/run/systemd/timesync/synchronized`) or an explicit `SystemCallFilter` exception
- [ ] Staged fleet rollout (below)

**Exit:** v1.0 on the full fleet with active discovery enabled per site.

## Phase 6+ — Identification plugins (ongoing)

Plugin interface in `internal/identify` taking a host's evidence and returning (field, value, confidence, evidence). Candidates in order of expected value: mDNS service types, Modbus Device Identification (FC 43/14), HTTP `Server` header and title, TLS certificate subject, DHCP fingerprint, SNMP `sysDescr`, hostname patterns.

## Testing strategy

| Layer | How | What it proves |
| --- | --- | --- |
| Decoders | Table tests over captured pcaps from real sites (ARP, DHCP, mDNS, LLDP, NDP) | Parsing of real OT device traffic, including malformed frames |
| Replay | Site pcaps replayed through the daemon with a simulated clock, compared with expected inventories | End-to-end behaviour on any machine, reproducible field issues |
| Toolchain | Dev container for every make target, locally and in CI | Identical Go, lint and test environment on every machine |
| Correlator | Golden tests: observation sequence in → expected bindings and events out, starting with the reconstruction scenario (`DATA_MODEL.md` §10) | IP change, takeover, duplicate IP and resolution, MAC move, NIC swap (new host), same IP on two interfaces, routed source IPs ignored, unbound probe results |
| Store | Migrations on empty and previous-version DBs; compaction; kill -9 during write | Crash safety and upgrade path |
| Platform backends and probes | Docker test network with simulated hosts (`make test-net`), runner as uid 65534 with only `CAP_NET_RAW`; in CI | Capture, netlink and transmit code under the real privilege model; rate limits, excludes, scope guards, result classification |
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
| A capture or netlink path needs `CAP_NET_ADMIN` | Security model and unit change | `capcheck` in Docker on every change (passing) and on target boards in phase 0 |
| Docker's kernel differs from the target kernels | A path works in tests but not in the field | Board capability check in phase 0; pilot sites before fleet rollout |
| Capture drops on busy mirrored ports | Missed observations | BPF filter to discovery protocols only, ring sizing, drop metric |
| SD card wear from SQLite writes | Storage failure | Batched commits every 5 s, compaction, `synchronous=NORMAL` in WAL |
| Clock jumps on boxes without RTC | Broken timelines | Mark events written before NTP sync |
| Kernel access spreads outside the platform layer | Code becomes hard to test without a network | Platform interfaces with fakes; review rule in `CLAUDE.md` |
| OUI data goes stale | Unknown vendors | Regenerate each release; optional override file |
