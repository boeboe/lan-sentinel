# LAN Sentinel — Implementation Plan

Six phases, each ending in a shippable build. Passive discovery lands before any active probing so the first field deployments cannot disturb OT equipment. Estimates assume one experienced Go engineer: 14–18 weeks of build plus about 4 weeks of pilot and soak time that overlaps later phases.

| Phase | Scope | Estimate | Exit gate |
| --- | --- | --- | --- |
| 0 | Foundations | 2 weeks | Daemon runs under systemd and reloads on SIGHUP |
| 1 | Observation pipeline and netlink | 2–3 weeks | Hosts appear from the neighbour table with vendor, scoped per interface |
| 2 | Passive capture | 3–4 weeks | **v0.1 field release:** passive only, 7-day pilot on 3 sites |
| 3 | API, CLI and metrics | 2–3 weeks | Historical-reconstruction acceptance test passes through the CLI |
| 4 | Active discovery with OT safety | 3–4 weeks | No faults in OT device soak; packet-rate limits verified |
| 5 | Release builds, hardening, rollout | 2 weeks | **v1.0** on the full fleet; active discovery enabled per site |
| 6+ | Identification plugins | ongoing | — |

## Phase 0 — Foundations (2 weeks)

- [ ] Repo skeleton, Go module `lan-sentinel`, `golangci-lint`, CI, `Makefile` with `build`, `release`, `test`, `test-netns`, `lint`
- [ ] Static cross-compiled builds for `linux/amd64` and `linux/arm64` (`CGO_ENABLED=0`), version/commit/date via `-ldflags`, `SHA256SUMS`
- [ ] Config loader: YAML + `LAN_SENTINEL_*` env + flags + defaults, strict validation (unknown keys fail)
- [ ] Commands: `daemon run`, `config validate`, `config show [--sources]`, `version`
- [ ] `slog` logging with journald handler and text fallback
- [ ] SQLite store (`modernc.org/sqlite`) with embedded migrations, WAL, single writer goroutine, batched commits
- [ ] Daemon lifecycle: context cancellation, `sd_notify` READY/WATCHDOG, graceful shutdown, SIGHUP reload
- [ ] Capability check on each target board/kernel under the reference unit with only `CAP_NET_RAW`: every row of the table in `ARCHITECTURE.md` §8; record results there. Any failure stops the project for a decision.
- [ ] Golden reconstruction scenario (`DATA_MODEL.md` §10) committed under `test/golden/reconstruction/` as observation stream + expected bindings, events and query answers; a test harness that runs it (failing until phase 1)
- [ ] `deploy/`: reference unit, `sysusers.d`, `tmpfiles.d`, default config

**Exit:** daemon starts under systemd as `lan-sentinel` with only `CAP_NET_RAW`, creates `hosts.db`, reloads config on SIGHUP, shuts down cleanly; capability check passed on all target boards; golden scenario committed.

## Phase 1 — Observation pipeline and netlink (2–3 weeks)

- [ ] `Observation` type, `Source` enum, bounded bus, drop counter
- [ ] Interface manager: enumerate links and addresses, one network context per interface name, `context_prefixes` history, follow changes, emit `INTERFACE_UP/DOWN`, `SUBNET_CHANGED`
- [ ] Netlink neighbour collector: startup dump, `RTM_NEWNEIGH`/`RTM_DELNEIGH` subscription, NUD state as metadata only
- [ ] Correlator v1: `DATA_MODEL.md` §5.1 (host = context + MAC, unbound observations), §5.2 on-link check, §5.3 open/replace/takeover/expiry with interval semantics of §3; `HOST_DISCOVERED`, `IP_ADDED`, `IP_CHANGED`, `IP_REMOVED`, `MAC_MOVED`
- [ ] Schema constraints and partial unique indexes from `DATA_MODEL.md` §4
- [ ] Presence state machine with configurable thresholds; `HOST_DISAPPEARED`, `HOST_REAPPEARED`
- [ ] Event engine writing to `events` (with `cause` and `evidence_json` snapshot) and journald
- [ ] OUI vendor lookup (IEEE MA-L/MA-M/MA-S) with a generator that builds a compact embedded table; optional override file; locally administered flag

**Exit:** on a test LAN, hosts appear from the kernel neighbour table alone, with vendor and correct per-interface scoping; the golden scenario passes at correlator level except the conflict steps (phase 2).

## Phase 2 — Passive capture (3–4 weeks)

- [ ] `AF_PACKET` capture per interface, BPF filter, optional promiscuous mode, ring buffer sizing, capture-drop metric
- [ ] Decoders: ARP (incl. gratuitous), IPv4 source, IPv6 + NDP, DHCP (option 12 hostname, 61 client-id, 55 parameter list kept for later fingerprinting), mDNS (A/AAAA/PTR/SRV/TXT), DNS responses, LLDP
- [ ] Fuzz target per decoder; pcap fixtures from real sites
- [ ] Name bindings (`DATA_MODEL.md` §5.4) and `preferred_name` precedence; `HOSTNAME_ADDED/CHANGED/REMOVED`
- [ ] Conflict handling: `DUPLICATE_IP_DETECTED` / `DUPLICATE_IP_RESOLVED` (conflicting ARP replies or gratuitous ARP), `conflict` flag; proxy-ARP flagging
- [ ] Retention, hourly roll-up and compaction job; `max_db_size` enforcement; golden scenario re-run after simulated 7-day compaction gives identical answers and evidence
- [ ] Startup integrity check with quarantine and recreate

**Exit:** full golden scenario passes at correlator level; passive-only build runs 7 days on 3 pilot sites with < 5% CPU and < 50 MB RSS on a RevPi, and reconstructs an injected IP change and duplicate IP correctly. First field-deployable release (v0.1).

## Phase 3 — Read side: API, CLI, metrics (2–3 weeks)

- [ ] REST API over `/run/lan-sentinel/api.sock` (0660, `lan-sentinel`), optional `127.0.0.1` listener
- [ ] Endpoints: `/v1/status`, `/v1/interfaces`, `/v1/hosts`, `/v1/hosts/{id}`, `/v1/hosts/{id}/history`, `/v1/hosts/{id}/evidence`, `/v1/hosts/find?q=&interface=&at=`, `/v1/history?q=&interface=&since=&until=` (IP/MAC/name timelines), `/v1/observations?host=&interface=&mac=&ip=&source=&unbound=&since=&until=&rollups=`, `/v1/events`, `/v1/events/stream` (JSON lines, backs `watch`), `/v1/services`, `/v1/config`, `/v1/db` (scan and kill-switch endpoints in phase 4)
- [ ] CLI per `CLI.md`: subcommand tree, query auto-detection, `find --at` result cases (0 / 1 / ≥2 holders, unconfirmed, replaced-by), IP history, `hosts evidence`, `observations list`, `table`/`json`/`jsonl`/`csv` output, exit codes
- [ ] `--offline` per the contract in `CLI.md` §1, tested for: live DB beside the writer, no `-wal` (immutable open), unreadable `-wal`, busy timeout
- [ ] Prometheus `/metrics` on the local listener, low-cardinality metrics only

**Exit:** the golden scenario's queries pass end to end through the CLI, online and with `--offline`.

## Phase 4 — Active discovery with OT safety (3–4 weeks)

- [ ] Probe scheduler: per-probe intervals, startup delay, jitter, randomised target order, global and per-protocol token buckets, concurrency cap, TCP per-interface and per-host caps, per-target spacing, excludes, timeout back-off
- [ ] Kill switch: env, `POST /v1/active/disable` and `/v1/active/enable`, persisted in `runtime_state`, `ACTIVE_DISABLED/ENABLED` events, `active disable|enable` CLI
- [ ] Scan planner shared by `scan plan` (`POST /v1/scans/plan`, and offline from config) and `scan run` (`POST /v1/scans`), with identical refusal rules
- [ ] ARP sweep (native Go) within configured networks only; `max_auto_scan_prefix_v4` guard
- [ ] TCP connect probes with OPEN/REFUSED/TIMEOUT/UNREACHABLE; `SERVICE_OPENED/CLOSED`
- [ ] ICMP echo via unprivileged ping sockets where allowed, else raw with `CAP_NET_RAW`
- [ ] IPv6 NDP solicitation for known addresses (no IPv6 sweeping)
- [ ] UDP framework that only runs protocol-specific probes; no generic UDP open/closed claims
- [ ] Scan profiles from config; `scan run` CLI; `SCAN_STARTED/COMPLETED` events and `scans` rows

**Exit:** active probing defaults to off, and when enabled never exceeds the global, per-protocol and per-host limits on a traffic-counting test rig; `scan plan` estimates match measured packets within 10%; the kill switch stops probing within one tick and survives a restart; soak test against real OT devices (PLC, inverter, HMI) shows no faults.

## Phase 5 — Release builds, hardening, pilot rollout (2 weeks)

- [ ] Release artifacts: static binaries for `linux/amd64` and `linux/arm64` with SHA-256 checksums; no `.deb` or other packages
- [ ] Hardened unit, capability audit, `systemd-analyze security` exposure ≤ 2.5
- [ ] Clock-jump handling: mark events written before NTP sync
- [ ] Staged fleet rollout (below)

**Exit:** v1.0 on the full fleet with active discovery enabled per site.

## Phase 6+ — Identification plugins (ongoing)

Plugin interface in `internal/identify` taking a host's evidence and returning (field, value, confidence, evidence). Candidates in order of expected value: mDNS service types, Modbus Device Identification (FC 43/14), HTTP `Server` header and title, TLS certificate subject, DHCP fingerprint, SNMP `sysDescr`, hostname patterns.

## Testing strategy

| Layer | How | What it proves |
| --- | --- | --- |
| Decoders | Table tests over captured pcaps from real sites (ARP, DHCP, mDNS, LLDP, NDP) | Parsing of real OT device traffic, including malformed frames |
| Correlator | Golden tests: observation sequence in → expected bindings and events out, starting with the reconstruction scenario (`DATA_MODEL.md` §10) | IP change, takeover, duplicate IP and resolution, MAC move, NIC swap (new host), same IP on two interfaces, routed source IPs ignored, unbound probe results |
| Store | Migrations on empty and previous-version DBs; compaction; kill -9 during write | Crash safety and upgrade path |
| Probes | `ip netns` + veth pairs in CI, fake hosts answering ARP/TCP | Rate limits, excludes, scope guards, result classification |
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
| OUI data goes stale | Unknown vendors | Regenerate each release; optional override file |
