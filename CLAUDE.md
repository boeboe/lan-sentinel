# CLAUDE.md — LAN Sentinel

Permanent instructions for Claude Code working in this repository.

## What this is

LAN Sentinel is a single static Go binary, `lan-sentinel`, that runs as a systemd service on Linux edge devices and keeps a persistent, interface-aware, historical inventory of hosts on local OT networks. The same binary is the daemon, the CLI client, the database inspector and the on-demand scanner. The code base is Linux only (`linux/amd64`, `linux/arm64`). Every build, lint and test runs in the Linux dev container through `make`, so a development machine (Linux or macOS) only needs Docker, make and git.

## Sources of truth

Read these before changing anything. If code and docs disagree, stop and ask.

- `docs/REQUIREMENTS.md` — what the system must do (FR/NFR ids)
- `docs/ARCHITECTURE.md` — components, data flow, key decisions
- `docs/DATA_MODEL.md` — Observation type, SQLite schema, correlation rules, event catalogue
- `docs/CLI.md` — the v1 command-line contract
- `docs/API.md` — the local REST API and the metrics
- `docs/IMPLEMENTATION_PLAN.md` — phases, tasks, exit criteria

## Names and paths (fixed)

| Item | Value |
| --- | --- |
| Repository / Go module | `lan-sentinel` |
| Binary | `lan-sentinel` |
| systemd unit | `lan-sentinel.service` |
| Service user/group | `lan-sentinel` |
| Config | `/etc/lan-sentinel/config.yaml` |
| Database | `/data/lan-sentinel/hosts.db` |
| API socket | `/run/lan-sentinel/api.sock` |
| Minimum kernel | 5.10 |
| Env prefix | `LAN_SENTINEL_` |
| Metrics prefix | `lan_sentinel_` |

## Hard rules

1. **Static Linux builds only.** `CGO_ENABLED=0`, delivered targets `linux/amd64` and `linux/arm64`. Never add a dependency that needs cgo (no libpcap, no mattn/go-sqlite3). Use `modernc.org/sqlite`, `gopacket/afpacket` and `gopacket/layers` (also to build probe frames), `vishvananda/netlink`. Raw frame I/O for probes goes through a generic frame connection in `internal/platform`; protocol logic stays out of the platform package. Do not add `mdlayher/arp` or `mdlayher/ndp` unless gopacket plus the platform layer cannot do something cleanly.
2. **Linux only; kernel access behind the platform interfaces.** The code base targets Linux only: no build tags, no stubs or implementations for other OSes. Capture, neighbour and interface monitoring and probe transmission go through `internal/platform` (`Capturer`, `NeighborSource`, `InterfaceMonitor`, `Transmitter`) so the rest can be tested with fakes; sd_notify and journald go through `internal/service`. Run Go only through `make` (the dev container), never on the macOS host.
3. **No packages.** A release is one tarball per target (`linux/amd64`, `linux/arm64`) with the static binary, `capcheck` and the reference unit/sysusers/tmpfiles/config files from `deploy/`, plus SHA-256 checksums, published by the manual `release` workflow from `main`. No `.deb`, `.rpm` or installers.
4. **Collectors only emit observations.** Collectors and probes never touch the database or host state. They send `observation.Observation` values on the bus. Only the correlator goroutine mutates state and writes events.
5. **Single SQLite writer.** One writer goroutine, WAL mode, batched transactions. CLI `--offline` opens the DB read-only (`mode=ro`).
6. **Host = MAC per interface.** Within a network context (the interface) a host has exactly one MAC and the MAC is the only identity evidence; hosts are never merged or split. Rows are keyed by an internal UUID `host_id`. The same IP or MAC on two interfaces is two different hosts/bindings. Bindings use `first_seen`/`last_seen`/`ended_at` (NULL = open) as defined in `docs/DATA_MODEL.md` §3.
7. **OT safety first.** Active discovery is off by default, only scans explicitly configured networks, respects the global packet-rate budget, concurrency cap, excludes and the `/24` prefix guard. Never add SYN scanning, generic UDP port scanning or IPv6 sweeping. TCP probes are plain `connect()` with immediate close and no payload. ARP sweeps the configured networks; ICMP, TCP and UDP probe known hosts only. UDP probes are protocol-specific (NTP, EtherNet/IP ListIdentity) and only add evidence: no response means nothing, never that a host is offline.
8. **No journal spam.** Observations are never logged. Only state transitions (events) go to journald.
9. **No high-cardinality metrics.** Never put MAC, IP, hostname or host ID in Prometheus labels.
10. **Least privilege.** Only `CAP_NET_RAW`. Do not introduce anything needing `CAP_NET_ADMIN` or root. `make test-net` enforces this in Docker.
11. **Out of scope for v1:** VLAN tagging, web UI, any data leaving the box (fleet aggregation, remote API), identification plugins beyond OUI (phase 6+). Do not build these without an explicit request.
12. **IPv4-first.** v1 active discovery is IPv4: ARP is the primary LAN discovery mechanism. IPv6 active probing (NDP solicitation) is deferred; do not implement it until it is requested. Passive IPv6/NDP decoding stays.

## Conventions

- Go 1.26+ (the floor set by `x/net`, `x/sys` and `modernc.org/sqlite`), standard layout: `cmd/lan-sentinel`, `internal/...` (see `docs/ARCHITECTURE.md`).
- CLI with cobra; config with YAML + env + flags, strict validation (unknown keys are errors).
- Logging with `log/slog`; journald handler in production, text or JSON handler in a terminal or container.
- Concurrency with `context` and `errgroup`; every goroutine stops on context cancellation.
- Use `net/netip` for addresses, `net.HardwareAddr` for MACs.
- Migrations are numbered `.sql` files in `migrations/`, embedded with `go:embed`, applied at startup.
- Tests: table-driven; decoders tested against frames built with gopacket (`test/frames`) and pcap fixtures in `test/fixtures/` (synthetic until real site captures are added); correlator tested with golden observation streams in `test/golden/` — the reconstruction scenario (`docs/DATA_MODEL.md` §10) must always pass; platform backends and probes tested in Docker on a test network with simulated hosts, as uid 65534 with only `CAP_NET_RAW` (`test/net/`, build tag `nettest`, `make test-net`).
- Every decoder gets a `go test -fuzz` target.
- Coverage of `internal/` (from every test package, `-coverpkg`) must stay at or above 90%; `make check` enforces it. Cover behaviour, not lines: error paths, retries and validation rules count; trivial tests written only for the number do not.
- Errors wrapped with `%w`; no panics outside `main`.

## Commands

```bash
make              # list all targets (make help)
make check        # fast gate: fmt-check, tidy-check, vet, lint, vuln, tests with race + coverage >= 90%
make check-all    # check + test-net + test-systemd
make build        # bin/lan-sentinel for the Docker host's architecture
make release      # static linux/amd64 + linux/arm64 into dist/ with checksums
make package      # release tarballs per target into dist/release/ (VERSION=vX.Y.Z)
make test         # unit and golden tests with -race
make coverage     # tests with coverage of internal/ (coverage.out), fails below 90%; make cover opens the report
make fuzz         # every Fuzz* target, FUZZTIME each (default 30s)
make test-net     # network integration tests in Docker (CAP_NET_RAW only)
make test-systemd # daemon under systemd in a container with the deploy/ unit
make run-dev      # daemon in the dev container on deploy/config.dev.yaml (replay)
make tools        # tools/capcheck for linux/amd64 + linux/arm64 (privilege check for boards)
make oui          # regenerate the embedded IEEE OUI table (each release)
make fixtures     # regenerate the synthetic pcap fixtures in test/fixtures
make fmt / tidy   # fix formatting / go.mod
make shell        # shell in the dev container
```

## How to work

- Work phase by phase from `docs/IMPLEMENTATION_PLAN.md`. Tick the checkbox when a task is done and its tests pass.
- Every make target that runs Go runs in the Linux dev container (`build/dev.Dockerfile`); do not run `go` directly on a macOS host.
- Run `make check` before considering a change done, and `make check-all` when touching platform, service, deploy or test-harness code.
- A phase is done only when its exit criterion is demonstrably met.
- If a requirement is unclear or a decision is missing, ask rather than guess; record the answer in the relevant doc.
- Keep docs in sync: a change to the CLI, schema, config keys or events updates `docs/` in the same change.
