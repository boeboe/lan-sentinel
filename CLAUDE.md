# CLAUDE.md — LAN Sentinel

Permanent instructions for Claude Code working in this repository.

## What this is

LAN Sentinel is a single static Go binary, `lan-sentinel`, that runs as a systemd service on edge devices and keeps a persistent, interface-aware, historical inventory of hosts on local OT networks. The same binary is the daemon, the CLI client, the database inspector and the on-demand scanner.

## Sources of truth

Read these before changing anything. If code and docs disagree, stop and ask.

- `docs/REQUIREMENTS.md` — what the system must do (FR/NFR ids)
- `docs/ARCHITECTURE.md` — components, data flow, key decisions
- `docs/DATA_MODEL.md` — Observation type, SQLite schema, correlation rules, event catalogue
- `docs/CLI.md` — the v1 command-line contract
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
| Env prefix | `LAN_SENTINEL_` |
| Metrics prefix | `lan_sentinel_` |

## Hard rules

1. **Static builds only.** `CGO_ENABLED=0`, targets `linux/amd64` and `linux/arm64`. Never add a dependency that needs cgo (no libpcap, no mattn/go-sqlite3). Use `modernc.org/sqlite`, `gopacket/afpacket`, `vishvananda/netlink`, `mdlayher/arp`, `mdlayher/ndp`.
2. **No packages.** Release artifacts are the two binaries plus SHA-256 checksums. No `.deb`, `.rpm` or installers. Reference unit/sysusers/tmpfiles/config files live in `deploy/`.
3. **Collectors only emit observations.** Collectors and probes never touch the database or host state. They send `observation.Observation` values on the bus. Only the correlator goroutine mutates state and writes events.
4. **Single SQLite writer.** One writer goroutine, WAL mode, batched transactions. CLI `--offline` opens the DB read-only (`mode=ro`).
5. **Host = MAC per interface.** Within a network context (the interface) a host has exactly one MAC and the MAC is the only identity evidence; hosts are never merged or split. Rows are keyed by an internal UUID `host_id`. The same IP or MAC on two interfaces is two different hosts/bindings. Bindings use `first_seen`/`last_seen`/`ended_at` (NULL = open) as defined in `docs/DATA_MODEL.md` §3.
6. **OT safety first.** Active discovery is off by default, only scans explicitly configured networks, respects the global packet-rate budget, concurrency cap, excludes and the `/24` prefix guard. Never add SYN scanning, generic UDP port scanning or IPv6 sweeping. TCP probes are plain `connect()` with immediate close and no payload.
7. **No journal spam.** Observations are never logged. Only state transitions (events) go to journald.
8. **No high-cardinality metrics.** Never put MAC, IP, hostname or host ID in Prometheus labels.
9. **Least privilege.** Only `CAP_NET_RAW`. Do not introduce anything needing `CAP_NET_ADMIN` or root.
10. **Out of scope for v1:** VLAN tagging, web UI, any data leaving the box (fleet aggregation, remote API), identification plugins beyond OUI (phase 6+). Do not build these without an explicit request.

## Conventions

- Go 1.23+, standard layout: `cmd/lan-sentinel`, `internal/...` (see `docs/ARCHITECTURE.md`).
- CLI with cobra; config with YAML + env + flags, strict validation (unknown keys are errors).
- Logging with `log/slog`; journald handler in production, text handler in a terminal.
- Concurrency with `context` and `errgroup`; every goroutine stops on context cancellation.
- Use `net/netip` for addresses, `net.HardwareAddr` for MACs.
- Migrations are numbered `.sql` files in `migrations/`, embedded with `go:embed`, applied at startup.
- Tests: table-driven; decoders tested against pcap fixtures in `test/fixtures/`; correlator tested with golden observation streams in `test/golden/` — the reconstruction scenario (`docs/DATA_MODEL.md` §10) must always pass; probes tested in network namespaces (`test/netns/`, needs root, behind a build tag `netns`).
- Every decoder gets a `go test -fuzz` target.
- Errors wrapped with `%w`; no panics outside `main`.

## Commands

```bash
make build        # host build
make release      # static linux/amd64 + linux/arm64 into dist/ with checksums
make test         # unit tests with -race
make test-netns   # namespace integration tests (sudo)
make lint         # golangci-lint
```

## How to work

- Work phase by phase from `docs/IMPLEMENTATION_PLAN.md`. Tick the checkbox when a task is done and its tests pass.
- A phase is done only when its exit criterion is demonstrably met.
- If a requirement is unclear or a decision is missing, ask rather than guess; record the answer in the relevant doc.
- Keep docs in sync: a change to the CLI, schema, config keys or events updates `docs/` in the same change.
