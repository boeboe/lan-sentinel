# CLAUDE.md — LAN Sentinel

Permanent instructions for Claude Code working in this repository.

## What this is

LAN Sentinel is a single cgo-free Go binary, `lan-sentinel`, that runs as a service (systemd on Linux, launchd on macOS) and keeps a persistent, interface-aware, historical inventory of hosts on local OT networks. The same binary is the daemon, the CLI client, the database inspector and the on-demand scanner. Linux and macOS (darwin) are both development platforms and delivery targets, on amd64 and arm64, with full feature parity.

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
| Service | Linux: systemd `lan-sentinel.service`; darwin: LaunchDaemons `lan-sentinel` and `lan-sentinel-prepare` |
| Service user/group | Linux: `lan-sentinel`; darwin: `_lan-sentinel` (+ group `access_bpf`) |
| Config | Linux: `/etc/lan-sentinel/config.yaml`; darwin: `/usr/local/etc/lan-sentinel/config.yaml` |
| Database | Linux: `/data/lan-sentinel/hosts.db`; darwin: `/usr/local/var/lan-sentinel/hosts.db` |
| API socket | Linux: `/run/lan-sentinel/api.sock`; darwin: `/var/run/lan-sentinel/api.sock` |
| Minimum OS | Linux kernel 5.10; macOS 14 |
| Env prefix | `LAN_SENTINEL_` |
| Metrics prefix | `lan_sentinel_` |

## Hard rules

1. **cgo-free builds for four targets.** `CGO_ENABLED=0`, targets `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`; all four must build and pass unit/golden tests on every change. Static on Linux; darwin links only `libSystem`. Never add a dependency that needs cgo (no libpcap, no mattn/go-sqlite3). Use `modernc.org/sqlite`; on Linux `gopacket/afpacket`, `vishvananda/netlink`, `mdlayher/arp`, `mdlayher/ndp`; on darwin `golang.org/x/sys/unix` (BPF ioctls), `golang.org/x/net/route`, `golang.org/x/net/bpf`, `gopacket/layers`.
2. **Platform code only behind the platform interfaces.** Capture, neighbour monitoring, interface monitoring and probe transmission/socket setup go through `internal/platform` (`Capturer`, `NeighborSource`, `InterfaceMonitor`, `Transmitter`) with `_linux.go` and `_darwin.go` backends; service glue lives in `internal/service`. Nothing else may import OS-specific packages. Every feature ships on both OSes; cross-compiling is not proof — each backend needs native tests on its OS.
3. **No packages.** Release artifacts are the four binaries plus SHA-256 checksums. No `.deb`, `.rpm`, `.pkg`, Homebrew formula or installers. Reference unit/sysusers/tmpfiles/config files live in `deploy/`.
4. **Collectors only emit observations.** Collectors and probes never touch the database or host state. They send `observation.Observation` values on the bus. Only the correlator goroutine mutates state and writes events.
5. **Single SQLite writer.** One writer goroutine, WAL mode, batched transactions. CLI `--offline` opens the DB read-only (`mode=ro`).
6. **Host = MAC per interface.** Within a network context (the interface) a host has exactly one MAC and the MAC is the only identity evidence; hosts are never merged or split. Rows are keyed by an internal UUID `host_id`. The same IP or MAC on two interfaces is two different hosts/bindings. Bindings use `first_seen`/`last_seen`/`ended_at` (NULL = open) as defined in `docs/DATA_MODEL.md` §3.
7. **OT safety first.** Active discovery is off by default, only scans explicitly configured networks, respects the global packet-rate budget, concurrency cap, excludes and the `/24` prefix guard. Never add SYN scanning, generic UDP port scanning or IPv6 sweeping. TCP probes are plain `connect()` with immediate close and no payload.
8. **No journal spam.** Observations are never logged. Only state transitions (events) go to the log sink (journald on Linux, JSON lines on darwin).
9. **No high-cardinality metrics.** Never put MAC, IP, hostname or host ID in Prometheus labels.
10. **Least privilege.** Linux: only `CAP_NET_RAW`, never `CAP_NET_ADMIN` or root. Darwin: the daemon runs as `_lan-sentinel` with BPF device access via `access_bpf`, never as root; only the boot-time `daemon prepare` job runs as root.
11. **Out of scope for v1:** VLAN tagging, web UI, any data leaving the box (fleet aggregation, remote API), identification plugins beyond OUI (phase 6+). Do not build these without an explicit request.

## Conventions

- Go 1.23+, standard layout: `cmd/lan-sentinel`, `internal/...` (see `docs/ARCHITECTURE.md`).
- CLI with cobra; config with YAML + env + flags, strict validation (unknown keys are errors).
- Logging with `log/slog`; journald handler on Linux, JSON lines under launchd on darwin, text handler in a terminal.
- Concurrency with `context` and `errgroup`; every goroutine stops on context cancellation.
- Use `net/netip` for addresses, `net.HardwareAddr` for MACs.
- Migrations are numbered `.sql` files in `migrations/`, embedded with `go:embed`, applied at startup.
- Tests: table-driven; decoders tested against pcap fixtures in `test/fixtures/`; correlator tested with golden observation streams in `test/golden/` — the reconstruction scenario (`docs/DATA_MODEL.md` §10) must always pass; platform backends and probes tested natively on each OS (`test/net/`, build tag `nettest`, needs root): network namespaces + veth on Linux, `feth` pairs on darwin.
- Every decoder gets a `go test -fuzz` target.
- Errors wrapped with `%w`; no panics outside `main`.

## Commands

```bash
make build        # host build (linux or darwin)
make release      # linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 into dist/ with checksums
make run-dev      # daemon on the host with deploy/config.dev.yaml (replay of a fixture)
make test         # unit tests with -race
make test-net     # native network integration tests: netns (Linux) / feth (darwin), sudo
make lint         # golangci-lint
```

## How to work

- Work phase by phase from `docs/IMPLEMENTATION_PLAN.md`. Tick the checkbox when a task is done and its tests pass.
- A phase is done only when its exit criterion is demonstrably met.
- If a requirement is unclear or a decision is missing, ask rather than guess; record the answer in the relevant doc.
- Keep docs in sync: a change to the CLI, schema, config keys or events updates `docs/` in the same change.
