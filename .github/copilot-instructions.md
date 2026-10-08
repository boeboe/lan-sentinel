# Copilot instructions — LAN Sentinel

Read [`AGENTS.md`](../AGENTS.md) first. It is the single set of instructions for every coding agent here: the hard rules (§4), where the truth lives (§2), the package map, what to run and the common tasks. This file only summarises what must never be missed.

- Linux only, static `CGO_ENABLED=0` Go. Never add a cgo dependency (no libpcap, no mattn/go-sqlite3).
- Run Go only through `make`, which uses the Linux dev container; `make check` is the gate.
- Collectors and probes only emit observations. Only `internal/correlate` changes state and writes events. One SQLite writer.
- A host is one MAC on one interface, keyed by a UUID `host_id`. Never merge or split hosts.
- Kernel access (AF_PACKET, netlink, raw sockets) only in `internal/platform`.
- OT safety: active discovery is off by default and bounded by budgets, excludes and the /24 guard.
  - No SYN scans, no generic UDP scans, no IPv6 sweeps.
  - No payload-sending identification probes.
- No observation logging; no MAC, IP, hostname or host ID in metric labels.
- Migrations are append-only. Docs change in the same change as the code (`AGENTS.md` §12).
- If code and docs disagree, or a decision is missing, ask rather than guess.
