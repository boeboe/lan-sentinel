# ADR 0001: One static binary

- Status: Accepted
- Date: 5 Oct 2026 (v1 specification)
- Specified in: `ARCHITECTURE.md` §2 (CLI, Build, Delivery); `REQUIREMENTS.md` NFR-PORT-1, §5 (Deliverables); `CLI.md` §1

## Context

The product runs on about a thousand small Linux edge devices: Raspberry Pi CM4, RevPi Connect and amd64 boxes. Field engineers need a troubleshooting tool on the box itself. Shipping and upgrading anything must be trivial, and must not depend on distribution packages.

## Decision

`lan-sentinel` is a single statically linked Go binary (`CGO_ENABLED=0`, `linux/amd64` and `linux/arm64`). Its cobra subcommands make it:

- the daemon (`daemon run`);
- the CLI client of the daemon's Unix-socket API;
- the read-only database inspector (`--offline`);
- the on-demand scanner (`scan plan`, `scan run`, through the daemon).

A release is one tarball per target with the binary, `capcheck`, the reference unit and config, and checksums.

## Consequences

- The CLI and the daemon are always the same version on a box.
- Every dependency must be pure Go (AGENTS.md rule 1): `modernc.org/sqlite`, `gopacket/afpacket`, `vishvananda/netlink`.
- Read commands work in two modes: through the API, or offline from the database file. The same `store.Reader` queries serve both, so the answers are identical.
- An upgrade replaces one file and the unit (`deploy/README.md`).

## Ruled out

- `.deb`, `.rpm` or installers (AGENTS.md rule 3).
- cgo-based libpcap or SQLite drivers.
- A separate CLI binary.
