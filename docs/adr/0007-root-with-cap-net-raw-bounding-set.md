# ADR 0007: Run as root with `CAP_NET_RAW` as the only capability

- Status: Accepted (replaces the original `lan-sentinel` service user)
- Date: 6 Oct 2026
- Specified in: `REQUIREMENTS.md` NFR-SEC-1, §5 (Service identity); `ARCHITECTURE.md` §8; `deploy/README.md`

## Context

The first design ran the daemon as a dedicated `lan-sentinel` user, created by `sysusers.d`, with directories from `tmpfiles.d`, holding `CAP_NET_RAW` as an ambient capability. On a Debian 11 board the `sysusers.d` installation failed. That made the install fragile on exactly the systems the product targets. The maintainer asked for a simple, robust install.

## Decision

The reference unit runs the daemon as root, with:

- `CapabilityBoundingSet=CAP_NET_RAW`, so root holds that capability alone;
- the unchanged sandbox: `ProtectSystem=strict`, a system-call filter, `NoNewPrivileges` and the rest of `ARCHITECTURE.md` §8.

There is no service user, no `sysusers.d` and no `tmpfiles.d`. The socket and database are root's, so CLI commands use `sudo`.

## Consequences

- An install is only the binary, the config, `/data/lan-sentinel` and the unit.
- Exposure rises from 2.0 to 2.3, still below the 2.5 limit of NFR-SEC-1.
- The code must still work as an unprivileged user with only `CAP_NET_RAW` (AGENTS.md rule 10). `make test-net` runs it as uid 65534 to prove this, so returning to a service user stays possible.
- Anything needing `CAP_NET_ADMIN`, another capability or root's file access is still forbidden.

## Ruled out

- Unrestricted root.
- Any capability beyond `CAP_NET_RAW`.
- Depending on root's file access.
