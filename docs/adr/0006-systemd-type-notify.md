# ADR 0006: systemd `Type=notify` in the foreground

- Status: Accepted
- Date: 5 Oct 2026 (v1 specification)
- Specified in: `ARCHITECTURE.md` §2 (Service manager), §8; `REQUIREMENTS.md` NFR-REL-1

## Context

The daemon must report readiness, be restarted if it hangs, reload its configuration without a restart, and run in a tight sandbox. All target systems run systemd: Debian 11, 12 and 13, with systemd 247, 252 and 257.

## Decision

- **Foreground process.** The daemon runs in the foreground; systemd owns its lifecycle, with no double-fork and no PID file.
- **Readiness and watchdog.** It uses `Type=notify` with `READY=1` once serving and `WATCHDOG=1` within `WatchdogSec=60`, and stops gracefully on SIGTERM.
- **Reload.** SIGHUP (`ExecReload`, `systemctl reload`) and `lan-sentinel config reload` re-read the configuration, all or nothing.
- **Logging.** Through a journald slog handler, with structured fields per event.
- **The unit.** The reference unit in `deploy/` is the tested unit. `make test-systemd` runs it unchanged on Debian 11, 12 and 13, and fails if `systemd-analyze security` exposure exceeds 2.5.

## Consequences

- sd_notify and journald code lives in `internal/service` only.
- `deploy/README.md`'s install block restarts the daemon (`systemctl restart`), so re-running it upgrades a running install. `enable --now` would leave the old binary running.
- On systemd 247, `PrivateIPC=` is unknown and logged as a warning; this is expected.

## Ruled out

- Daemonising (forking) the process.
- Other init systems.
- Logging observations to the journal.
