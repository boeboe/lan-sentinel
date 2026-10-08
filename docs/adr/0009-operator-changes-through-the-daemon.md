# ADR 0009: Operator changes travel through the daemon

- Status: Accepted
- Date: 6 Oct 2026 (kill switch and scans); applied to host descriptions 7 Oct 2026
- Specified in: `ARCHITECTURE.md` §3 (API and CLI, Active probes); `API.md` (Operator endpoints); `DATA_MODEL.md` §5.8, §8; `REQUIREMENTS.md` §5 (Kill switch, Host descriptions)

## Context

Operators change state:

- the kill switch (`active disable`/`enable`);
- operator scans (`scan run`);
- host descriptions (`hosts set`/`unset`).

Each change must be audited as an event with the caller, and ordered with the observations around it. It must also respect the single writer (ADR 0004) and the single correlator (ADR 0003).

## Decision

The CLI calls an operator endpoint of the API. The daemon's `api.Control` implementation hands the change to the correlator as an operator message on the bus (`Bus.PublishOperator`, with a barrier). The correlator applies it and emits its event, and the API answers once the store has committed it. The caller is taken from the socket's `SO_PEERCRED`.

A `config reload` is not an operator message: it changes no stored state. The daemon swaps its running configuration atomically and logs the reload with its caller (`ARCHITECTURE.md` §6).

## Consequences

- Operator changes are ordered with observations, recorded with their caller, and appear in `watch` like any other event.
- `--offline` cannot make changes. Write commands fail with a usage error that names the running daemon.
- Once the correlator has stopped, the bus is closed and such requests fail rather than wait.
- A new operator action means a new `Operator` kind, handling in `internal/correlate`, an endpoint and a `Control` method. It is never a direct database write.

## Ruled out

- The CLI or the API writing the database directly.
- Changes that bypass the event record.
