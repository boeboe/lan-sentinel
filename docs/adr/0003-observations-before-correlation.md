# ADR 0003: Observations before correlation

- Status: Accepted
- Date: 5 Oct 2026 (v1 specification)
- Specified in: `ARCHITECTURE.md` §1, §2 (Data flow, Concurrency), §3 (Observation bus, Correlator); `DATA_MODEL.md` §2, §5

## Context

Evidence about hosts arrives from many independent sources:

- passive capture;
- the kernel neighbour table;
- active probes;
- replay files.

Correlation must be deterministic. The same evidence must always give the same hosts, bindings and events, so that a site's history can be reproduced from a capture and golden tests are exact.

## Decision

Every source emits normalised `observation.Observation` values onto one bounded bus. Collectors and probes never touch state or the database.

A single correlator goroutine (`internal/correlate`) applies the rules of `DATA_MODEL.md` §5 to each message in order. It is the only code that changes host state and emits events.

Time is data:

- rules use each observation's timestamp;
- timer transitions are stamped with the moment their threshold was crossed;
- every component reads time through `clock.Clock`.

When the bus is full, live observations are dropped and counted, so collectors never block. Interface states, replayed observations and operator messages wait instead.

## Consequences

- Collectors and decoders are pure and testable in isolation. The correlator is tested with golden observation streams (`test/golden`), and replay on a simulated clock reproduces live behaviour exactly.
- A new evidence source is a new collector that emits observations. It never gets a shortcut to state.
- Observations are never logged (AGENTS.md rule 8); events are the record of change.

## Ruled out

- Collectors writing to the database or keeping their own host state.
- Several correlator goroutines.
- Wall-clock reads inside correlation rules.
