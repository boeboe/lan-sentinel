# ADR 0004: SQLite in WAL mode with a single writer

- Status: Accepted
- Date: 5 Oct 2026 (v1 specification)
- Specified in: `ARCHITECTURE.md` §2 (Storage, SQLite driver), §3 (Store); `REQUIREMENTS.md` NFR-PERF-1, NFR-PERF-2, FR-ST-*; `DATA_MODEL.md` §4, §9; `CLI.md` §1

## Context

The history must survive power cuts on devices with SD cards. Writes must be few, to limit wear. Field engineers need to query the database even when the daemon is down. Everything must be one portable file, read by a cgo-free binary.

## Decision

- **Engine.** SQLite through `modernc.org/sqlite` (pure Go), in WAL mode with `synchronous=NORMAL`.
- **One writer.** A single writer goroutine in `internal/store` commits batched transactions, targeting one every 5 s. The correlator assigns row ids itself, so it can refer to rows not yet committed.
- **Reads.** The API and `--offline` use the same read-only `store.Reader` queries; `--offline` opens with `mode=ro` under the offline-access contract of `CLI.md` §1.
- **Migrations.** Numbered and embedded, applied forward only at start-up; an older binary refuses a newer schema.
- **Integrity.** `PRAGMA quick_check` runs at start-up. A corrupt file is quarantined and recreated (`DATABASE_RECREATED`).

## Consequences

- No lock contention, and the order of state changes is deterministic.
- Reads see committed data at most one batch behind.
- A crash loses at most the open batch. `test/crash` kills the daemon mid-write five times and checks that nothing committed is lost.
- Released migrations are immutable (AGENTS.md §13). Changing a CHECK constraint means rebuilding the table.
- 90 simulated days of a worst-case 50-host LAN reach 158.8 MB, within the 200 MB budget (`make soak`, 7 Oct 2026).

## Ruled out

- cgo SQLite drivers (`mattn/go-sqlite3`).
- Several writers, or writes from the API or CLI.
- A server database.
