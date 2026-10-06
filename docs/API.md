# LAN Sentinel — Local API

The daemon serves a read API for the CLI and local integrations (FR-API-1). It is the only integration point in v1; no data leaves the box.

## Transport

| Listener | Address | Serves | Access |
| --- | --- | --- | --- |
| Unix socket | `api.socket` (default `/run/lan-sentinel/api.sock`) | `/v1/…` | Mode `0660`, owner `lan-sentinel:lan-sentinel` in a `0750` runtime directory: the service group and root. No other authentication in v1. |
| TCP (optional) | `api.listen`, loopback only (e.g. `127.0.0.1:9734`) | Reads only: `GET /v1/…` and `GET /metrics` when `metrics.enabled` | Anyone on the box. Requests whose `Host` is not a loopback name or address are refused (403), so a web page in a local browser cannot reach it through DNS rebinding. Endpoints that change state (phase 4) are served on the socket only, where the service group and `SO_PEERCRED` apply. |

A stale socket from a crashed daemon is replaced at start-up; a socket another daemon is listening on stops the start. The API reads through a read-only connection pool, so it sees what the single writer has committed: at most one batch interval (5 s) behind the correlator. Replays commit their last batch when they finish. `/v1/events/stream` is live.

All responses are JSON (`application/json`, times RFC 3339 UTC); the stream is JSON lines (`application/x-ndjson`). Errors are `{"error": "message"}` with status 400 (bad parameter or query), 403 (TCP `Host` not loopback), 404 (unknown host or endpoint), 405 (method other than `GET`/`HEAD`), 503 (database busy) or 500. `mac` and `ip` parameters accept any written form (`00-1B-1B-…`, `001b.1b…`, IPv4-mapped IPv6) and are normalised; a value that is not a MAC or IP is a 400.

The response types are the read model in `internal/store/model.go` (and `api.Status` in `internal/api`); their JSON field names are this contract.

## Endpoints

All are `GET`. Time parameters are RFC 3339; the CLI turns its local-time and duration forms into RFC 3339 before calling.

| Path | Parameters | Returns |
| --- | --- | --- |
| `/v1/status` | | `Status`: version, commit, platform, PID, start time, replay flag, `state` (`ok`, `degraded`: a configured collector is not running, `unhealthy`: the database does not answer), problems, database (path, ok, sizes, schema version), kill switch (`active`), interfaces with live state, MAC, prefixes and per-collector state (FR-STAT-1), host counts per interface and presence, last scan |
| `/v1/interfaces` | | `[]InterfaceInfo`: name, state (`up`, `down`, `absent`, `unknown`), MAC, open prefixes, passive/active/replay, host count |
| `/v1/hosts` | `interface`, `q` + optional `kind` (hosts that ever matched), `presence` (`live` = ACTIVE/RECENT, `notlive` = STALE/MISSING), `vendor` (substring of vendor or manufacturer), `port` (an OPEN service), `seen_since` | `[]HostSummary` with open IPs |
| `/v1/hosts/find` | `q` (required), `kind`, `interface`, `at` | `FindResult` (below) |
| `/v1/hosts/{id}` | | `Host`: summary plus every address and name binding (closed ones too) with sources, services, identifications |
| `/v1/hosts/{id}/history` | `since`, `until` | `[]Event` of the host (404 for an unknown host) |
| `/v1/hosts/{id}/evidence` | `since` | `Evidence`: the host, observation counts per source and IP (raw and roll-ups), the host's events with evidence snapshots |
| `/v1/evidence` | `q` (required), `kind`, `interface`, `since` | `[]Evidence` for every host that ever matched `q`, from one snapshot (`hosts evidence`) |
| `/v1/history` | `q` (required), `kind`, `interface`, `since`, `until` | `[]Event`: the timeline of a host, MAC, IP or name (`CLI.md` §4) |
| `/v1/observations` | `host`, `interface`, `mac`, `ip`, `source`, `unbound`, `since`, `until`, `limit` (default 1000, the latest), `rollups` | `[]Observation`, or with `rollups=true` `[]Rollup` |
| `/v1/events` | `since`, `until`, `type` (repeatable or comma-separated; spec or CLI names), `interface`, `mac`, `ip`, `host`, `limit` (the latest; default 10000) | `[]Event` in time order |
| `/v1/events/stream` | `interface`, `type`, `port` (service events of that port) | live `Event`s as JSON lines until the client disconnects (`watch`); without `id`, otherwise as stored. A client more than 256 events behind misses events rather than slowing the correlator |
| `/v1/services` | `port`, `state`, `interface` | `[]ServiceRow`: probe result with the host's interface, MAC and open IPs |
| `/v1/config` | | the effective configuration |
| `/v1/db` | | `DBInfo`: path, schema version, journal mode, file, data and WAL sizes, row counts |
| `/v1/db/check` | | `CheckResult` of `PRAGMA integrity_check` |

`q` is classified as host UUID, MAC (`aa:bb:..`, `aa-bb-..`, `aabb.ccdd.eeff`), IPv4, IPv6 or hostname, in that order; `kind` (`host`, `mac`, `ip`, `name`) overrides it, and a value that is not of that kind is a 400.

### `FindResult`

| Field | Meaning |
| --- | --- |
| `kind`, `query`, `at` | The classified query, normalised (lowercase MAC, canonical IP), and the time asked for |
| `hosts[]` | Every holder or match, each a `Host` with the attributes in effect at `at` (or now) plus, for IP queries: `binding` (with sources), `unconfirmed` (`at` > `last_seen`), `conflict` (two or more holders at `at`), `replaced_by` (the next binding of the IP), `moved_to` (the host's next address) and `conflict_event` (the `DUPLICATE_IP_DETECTED` covering `at`) |
| `previous[]`, `next[]` | For an IP with no holder at `at`: per interface, the binding that ended last before `at` and the one that started first after it |

## Metrics

`GET /metrics` on the TCP listener, Prometheus text format, gathered at scrape time. Labels are `interface`, `presence`, `type`, `source`, `protocol`, `port`, `result`, `reason` and `collector` only; never a MAC, IP, hostname or host ID (CLAUDE.md rule 9, enforced by `internal/metrics`).

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `lan_sentinel_hosts` | gauge | interface, presence | Hosts per presence state (every configured interface and state, zeros included) |
| `lan_sentinel_events_total` | counter | type | Events since start (every catalogue type) |
| `lan_sentinel_observations_total` | counter | source | Observations processed |
| `lan_sentinel_observations_unbound_total` | counter | source | Observations without a MAC that matched no host |
| `lan_sentinel_bus_dropped_total` | counter | | Observations dropped because the bus was full |
| `lan_sentinel_capture_drops_total` | counter | interface | Frames the kernel dropped because the capture ring was full |
| `lan_sentinel_db_size_bytes` | gauge | | Data size (pages in use), the value `max_db_size` caps |
| `lan_sentinel_active_disabled` | gauge | | 1 when the kill switch is set (persisted or by environment) |
| `lan_sentinel_collector_up` | gauge | interface, collector | 1 when a configured collector runs, 0 when it failed; disabled collectors are left out |

Phase 4 adds `lan_sentinel_probe_total{interface,protocol,port,result}`, `lan_sentinel_probe_throttled_total{protocol,reason}` and `lan_sentinel_scan_duration_seconds`.
