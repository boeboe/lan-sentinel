# LAN Sentinel — Local API

The daemon serves an API for the CLI and local integrations (FR-API-1): reads, plus the operator endpoints (the active-discovery kill switch, scans, configuration reload). It is the only integration point in v1; no data leaves the box.

## Transport

| Listener | Address | Serves | Access |
| --- | --- | --- | --- |
| Unix socket | `api.socket` (default `/run/lan-sentinel/api.sock`) | `/v1/…` | Mode `0660` in a `0750` runtime directory, owned by the daemon's user and group: `root:root` under the reference unit, so callers need `sudo`. No other authentication in v1. |
| TCP (optional) | `api.listen`, loopback only (e.g. `127.0.0.1:9734`) | Reads only: `GET /v1/…` and `GET /metrics` when `metrics.enabled` | Anyone on the box. Requests whose `Host` is not a loopback name or address are refused (403), so a web page in a local browser cannot reach it through DNS rebinding. The operator endpoints, which change state, are served on the socket only, where file permissions and `SO_PEERCRED` apply. |

A stale socket from a crashed daemon is replaced at start-up; a socket another daemon is listening on stops the start. The API reads through a read-only connection pool, so it sees what the single writer has committed: at most one batch interval (5 s) behind the correlator. Replays commit their last batch when they finish. `/v1/events/stream` is live.

All responses are JSON (`application/json`, times RFC 3339 UTC); the stream is JSON lines (`application/x-ndjson`). Errors are `{"error": "message"}` with status 400 (bad parameter, query or request body), 403 (TCP `Host` not loopback), 404 (unknown host or endpoint), 405 (method other than `GET`/`HEAD` on a read endpoint, other than `POST` on an operator endpoint, or anything but a read on the TCP listener), 409 (operator request in conflict, below), 422 (configuration reload rejected, below), 503 (database busy) or 500. `mac` and `ip` parameters accept any written form (`00-1B-1B-…`, `001b.1b…`, IPv4-mapped IPv6) and are normalised; a value that is not a MAC or IP is a 400.

The response types are the read model in `internal/store/model.go` (and `api.Status` in `internal/api`); their JSON field names are this contract. Every `Event` carries `clock_sync`: `synced`, `unsynced` (written before NTP synchronisation, so its `ts` may be off) or `unknown` (`DATA_MODEL.md` §7).

## Endpoints

The read endpoints are `GET`. Time parameters are RFC 3339; the CLI turns its local-time and duration forms into RFC 3339 before calling.

| Path | Parameters | Returns |
| --- | --- | --- |
| `/v1/status` | | `Status`: version, commit, platform, PID, start time, replay flag, `state` (`ok`, `degraded`: a configured collector is not running, `unhealthy`: the database does not answer), problems, database (path, ok, sizes, schema version), kill switch (`active`), `clock` (the kernel clock: `synced`, `unsynced` or `unknown`), interfaces with live state, MAC, prefixes and per-collector state (FR-STAT-1): collector, backend (e.g. `afpacket`, `netlink`, `ping socket`, `socket`), state, error, since and, for a probe, `last_pass` (its last periodic pass: `at` when it ended, `seconds`, `probed`, `replied` (a reply, or TCP OPEN or REFUSED), `blocked` (refused by the policy, not sent), `complete` (false when cut short); absent before the first), host counts per interface and presence, `last_scan` (the latest `scans` row: id, interface, kind, trigger, started, finished, targets, results; `null` before the first scan) |
| `/v1/interfaces` | | `[]InterfaceInfo`: name, state (`up`, `down`, `absent`, `unknown`), MAC, open prefixes, passive/active/replay, host count |
| `/v1/hosts` | `interface`, `q` + optional `kind` (hosts that ever matched), `presence` (`live` = ACTIVE/RECENT, `notlive` = STALE/MISSING), `vendor` (substring of vendor or manufacturer), `port` (an OPEN service), `seen_since` | `[]HostSummary` with open IPs |
| `/v1/hosts/find` | `q` (required), `kind`, `interface`, `at` | `FindResult` (below) |
| `/v1/hosts/{id}` | | `Host`: summary plus every address and name binding (closed ones too) with sources, services, identifications (field, value, confidence, source, evidence, first/last seen, `current`: the value the source holds now) |
| `/v1/hosts/{id}/history` | `since`, `until` | `[]Event` of the host (404 for an unknown host) |
| `/v1/hosts/{id}/evidence` | `since` | `Evidence`: the host, observation counts per source and IP (raw and roll-ups), the host's events with evidence snapshots |
| `/v1/evidence` | `q` (required), `kind`, `interface`, `since` | `[]Evidence` for every host that ever matched `q`, from one snapshot (`hosts evidence`) |
| `/v1/history` | `q` (required), `kind`, `interface`, `since`, `until` | `[]Event`: the timeline of a host, MAC, IP or name (`CLI.md` §4) |
| `/v1/observations` | `host`, `interface`, `mac`, `ip`, `source`, `unbound`, `since`, `until`, `limit` (default 1000, the latest), `rollups` | `[]Observation`, or with `rollups=true` `[]Rollup` |
| `/v1/events` | `since`, `until`, `type` (repeatable or comma-separated; spec or CLI names), `interface`, `mac`, `ip`, `host`, `limit` (the latest; default 10000) | `[]Event` in time order |
| `/v1/events/stream` | `interface`, `type`, `port` (service events of that port) | live `Event`s as JSON lines until the client disconnects (`watch`); without `id`, otherwise as stored. A client more than 256 events behind misses events rather than slowing the correlator |
| `/v1/services` | `port`, `state`, `interface` | `[]ServiceRow`: probe result with the host's interface, MAC and open IPs, and `detail` (what a protocol-specific UDP probe learnt, e.g. the NTP stratum) |
| `/v1/dhcp/servers` | `interface`, `status` (`allowed`, `unexpected`, `unchecked`) | `[]DHCPServer` (`DATA_MODEL.md` §5.6): `interface`, `server_id` (option 54; absent when unknown), `relay` (`giaddr`), `mac` and `ip` of the sender (the server or the relay), `host_id`, `status` (the allowlist verdict at the last reply), `config` (`router`, `dns`, `subnet_mask` last advertised), `first_seen`, `last_seen`; by interface, known identities first, the latest sender of each first |
| `/v1/config` | | the effective configuration |
| `/v1/db` | | `DBInfo`: path, schema version, journal mode, file, data and WAL sizes, row counts |
| `/v1/db/check` | | `CheckResult` of `PRAGMA integrity_check` |

`q` is classified as host UUID, MAC (`aa:bb:..`, `aa-bb-..`, `aabb.ccdd.eeff`), IPv4, IPv6 or hostname, in that order; `kind` (`host`, `mac`, `ip`, `name`) overrides it, and a value that is not of that kind is a 400.

### Operator endpoints

`POST` with a JSON body, on the Unix socket only. The actor recorded in the events is the Unix user of the calling process (`SO_PEERCRED`; `uid N` without a passwd entry). Kill-switch changes are serialised and recorded even if the client disconnects. In replay mode, where no probes run, the kill-switch endpoints only record the switch.

| Path | Body | Returns |
| --- | --- | --- |
| `/v1/active/disable` | `{"reason": "..."}` (required) | The kill switch state (`ActiveState`) once it is set and committed: probes stop at once, running scans are aborted, `ACTIVE_DISABLED` is recorded and the switch persists across restarts (`DATA_MODEL.md` §8) |
| `/v1/active/enable` | `{"reason": "..."}` (optional) | The state once cleared and committed, with `ACTIVE_ENABLED` (nothing is recorded when it was not set); probing resumes only then. 409 while `LAN_SENTINEL_ACTIVE_DISABLED=1` forces it |
| `/v1/scans/plan` | `Request` | `Plan`, computed by the same planner `scan run` uses; a refusal is a 200 with `allowed: false` and every reason |
| `/v1/scans` | `Request` | `ScanResult` once the scan is done: the plan and, per interface, start, end, ARP responders, counts per probe and result, and `aborted` (e.g. kill switch, or the scan could not be recorded and did not run). 409 with the `ScanResult` (its plan says why) when the plan refuses, 409 when another operator scan runs or in replay mode, 500 when the scan ran but could not be recorded. A client that disconnects aborts the scan |
| `/v1/config/reload` | none, or `{}` | `ReloadResult` once the daemon has re-read its configuration file, as on SIGHUP: `path`, `applied` (the keys whose new values took effect) and `not_applied` (changed keys that need a restart and keep their running values), each a list of `{key, old, new}` keyed as `config show --sources` keys them (for `not_applied`, `old` is the running value and `new` the file's). 422 when the file does not load or validate, or the running values it would keep do not validate with it; the error lists the per-key problems and nothing changed. Reloads are serialised with SIGHUP; the daemon logs each with the caller (FR-CFG-3) |

`Request` (`internal/probe`): `interfaces`, `networks` (inside the interfaces' configured networks), `profile`, `arp`, `icmp`, `tcp` (ports), `udp` (probe names), `allow_wide` (acknowledges a sweep of more than 65,536 addresses after its plan); probes named are added to the profile's, and with none at all the scan is an ARP sweep. `Plan`: `allowed`, `reasons`, `probes`, per interface the networks, `sweep_targets` (ARP), `known_targets` (ICMP/TCP/UDP), `excluded` (the excludes that applied) and an estimate, the rates, the total `estimate` (`arp_requests`, `icmp_echoes`, `tcp_connects`, `udp_probes`, `packets` (a TCP connect counts 3, its most), `typical_seconds` (the estimated typical duration), `no_response_seconds` (the estimated no-response duration)) and `assumptions`, the estimate's assumptions as sentences. In a `ScanResult`, an ARP sweep's unanswered addresses are one count per interface (`counts.arp.no_reply`).

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
| `lan_sentinel_dhcp_servers` | gauge | interface, status | DHCP servers (identity, relay and sender) heard from within `presence.stale`, by allowlist verdict: `allowed`, `unexpected`, `unchecked` (no allowlist). Alert on `status="unexpected"` above 0 |
| `lan_sentinel_probe_total` | counter | interface, protocol, port, result | Probes per result: `reply`/`no_reply` (ARP, ICMP, UDP), `open`/`refused`/`timeout`/`unreachable`/`unknown` (TCP), `blocked` (the policy refused it; nothing was sent). `port` is the UDP probe's port or a configured TCP port (`active.tcp.targets`, profiles), `other` for a TCP port given only to `scan run`, and empty for ARP and ICMP |
| `lan_sentinel_probe_throttled_total` | counter | protocol, reason | Probes that waited for a safety limit: `global`, `protocol`, `target_spacing`, `concurrency`, `tcp_interface`, `tcp_host` |
| `lan_sentinel_scan_duration_seconds` | gauge | interface, protocol | Duration of the last periodic pass or operator scan phase |
