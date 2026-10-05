# LAN Sentinel — CLI

One static binary, `lan-sentinel`, is the service, the troubleshooting client, the database inspector and the on-demand scanner.

```text
lan-sentinel [global options] <command> <subcommand> [options]
```

## 1. How commands reach data

- **Online (default):** commands talk to the running daemon over `/run/lan-sentinel/api.sock`. This gives consistent reads and is required for `scan run`, `active enable|disable`, `watch` and `daemon status`.
- **Offline (`--offline`):** the CLI opens the database directly, read-only. Read commands (`hosts`, `events`, `observations`, `services`, `interfaces`, `db`, `scan plan`) still work when the daemon will not start. Commands that need the daemon refuse `--offline` with exit 64 and a clear message.

`lan-sentinel daemon run` stays in the foreground; systemd owns the process. No double-fork daemonisation.

### Offline database access contract

| Situation | Behaviour |
| --- | --- |
| Daemon running (`hosts.db-wal` present) | Open `file:<path>?mode=ro` with `PRAGMA busy_timeout = 5000` and `PRAGMA query_only = 1`. Never `immutable=1`. Each command runs in a single read transaction, so it sees one consistent snapshot. Requires read access to the directory, `hosts.db`, `-wal` and `-shm` (group `lan-sentinel`, see below). |
| No `-wal` file (daemon stopped cleanly; the last connection checkpoints and removes the WAL) | Open `file:<path>?mode=ro&immutable=1`, because a read-only user cannot create `-shm`. Data is complete. The CLI prints a notice to stderr. If `-wal` appears while the command runs (daemon started), results may be stale; re-run. |
| `-wal` present but not readable, or `-shm` missing and the directory not writable | Exit 2: `cannot open database read-only beside the WAL; run as a member of group lan-sentinel or copy the database`. |
| Copied database | Copy only after `systemctl stop lan-sentinel`, or copy `hosts.db`, `-wal` and `-shm` together. A `hosts.db` copied alone while the daemon was running lacks every transaction since the last checkpoint; the CLI cannot detect this. |
| `SQLITE_BUSY` after the busy timeout | Exit 2 with the SQLite error. |

The daemon runs with `UMask=0027` and the data directory is `0750 lan-sentinel:lan-sentinel` (from `tmpfiles.d`), so database files are group-readable. Operators who use `--offline` must be in group `lan-sentinel` or use `sudo`. Offline commands keep their read transaction short; a long-held reader stops WAL checkpoints.

## 2. Global options

| Option | Meaning |
| --- | --- |
| `--config PATH` | Config file (default `/etc/lan-sentinel/config.yaml`) |
| `--db PATH` | Database path for `--offline` (default from config) |
| `--socket PATH` | API socket (default `/run/lan-sentinel/api.sock`) |
| `-o`, `--output table\|json\|jsonl\|csv` | Output format (default `table`) |
| `--no-color` | Disable colour |
| `--log-level trace\|debug\|info\|warn\|error` | Log level |
| `--timeout DURATION` | Client timeout |
| `--offline` | Read the database directly, read-only |
| `--quiet` | Minimal output; rely on exit code |

## 3. v1 commands

| Command | Purpose | Key options | Phase |
| --- | --- | --- | --- |
| `daemon run` | Run the service in the foreground | `--config`, `--log-level` | 0 |
| `daemon status` | Version, PID, uptime, DB health, interfaces, host counts, kill-switch state, last scan, collector health | `-o json`; `--quiet` exit codes | 3 |
| `hosts list` | Inventory: MAC, IP, hostname, vendor, interface, presence, last seen | `--interface`, `--active`, `--stale`, `--vendor`, `--port`, `--seen-within` | 3 |
| `hosts show <host-id>` | Full record of one host | | 3 |
| `hosts find <query>` | Current or point-in-time holder(s) with addresses, names and services and their sources | `--interface`, `--at <time>` | 3 |
| `hosts history <query>` | Event timeline for a host, MAC, IP or name | `--interface`, `--since`, `--until` | 3 |
| `hosts evidence <query>` | Why we believe what we believe about a host: per attribute, the sources, first/last seen and counts, plus the evidence snapshots of its events | `--interface`, `--since` | 3 |
| `observations list` | Raw observations within retention; hourly roll-ups with `--rollups` | `--host`, `--interface`, `--mac`, `--ip`, `--source`, `--unbound`, `--since`, `--until`, `--limit`, `--rollups` | 3 |
| `events list` | All events on this box | `--since`, `--until`, `--type`, `--interface`, `--mac`, `--ip` | 3 |
| `services list` | Probe results per host and port | `--port`, `--state`, `--interface` | 3 (data from 4) |
| `interfaces list` | State, MAC, current prefixes, passive/active per interface | | 3 |
| `watch` | Live event stream | `--interface`, `--type`, `--port` | 3 |
| `active disable` | Kill switch: stop all active probing now; persists across restarts | `--reason TEXT` (required) | 4 |
| `active enable` | Clear the kill switch | `--reason TEXT` | 4 |
| `scan plan` | Dry run: what a scan would do, sending nothing | same as `scan run` | 4 |
| `scan run` | Operator-triggered scan, bound by the same safety controls | `--interface`, `--network`, `--arp`, `--icmp`, `--tcp <port>` (repeatable), `--profile` | 4 |
| `config show` | Effective config after merging defaults, file, env and flags | `--sources` | 0 |
| `config validate` | Validate a config before rollout | `--config` | 0 |
| `db info` | Path, schema version, journal mode, size, WAL size, row counts | | 3 |
| `db check` | SQLite integrity check | | 3 |
| `version` | Version, commit, build date, Go version, architecture | | 0 |

There are no merge or split commands: within an interface a host is its MAC (`DATA_MODEL.md` §1).

Deferred past v1: `daemon reload` (use `systemctl reload lan-sentinel`), `neighbors list`, `interfaces show`, `scan status`, `db vacuum`, `db export`.

## 4. Behaviour details

### Query auto-detection (`hosts find`, `hosts history`, `hosts evidence`)

The argument is classified in this order: host UUID → MAC (any of `aa:bb:..`, `aa-bb-..`, `aabb.ccdd.eeff`) → IPv4 → IPv6 → hostname. Explicit flags `--ip`, `--mac`, `--hostname`, `--id` override detection. Multiple matches (e.g. the same IP or MAC on two interfaces) are all shown, grouped by interface, unless `--interface` is given.

### `hosts find`

Without `--at`, shows hosts with an open binding for the query. With `--at T`, uses the point-in-time query in `DATA_MODEL.md` §4:

| Holders at T | Output | Exit |
| --- | --- | --- |
| 1 | The host record, its binding interval, and `Replaced by:` the next binding for that IP (if any) and the host's next address (if any). If `T > last_seen` the binding is marked `unconfirmed since <last_seen>`. | 0 |
| ≥ 2 | Every holder, each marked `CONFLICT`, plus the `DUPLICATE_IP_DETECTED` event that covers T | 0 |
| 0 | `no holder at T`, plus the previous binding (holder and end time) and the next binding (holder and start time) | 1 |

For a MAC or name query, `--at` shows the host and the addresses and names in effect at T.

### `hosts history`

- Host UUID or MAC: every event for that host (for a MAC, for each context it appears in).
- IP: every event whose old or new value is that IP, across all hosts that ever held it, in time order. This is the IP's ownership timeline.
- Name: every event for hosts that ever held that name.

### `hosts evidence`

For each attribute (each address, name, service, identification) the sources that confirmed it, with first/last seen per source (from `address_sources` and roll-ups) and observation counts within roll-up retention. Then the host's events with their `evidence_json` snapshots, which remain after raw observations are pruned.

### `observations list`

Columns: time, interface, source, MAC, IP, hostname, service, host ID. `--unbound` shows observations that matched no host. Observations older than raw retention are only available with `--rollups` (one row per host, source, MAC, IP and hour, with count). Default `--limit` 1000.

### `active disable` / `active enable`

`disable` stops all probe engines within one scheduler tick, cancels running scans, writes the persisted kill switch (`DATA_MODEL.md` §8) and emits `ACTIVE_DISABLED` with the reason and the calling Unix user (from `SO_PEERCRED`). `enable` clears it and emits `ACTIVE_ENABLED`; it fails with exit 2 if `LAN_SENTINEL_ACTIVE_DISABLED=1` is set. Enabling the switch does not override per-interface `active.enabled: false`.

### `scan plan`

Accepts the same options as `scan run`, sends nothing, and prints:

- interface, requested networks, profile and probes/ports
- target count after excludes, and the excluded IPs/ranges that applied
- per-protocol rate, effective packets/s against the global budget, concurrency caps
- estimated packets, connections and duration
- verdict: `ALLOWED` or `REFUSED` with every reason (kill switch set, active discovery disabled on the interface, network outside the interface's configured networks, prefix wider than `max_auto_scan_prefix_v4`, no targets left)

Exit 0 if allowed, 2 if refused. Online, the daemon computes the plan from its effective config. With `--offline`, the CLI computes it from the config file and the persisted kill switch.

### `scan run`

Computes the same plan, prints it, and refuses (exit 2) if `scan plan` would. Otherwise it runs through the daemon's scheduler and budgets, prints progress and a summary, and returns when the scan completes.

### Time arguments

`--since`/`--seen-within` accept durations (`24h`, `7d`) or timestamps. `--at`/`--until` accept `YYYY-MM-DD`, `YYYY-MM-DD HH:MM[:SS]` (local time) or RFC 3339.

### Event type names

`--type` takes the kebab-case CLI names from `DATA_MODEL.md` §7, e.g. `ip-changed`, `duplicate-ip`, `mac-moved`. Repeatable.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success / healthy |
| 1 | Degraded (`daemon status`), or no results for `find` |
| 2 | Unhealthy (`daemon status`), command error, or scan refused |
| 3 | Daemon unreachable (online mode) |
| 64 | Usage error |

### `config validate` output

Prints interfaces with passive/active mode, active scan networks, enabled probes and ports, per-protocol budgets and the estimated maximum probe rate. Exit 0 if valid, 2 with per-key errors otherwise.

### `config show --sources`

Prints every effective key with where its value came from (default, file path, `LAN_SENTINEL_*` variable, or flag).

## 5. Examples

```bash
$ lan-sentinel hosts list --interface eth1
MAC                IP               HOSTNAME        VENDOR        IFACE  STATE   LAST SEEN
00:0c:26:8e:1b:d6  192.168.110.200  hmi01.local     Weintek Labs  eth1   ACTIVE  12s ago
00:1b:1b:12:34:56  192.168.110.60   inverter.local  Siemens       eth1   RECENT  14m ago
```

```bash
$ lan-sentinel hosts find 192.168.110.200
Host ID:     3db0ce66-38c2-4f50-a1ce-a593cb872f88
Interface:   eth1
MAC:         00:0c:26:8e:1b:d6  Weintek Labs
State:       ACTIVE
First seen:  2026-10-03 11:24:10
Last seen:   2026-10-05 19:52:44

Addresses:
  192.168.110.200  2026-10-03 11:24:10 → open   sources: passive_arp, netlink_neighbor, arp_scan

Names:
  hmi01.local      mdns

Services:
  tcp/80   OPEN     13s ago
  tcp/502  REFUSED  2m ago
```

```bash
$ lan-sentinel hosts find 192.168.110.50 --interface eth1 --at "2026-10-01 10:30"
Host ID:     8f0e2a71-5c1d-4d4e-9a0b-2b7f3c9e1d22
MAC:         00:1b:1b:aa:bb:01  Siemens
Binding:     192.168.110.50  2026-10-01 10:00:00 → 2026-10-01 11:00:00  (unconfirmed since 10:00:00)
Replaced by: 192.168.110.50 → 00:1b:1b:aa:bb:02 from 2026-10-01 12:00:00
             host moved to 192.168.110.51 at 2026-10-01 11:00:00 (IP_CHANGED, passive_dhcp)
```

```bash
$ lan-sentinel hosts history 192.168.110.50 --interface eth1
2026-10-01 10:00:00  HOST_DISCOVERED  eth1  00:1b:1b:aa:bb:01  192.168.110.50   passive_arp
2026-10-01 11:00:00  IP_CHANGED       eth1  00:1b:1b:aa:bb:01  .50 -> .51       passive_dhcp
2026-10-01 12:00:00  HOST_DISCOVERED  eth1  00:1b:1b:aa:bb:02  192.168.110.50   passive_arp
2026-10-01 14:00:00  SERVICE_OPENED   eth1  00:1b:1b:aa:bb:02  tcp/502          tcp_connect
```

```bash
$ lan-sentinel events list --type duplicate-ip --since 24h
2026-10-05 14:22:31  DUPLICATE_IP_DETECTED  eth0  192.168.0.1
    e8:48:b8:47:09:73
    38:43:7d:96:6a:91
```

```bash
$ lan-sentinel scan plan --interface eth1 --profile modbus
Interface:  eth1    Profile: modbus    Networks: 192.168.110.0/24
Targets:    253     (excluded: 192.168.110.1)
Probes:     arp; tcp/502
Rates:      arp 10 pps, tcp 5 connects/s (≤4 per interface, ≤1 per host); global cap 20 pps
Estimate:   253 ARP requests, 253 TCP connects (3 packets each), ~1012 packets, ~51 s
Verdict:    ALLOWED
```

```bash
$ lan-sentinel active disable --reason "PLC fault on line 3, investigating"
Active discovery disabled (persists across restarts). Clear with: lan-sentinel active enable
```

```bash
$ lan-sentinel watch --interface eth1
19:42:12  HOST_DISCOVERED  eth1  192.168.110.200  00:0c:26:8e:1b:d6  Weintek Labs
19:43:04  IP_CHANGED       eth1  192.168.110.60 -> 192.168.110.61  00:1b:1b:12:34:56
19:43:18  SERVICE_OPENED   eth1  192.168.110.61 tcp/502
```

```bash
$ lan-sentinel services list --port 502
IP               MAC                PORT     STATE    LAST CHECK
192.168.110.61   00:1b:1b:12:34:56  502/tcp  OPEN     13s ago
192.168.110.200  00:0c:26:8e:1b:d6  502/tcp  REFUSED  2m ago
```

```bash
$ lan-sentinel daemon status --quiet; echo $?
0
```

```bash
lan-sentinel scan run --interface eth1 --profile modbus
lan-sentinel observations list --host 3db0ce66-38c2-4f50-a1ce-a593cb872f88 --since 1h
lan-sentinel hosts evidence 192.168.110.200 --interface eth1
lan-sentinel hosts history 192.168.1.200 --offline --since 24h
lan-sentinel hosts find 192.168.1.200 --interface eth1 --at "2026-10-04 10:15"
```
