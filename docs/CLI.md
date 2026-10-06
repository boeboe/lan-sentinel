# LAN Sentinel — CLI

One cgo-free binary, `lan-sentinel`, is the service, the troubleshooting client, the database inspector and the on-demand scanner.

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
| Daemon running (`hosts.db-wal` present) | Open `file:<path>?mode=ro` with `PRAGMA busy_timeout = 5000` and `PRAGMA query_only = 1`. Never `immutable=1`. Each command runs in a single read transaction, so it sees one consistent snapshot. Requires read access to the directory, `hosts.db`, `-wal` and `-shm` (service group, see below). |
| No `-wal` file (daemon stopped cleanly; the last connection checkpoints and removes the WAL) | Open `file:<path>?mode=ro&immutable=1`, because a read-only user cannot create `-shm`. Data is complete. The CLI prints a notice to stderr. If `-wal` appears while the command runs (daemon started), results may be stale; re-run. |
| `-wal` present but not readable, or `-shm` missing and the directory not writable | Exit 2: `cannot open database read-only beside the WAL; run as a member of the service group or copy the database`. |
| Copied database | Copy only after `systemctl stop lan-sentinel`, or copy `hosts.db`, `-wal` and `-shm` together. A `hosts.db` copied alone while the daemon was running lacks every transaction since the last checkpoint; the CLI cannot detect this. |
| `SQLITE_BUSY` after the busy timeout | Exit 2 with the SQLite error. |

The daemon runs with `UMask=0027` and the data directory is `0750 lan-sentinel:lan-sentinel` (from `tmpfiles.d`), so database files are group-readable. Operators who use `--offline` must be in that group or use `sudo`. Offline commands keep their read transaction short; a long-held reader stops WAL checkpoints.

## 2. Global options

| Option | Meaning |
| --- | --- |
| `--config PATH` | Config file (default `$LAN_SENTINEL_CONFIG`, else `/etc/lan-sentinel/config.yaml`) |
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
| `daemon status` | Version, platform, PID, uptime, DB health, interfaces, host counts, kill-switch state, last scan, and per-interface collector state (`running`/`disabled`/`unsupported`/`failed` + error) | `-o json`; `--quiet` exit codes | 3 |
| `hosts list` | Inventory: MAC, IP, hostname, vendor, interface, presence, last seen. `--active`: live hosts (ACTIVE or RECENT); `--stale`: the others (STALE or MISSING); `--port`: an OPEN service on that port; `--vendor`: substring of vendor or manufacturer | `--interface`, `--active`, `--stale`, `--vendor`, `--port`, `--seen-within` | 3 |
| `hosts show <host-id>` | Full record of one host | | 3 |
| `hosts find <query>` | Current or point-in-time holder(s) with addresses, names and services and their sources; exit 1 when nothing matches | `--interface`, `--at <time>`, `--ip`/`--mac`/`--hostname`/`--id` | 3 |
| `hosts history <query>` | Event timeline for a host, MAC, IP or name | `--interface`, `--since`, `--until`, `--ip`/`--mac`/`--hostname`/`--id` | 3 |
| `hosts evidence <query>` | Why we believe what we believe about a host: per attribute, the sources, first/last seen and counts, plus the evidence snapshots of its events; every host that ever matched the query; exit 1 when none | `--interface`, `--since`, `--ip`/`--mac`/`--hostname`/`--id` | 3 |
| `observations list` | Raw observations within retention; hourly roll-ups with `--rollups` | `--host`, `--interface`, `--mac`, `--ip`, `--source`, `--unbound`, `--since`, `--until`, `--limit`, `--rollups` | 3 |
| `events list` | Events on this box, the latest `--limit` (default 1000) in time order | `--since`, `--until`, `--type`, `--interface`, `--mac`, `--ip`, `--limit` | 3 |
| `services list` | Probe results per host and port | `--port`, `--state`, `--interface` | 3 (data from 4) |
| `interfaces list` | State, MAC, current prefixes, passive/active per interface | | 3 |
| `watch` | Live event stream | `--interface`, `--type`, `--port` | 3 |
| `active disable` | Kill switch: stop all active probing now; persists across restarts | `--reason TEXT` (required) | 4 |
| `active enable` | Clear the kill switch | `--reason TEXT` | 4 |
| `scan plan` | Dry run: what a scan would do, sending nothing | same as `scan run` | 4 |
| `scan run` | Operator-triggered scan, bound by the same safety controls | `--interface`, `--network` (repeatable), `--arp`, `--icmp`, `--tcp <port>` (repeatable), `--udp <probe>` (`ntp`, `enip`; repeatable), `--profile`, `--allow-wide` | 4 |
| `config show` | Effective config after merging defaults, file, env and flags | `--sources` | 0 |
| `config validate` | Validate a config before rollout | `--config` | 0 |
| `db info` | Path, schema version, journal mode, size, WAL size, row counts | | 3 |
| `db check` | SQLite integrity check | | 3 |
| `version` | Version, commit, build date, Go version, architecture | | 0 |

There are no merge or split commands: within an interface a host is its MAC (`DATA_MODEL.md` §1).

Deferred past v1: `daemon reload` (use `systemctl reload lan-sentinel`), `neighbors list`, `interfaces show`, `scan status`, `db vacuum`, `db export`.

## 4. Behaviour details

### Query auto-detection (`hosts find`, `hosts history`, `hosts evidence`)

The argument is classified in this order: host UUID → MAC (any of `aa:bb:..`, `aa-bb-..`, `aabb.ccdd.eeff`) → IPv4 → IPv6 → hostname. Instead of the argument, one of `--ip`, `--mac`, `--hostname`, `--id` gives the query with an explicit kind (e.g. `--hostname cafe.babe.f00d` for a name that looks like a MAC); a value that is not of that kind is a usage error (exit 64). Hostnames match case-insensitively. Multiple matches (e.g. the same IP or MAC on two interfaces) are all shown, grouped by interface, unless `--interface` is given.

### `hosts find`

Without `--at`, shows hosts with an open binding for the query. With `--at T`, uses the point-in-time query in `DATA_MODEL.md` §4:

| Holders at T | Output | Exit |
| --- | --- | --- |
| 1 | The host, its binding interval with sources, `Replaced by:` the next binding for that IP (if any) and `Moved to:` the host's next address (if any). If `T > last_seen` the binding is marked `unconfirmed since <last_seen>`. | 0 |
| ≥ 2 | Every holder, each binding marked `CONFLICT`, plus the `DUPLICATE_IP_DETECTED` event that covers T | 0 |
| 0 | `No holder of <ip> at T`, plus the previous binding (holder and end time) and the next binding (holder and start time) | 1 |

For a MAC or name query, `--at` shows the host and the addresses and names in effect at T.

### `hosts history`

- Host UUID or MAC: every event for that host, including those where it is the related host (the other side of a conflict or MAC move); for a MAC, for each context it appears in.
- IP: every event whose old value, new value or evidence IP (`evidence_json.ip`) is that IP, across all hosts that ever held it, in time order. This is the IP's ownership timeline, including service and conflict events seen on it.
- Name: every event for hosts that ever held that name.

### `hosts evidence`

For each attribute (each address, name, service, identification) the sources that confirmed it, with first/last seen per source (from `address_sources` and roll-ups) and observation counts within roll-up retention. Then the host's events with their `evidence_json` snapshots, which remain after raw observations are pruned.

### `observations list`

Columns: time, interface, source, MAC, IP, hostname, service, host ID. The latest `--limit` rows, in time order. `--unbound` shows observations that matched no host. Observations older than raw retention are only available with `--rollups` (one row per host, source, MAC, IP and hour, with count). Default `--limit` 1000.

### `active disable` / `active enable`

`disable` stops all probe engines at once (every probe checks the switch right before it is sent, and running passes and scans are cancelled), writes the persisted kill switch (`DATA_MODEL.md` §8) and emits `ACTIVE_DISABLED` with the reason and the calling Unix user (from `SO_PEERCRED`); it returns once that is committed. `enable` clears it and emits `ACTIVE_ENABLED` (a no-op when it is not set); probing resumes only once that is committed. It fails with exit 2 if `LAN_SENTINEL_ACTIVE_DISABLED=1` is set. Enabling the switch does not override per-interface `active.enabled: false`. Both need the daemon; `-o json` prints the resulting state.

### `scan plan`

Accepts the same options as `scan run`, sends nothing, and prints:

- interface, requested networks, profile and probes/ports
- targets after excludes: the addresses the ARP sweep covers (without the interface's own) and the known hosts (open IPv4 bindings in the networks) that ICMP, TCP and UDP probe, and the excludes that applied
- per-protocol rates, the TCP concurrency caps and the global budget
- estimated packets (a TCP connect counts 3, its most) and two durations, labelled: the **estimated typical duration** and the **estimated no-response duration**
- the assumptions behind the estimate: probes paced at the rates shown and at least the target spacing apart, sending and answering taking no time; for the typical duration, that known hosts answer at once while most swept addresses are empty, so only the ARP sweep waits out its reply timeout; for the no-response duration, that nothing answers, so every phase waits out its reply timeout (named per probe); and that hosts that first answer the sweep are probed too, which adds to a run
- verdict: `ALLOWED` or `REFUSED` with every reason (kill switch set, active discovery disabled on the interface, interface not configured, network outside the interface's configured networks or not IPv4, prefix wider than `max_auto_scan_prefix_v4`, a sweep beyond `active.max_sweep_targets`, a sweep of more than 65,536 addresses without `--allow-wide`, unknown profile or UDP probe, no targets left)

With no probe given (no `--arp`, `--icmp`, `--tcp`, `--udp` and no profile) the scan is an ARP sweep; probes given are added to the profile's. A sweep of more than 65,536 addresses (possible only with the expert override `active.max_sweep_targets`) is refused until the plan is repeated with `--allow-wide`: the refused plan is the preview, with the target count and both durations. Without `--interface` every interface with active discovery is planned. Exit 0 if allowed, 2 if refused. Online, the daemon computes the plan from its effective config, the kill switch, the live interface addresses and the known hosts. With `--offline`, the CLI computes it from the config file, the persisted kill switch and `LAN_SENTINEL_ACTIVE_DISABLED`, and the known hosts in the database; the interfaces' own addresses are unknown offline, so they count as sweep targets. The ARP responders of a run are probed as well, so a run can probe more hosts than its plan counts.

### `scan run`

Computes the same plan, prints it, and refuses (exit 2) if `scan plan` would. Otherwise it runs through the daemon's scheduler and budgets, interface by interface: the ARP sweep, then ICMP, TCP port by port and UDP probe by probe on the known hosts and the ARP responders. It prints the estimated typical duration while it runs and returns when the scan completes, with per interface the duration, how many hosts answered the sweep and the results per probe; exit 2 if the scan was aborted (the kill switch was set meanwhile), refused by the daemon, or done but not recorded. Only one operator scan runs at a time; interrupting `scan run` (Ctrl-C) aborts the scan, which is recorded as aborted. Each interface's scan is recorded as a `scans` row with `SCAN_STARTED` and `SCAN_COMPLETED` events; periodic passes are not. Needs the daemon.

### Time arguments

`--since`/`--seen-within` accept durations (`24h`, `7d`, `90m`) counted back from now, or timestamps. `--at`/`--until` accept `YYYY-MM-DD`, `YYYY-MM-DD HH:MM[:SS]` (local time) or RFC 3339. Tables show local time.

### Output formats

Lists (`hosts list`, `hosts history`, `observations list`, `events list`, `services list`, `interfaces list`) support all four formats; `json` is the API's objects (`API.md`), `csv` uses RFC 3339 UTC times and empty cells for missing values. Hostnames and other text come from the network, so a CSV cell starting with `=`, `+`, `-`, `@`, tab or carriage return is prefixed with `'` to keep spreadsheets from running it as a formula. Records (`hosts show`, `hosts find`, `daemon status`, `db info`, `db check`) support `table` and `json`; `hosts evidence` also `jsonl`; `watch` prints a line per event or, with `-o jsonl`/`json`, the event objects. `--quiet` prints nothing and leaves the answer to the exit code.

### Online reads

Online, the daemon answers from what its single writer has committed, at most one 5-second batch behind; `watch` is live. Offline and online answers come from the same queries, and each command is one snapshot (`hosts evidence` included). `--mac` and `--ip` filters accept any written form. A socket the caller may not open is exit 2 with a hint to join the service group (the daemon may be running); no daemon on the socket is exit 3.

### Event type names

`--type` takes the kebab-case CLI names from `DATA_MODEL.md` §7, e.g. `ip-changed`, `duplicate-ip`, `mac-moved`. Repeatable.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success / healthy |
| 1 | Degraded (`daemon status`, e.g. a configured collector not running), or no results for `find` |
| 2 | Unhealthy (`daemon status`), command error, or scan refused |
| 3 | Daemon unreachable (online mode) |
| 64 | Usage error |

### `config validate` output

Prints interfaces with passive/active mode, active scan networks with the number of addresses a sweep covers and how long one takes at the ARP rate, enabled probes and ports, per-protocol budgets, the expert override `active.max_sweep_targets` when it is above 65,536, and the estimated maximum probe rate. Exit 0 if valid, 2 with per-key errors otherwise.

### `config show --sources`

Prints every effective key with where its value came from (default, file path, `LAN_SENTINEL_*` variable, or flag).

## 5. Examples

The host, history, event, evidence and service outputs are from the golden reconstruction scenario (`DATA_MODEL.md` §10), with host IDs shortened; `interfaces list`, `watch` and `daemon status` show a live box. A name not confirmed for `name_expiry` is marked `(stale)` in the Names list.

```bash
$ lan-sentinel hosts list
MAC                IP              HOSTNAME     VENDOR              IFACE  STATE   LAST SEEN
00:1e:c9:00:00:01  -               plant-sw-01  Dell Inc.           eth0   ACTIVE  58m ago
00:0c:26:aa:bb:03  192.168.110.51  -            Weintek Labs. Inc.  eth1   STALE   2h ago
00:1b:1b:aa:bb:01  192.168.110.52  -            Siemens AG          eth1   STALE   1h ago
00:1b:1b:aa:bb:02  192.168.110.50  plc-b.local  Siemens AG          eth1   ACTIVE  59m ago
```

```bash
$ lan-sentinel hosts find 192.168.110.50
Host ID:     01a10f56-890f-7282-…
Interface:   eth1
MAC:         00:1b:1b:aa:bb:02  Siemens AG
State:       ACTIVE
Name:        plc-b.local
First seen:  2026-10-01 12:00:00
Last seen:   2026-10-01 14:01:00

Addresses:
  192.168.110.50   2026-10-01 12:00:00 → open   sources: passive_arp, tcp_connect, passive_mdns

Names:
  plc-b.local      mdns     confirmed 59m ago

Services:
  tcp/502  OPEN        1h ago

Identification:
  manufacturer=Siemens AG  oui  confidence 0.70
```

```bash
$ lan-sentinel hosts find 192.168.110.50 --interface eth1 --at "2026-10-01 10:30"
Host ID:     01a10f56-890f-70c4-…
Interface:   eth1
MAC:         00:1b:1b:aa:bb:01  Siemens AG
Binding:     192.168.110.50   2026-10-01 10:00:00 → 2026-10-01 11:00:00   sources: passive_arp   (unconfirmed since 2026-10-01 10:00:00)
Replaced by: 192.168.110.50 → 00:1b:1b:aa:bb:02 from 2026-10-01 12:00:00
Moved to:    192.168.110.51 at 2026-10-01 11:00:00
```

```bash
$ lan-sentinel hosts find 192.168.110.51 --interface eth1 --at "2026-10-01 13:10"
Host ID:     01a10f56-890f-7343-…
Interface:   eth1
MAC:         00:0c:26:aa:bb:03  Weintek Labs. Inc.
Binding:     192.168.110.51   2026-10-01 13:00:00 → open   sources: passive_arp   CONFLICT   (unconfirmed since 2026-10-01 13:00:00)
Conflict:    2026-10-01 13:00:00 DUPLICATE_IP_DETECTED 192.168.110.51 between 00:0c:26:aa:bb:03 and 00:1b:1b:aa:bb:01

Host ID:     01a10f56-890f-70c4-…
Interface:   eth1
MAC:         00:1b:1b:aa:bb:01  Siemens AG
Binding:     192.168.110.51   2026-10-01 11:00:00 → 2026-10-01 13:30:00   sources: passive_dhcp, kernel_neighbor   CONFLICT   (unconfirmed since 2026-10-01 12:58:00)
Moved to:    192.168.110.52 at 2026-10-01 13:30:00
Conflict:    2026-10-01 13:00:00 DUPLICATE_IP_DETECTED 192.168.110.51 between 00:0c:26:aa:bb:03 and 00:1b:1b:aa:bb:01
```

```bash
$ lan-sentinel hosts find 192.168.110.50 --interface eth1 --at "2026-10-01 11:30"; echo $?
No holder of 192.168.110.50 at 2026-10-01 11:30:00.
Previous:    192.168.110.50 held by 00:1b:1b:aa:bb:01 on eth1 until 2026-10-01 11:00:00
Next:        192.168.110.50 held by 00:1b:1b:aa:bb:02 on eth1 from 2026-10-01 12:00:00
1
```

```bash
$ lan-sentinel hosts history 192.168.110.50 --interface eth1
TIME                 TYPE             IFACE  MAC                VALUE                             RELATED  CAUSE
2026-10-01 10:00:00  HOST_DISCOVERED  eth1   00:1b:1b:aa:bb:01  192.168.110.50                    -        passive_arp
2026-10-01 11:00:00  IP_CHANGED       eth1   00:1b:1b:aa:bb:01  192.168.110.50 -> 192.168.110.51  -        passive_dhcp
2026-10-01 12:00:00  HOST_DISCOVERED  eth1   00:1b:1b:aa:bb:02  192.168.110.50                    -        passive_arp
2026-10-01 14:00:00  SERVICE_OPENED   eth1   00:1b:1b:aa:bb:02  tcp/502                           -        tcp_connect
```

```bash
$ lan-sentinel events list --type duplicate-ip --since 24h
TIME                 TYPE                   IFACE  MAC                VALUE           RELATED            CAUSE
2026-10-01 13:00:00  DUPLICATE_IP_DETECTED  eth1   00:0c:26:aa:bb:03  192.168.110.51  00:1b:1b:aa:bb:01  passive_arp
```

```bash
$ lan-sentinel hosts evidence 00:0c:26:aa:bb:03
Host 01a10f56-890f-7343-…  00:0c:26:aa:bb:03  on eth1

Addresses:
  192.168.110.51   2026-10-01 13:00:00 → open
      passive_arp      first 2026-10-01 13:00:00  last 2026-10-01 13:00:00

Identification:
  manufacturer=Weintek Labs. Inc.  oui  confidence 0.70  {"mac":"00:0c:26:aa:bb:03","registry":"IEEE"}

Observations (raw and roll-ups):
  passive_arp      192.168.110.51        1  first 2026-10-01 13:00:00  last 2026-10-01 13:00:00

Events:
  2026-10-01 13:00:00  HOST_DISCOVERED        192.168.110.51  (passive_arp)
      evidence {"interface":"eth1","ip":"192.168.110.51","mac":"00:0c:26:aa:bb:03","source":"passive_arp","ts":"2026-10-01T13:00:00Z"}
  2026-10-01 13:00:00  DUPLICATE_IP_DETECTED  192.168.110.51  (passive_arp)
      evidence {"interface":"eth1","ip":"192.168.110.51","mac":"00:0c:26:aa:bb:03","source":"passive_arp","ts":"2026-10-01T13:00:00Z"}
  2026-10-01 13:30:00  DUPLICATE_IP_RESOLVED  192.168.110.51  (passive_dhcp)
      evidence {"interface":"eth1","ip":"192.168.110.52","mac":"00:1b:1b:aa:bb:01","source":"passive_dhcp","ts":"2026-10-01T13:30:00Z"}
```

```bash
$ lan-sentinel scan plan --interface eth1 --profile modbus
Interface:  eth1    Profile: modbus    Networks: 192.168.110.0/24
Targets:    252 to sweep (excluded: 192.168.110.1), 14 known hosts
Probes:     arp; tcp/502
Rates:      arp 10 pps, tcp 5 connects/s (≤4 per interface, ≤1 per host); global cap 20 pps
Estimate:   252 ARP requests, 14 TCP connects (at most 3 packets each), at most ~294 packets
Duration:   estimated typical ~30 s, estimated no-response ~31 s
Assumes:    probes leave paced at the rates above, at most 20 packets/s in all (a TCP connect counts 3), and at least 1s apart per target; sending, connecting and answering take no time
            typical: known hosts answer at once; most swept addresses are empty, so the ARP sweep waits its 1s reply timeout once, after its last request
            no-response: nothing answers, so every phase waits out its reply timeout once (ARP 1s, tcp/502 750ms)
            ICMP, TCP and UDP counts use the hosts known now; hosts that first answer the sweep are probed too, which adds to a run
Verdict:    ALLOWED
```

```bash
$ lan-sentinel scan run --interface eth1 --profile modbus
...                                   (the plan, as above)
Scanning (estimated typical duration ~30 s) ...
eth1: done in 30 s; 15 hosts answered ARP
  arp      237 no_reply, 15 reply
  tcp/502  3 OPEN, 12 REFUSED
```

```bash
$ lan-sentinel active disable --reason "PLC fault on line 3, investigating"
Active discovery disabled (persists across restarts). Clear with: lan-sentinel active enable
```

```bash
$ lan-sentinel watch --interface eth1
19:42:12  HOST_DISCOVERED        eth1   192.168.110.200  00:0c:26:8e:1b:d6
19:43:04  IP_CHANGED             eth1   192.168.110.60 -> 192.168.110.61  00:1b:1b:12:34:56
19:43:18  SERVICE_OPENED         eth1   tcp/502  00:1b:1b:12:34:56
```

```bash
$ lan-sentinel services list --port 502
IP              MAC                IFACE  PORT     STATE  LAST CHECK
192.168.110.50  00:1b:1b:aa:bb:02  eth1   502/tcp  OPEN   1h ago
```

```bash
$ lan-sentinel interfaces list
NAME  STATE  MAC                PREFIXES          PASSIVE  ACTIVE  HOSTS
eth0  up     00:c0:08:9a:41:02  -                 on       off     1
eth1  up     00:c0:08:9a:41:03  192.168.110.0/24  on       on      3
```

```bash
$ lan-sentinel daemon status
Version:    1.0.0 (linux/arm64)   PID 412   up 3d 4h
Database:   /data/lan-sentinel/hosts.db  ok  41 MB
Active:     enabled
Last scan:  never
Interfaces:
  eth1   up      192.168.110.0/24
         hosts      12 active, 3 recent, 1 stale
         capture    running     afpacket
         neighbor   running     netlink
         interface  running     netlink
  eth2   up      10.0.0.0/24
         capture    failed      socket(AF_PACKET): operation not permitted
         neighbor   running     netlink
         interface  running     netlink
State:      DEGRADED
  - eth2 capture: socket(AF_PACKET): operation not permitted
```

```bash
$ lan-sentinel daemon status --quiet; echo $?
1
```

```bash
lan-sentinel scan run --interface eth1 --profile modbus
lan-sentinel observations list --host 3db0ce66-38c2-4f50-a1ce-a593cb872f88 --since 1h
lan-sentinel hosts evidence 192.168.110.200 --interface eth1
lan-sentinel hosts history 192.168.1.200 --offline --since 24h
lan-sentinel hosts find 192.168.1.200 --interface eth1 --at "2026-10-04 10:15"
```
