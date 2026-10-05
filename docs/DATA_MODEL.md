# LAN Sentinel — Data Model

Current state and history live in separate tables: binding tables carry explicit intervals, `events` is append-only and kept long, and `observations` is compacted.

## 1. Concepts

| Concept | Meaning |
| --- | --- |
| Network context | Where something was seen. In v1 exactly one per monitored interface, stable for the life of that interface name (VLAN out of scope). Every host belongs to one context. Subnet changes do not create a new context; they are recorded in `context_prefixes`. |
| Host | A device seen on one context, identified by exactly one MAC address. Internally keyed by a UUID `host_id`. Within a context, MAC ↔ host is one-to-one and permanent. |
| Address | An IP bound to a host over an interval. |
| Name | A hostname with its type/provenance bound to a host over an interval. |
| Service | Current result of probing a protocol/port on a host. History is in events. |
| Identification | A derived fact (manufacturer, device type, `proxy_arp`) with confidence and evidence. |
| Observation | Raw evidence: "source S saw MAC X / IP Y / name Z at time T on interface I". |
| Event | A state transition derived from observations or timers, with a self-contained evidence snapshot. |

### Identity decision

The MAC address is the only evidence that two observations come from the same host. Consequences:

- One host has exactly one MAC per context, for its whole life. A device with two NICs is two hosts. A NIC swap is a new host; the old one ages to MISSING.
- The same MAC seen on two interfaces is two hosts (one per context), linked by a `MAC_MOVED` event.
- The engine never merges or splits hosts, and there are no manual merge/split operations. IP and hostname never decide identity.
- A host cannot exist without a MAC. Observations without a MAC only attach to an existing host (§5 rule 2).

`host_id` is still a UUID, not the MAC, so that references stay stable, contexts stay separate, and the key does not leak into API paths and metrics.

## 2. Observation

Every collector and probe emits this type and nothing else:

```go
type Observation struct {
    Time      time.Time
    Source    Source            // see below
    Context   ContextKey        // interface name
    MAC       net.HardwareAddr  // may be nil (e.g. TCP probe)
    IP        netip.Addr        // may be invalid (e.g. LLDP)
    Hostname  string
    NameType  NameType          // mdns, dhcp, dns_ptr, netbios, lldp
    Service   *ServiceResult    // proto, port, OPEN/REFUSED/TIMEOUT/UNREACHABLE/UNKNOWN
    NUDState  string            // netlink only
    Meta      map[string]string
}
```

Sources: `passive_arp`, `passive_ipv4`, `passive_ipv6`, `passive_ndp`, `passive_dhcp`, `passive_mdns`, `passive_dns`, `passive_lldp`, `netlink_neighbor`, `arp_scan`, `icmp_scan`, `ndp_probe`, `tcp_connect`, `udp_probe`.

Events that are not caused by an observation use one of these internal causes instead of a source: `presence` (presence ticker), `expiry` (binding expiry), `netlink_link` (interface manager), `scheduler` (scan runs), `operator` (API/CLI action).

## 3. Time and interval semantics

All timestamps are UTC Unix milliseconds (`INTEGER`). Every binding table (`addresses`, `names`, `context_prefixes`) uses the same three columns:

| Column | Nullable | Meaning |
| --- | --- | --- |
| `first_seen` | no | Time of the first observation that opened the binding. Interval start, inclusive. |
| `last_seen` | no | Time of the most recent observation supporting the binding. Updated on every confirming observation. Never NULL. |
| `ended_at` | yes | `NULL` while the binding is open. Set exactly once when it is closed, to the time of the cause (§5.3). Interval end, exclusive. |

A binding is **in effect at time T** when `first_seen <= T AND (ended_at IS NULL OR ended_at > T)`. Intervals are half-open, so a takeover that closes one binding and opens another at the same millisecond never overlaps.

A binding in effect at T with `T > last_seen` was **unconfirmed** at T: it was the last known state, but no evidence was received between `last_seen` and T. Queries return `last_seen` so the CLI can show this (§7).

`hosts` has `first_seen` and `last_seen` (no `ended_at`: hosts are never closed, only their presence changes).

## 4. Schema (`migrations/0001_init.sql`)

| Table | Columns | Purpose |
| --- | --- | --- |
| `network_contexts` | id, interface, first_seen, last_seen | One row per monitored interface name |
| `context_prefixes` | id, context_id, prefix, first_seen, last_seen, ended_at | The interface's own addresses/subnets over time (CIDR text) |
| `hosts` | host_id (UUID), context_id, mac, vendor, locally_administered, presence, preferred_name, manufacturer, device_type, first_seen, last_seen, tags | One row per (context, MAC) |
| `addresses` | id, context_id, host_id, ip, family, conflict, first_seen, last_seen, ended_at | IP bindings over time |
| `address_sources` | address_id, source, first_seen, last_seen | Which sources confirmed a binding |
| `names` | id, host_id, name, name_type, source, first_seen, last_seen, ended_at | Hostnames with provenance |
| `services` | id, host_id, proto, port, state, first_seen, last_seen, last_result_at | Current probe result per host/port |
| `identifications` | id, host_id, field, value, confidence, source, evidence_json, first_seen, last_seen | Device identification evidence |
| `observations` | id, ts, context_id, source, mac, ip, hostname, name_type, service_json, meta_json, host_id | Raw evidence, compacted; `host_id` NULL if unbound |
| `observation_rollups` | id, hour, context_id, host_id, source, mac, ip, count, first_ts, last_ts | Hourly roll-ups of observations |
| `events` | id, ts, type, severity, context_id, host_id, related_host_id, old_value, new_value, cause, observation_id, evidence_json, clock_synced | Permanent history |
| `scans` | id, context_id, kind, trigger, started_at, finished_at, targets, results_json | Scan runs |
| `runtime_state` | key, value, updated_at | Persisted operator state (kill switch, §8) |
| `schema_migrations` | version, applied_at | Migration tracking |

MACs are stored as lowercase colon-separated text; IPs as canonical text from `netip.Addr.String()`; prefixes from `netip.Prefix.String()`.

### Context scoping

Every host row carries `context_id`. `names`, `services`, `identifications` and `address_sources` inherit their context through `host_id` and do not repeat it. `addresses` repeats `context_id` (always equal to `hosts.context_id` of its host; enforced by the writer and a test) so the point-in-time index works without a join.

### Constraints

| Constraint | Rule |
| --- | --- |
| `network_contexts` | `UNIQUE(interface)` |
| `hosts` | `UNIQUE(context_id, mac)` — the identity rule |
| `addresses` (open) | `UNIQUE(host_id, ip) WHERE ended_at IS NULL` — one open binding per host and IP |
| `addresses` (closed) | `CHECK(ended_at IS NULL OR ended_at >= first_seen)`, `CHECK(last_seen >= first_seen)` |
| `addresses` (conflict) | Several open bindings for the same `(context_id, ip)` with different hosts are allowed only while a duplicate-IP conflict is active; each has `conflict = 1`. Otherwise at most one open binding per `(context_id, ip)` (enforced by the correlator, verified by tests). |
| `names` (open) | `UNIQUE(host_id, name_type, name) WHERE ended_at IS NULL` |
| `context_prefixes` (open) | `UNIQUE(context_id, prefix) WHERE ended_at IS NULL` |
| `services` | `UNIQUE(host_id, proto, port)` |
| `address_sources` | `PRIMARY KEY(address_id, source)` |

`observations.host_id` and `events.observation_id` are soft references without foreign keys, because observations are pruned.

### Indexes

- `addresses(context_id, ip, first_seen)` — point-in-time lookup
- `addresses(host_id, first_seen)`
- `hosts(mac)` — cross-context MAC lookup (`MAC_MOVED`, `hosts find <mac>`)
- `names(name)`
- `events(ts)`, `events(host_id, ts)`, `events(type, ts)`, `events(context_id, ts)`
- `observations(ts)`, `observations(host_id, ts)`, `observation_rollups(hour)`, `observation_rollups(host_id, hour)`

### Point-in-time query

"Who had 192.168.1.200 on eth1 at T?":

```sql
SELECT h.host_id, h.mac, h.preferred_name, h.manufacturer,
       a.first_seen, a.last_seen, a.ended_at, a.conflict
FROM addresses a
JOIN network_contexts c ON c.id = a.context_id
JOIN hosts h ON h.host_id = a.host_id
WHERE c.interface = :iface
  AND a.ip = :ip
  AND a.first_seen <= :t
  AND (a.ended_at IS NULL OR a.ended_at > :t)
ORDER BY a.last_seen DESC;
```

| Rows | Meaning |
| --- | --- |
| 0 | No known holder at T. The CLI also shows the previous binding (latest with `ended_at <= T`) and the next one (earliest with `first_seen > T`). |
| 1 | The holder. Flagged *unconfirmed* if `T > last_seen`. |
| ≥ 2 | A duplicate-IP conflict was active at T. All holders are shown, marked CONFLICT. |

The events for that host and IP around T then explain what changed, what replaced it, and the evidence for each step.

## 5. Correlation rules

Applied by the correlator to each observation, in order, within the observation's context.

### 5.1 Binding the observation to a host

1. **Observation has a MAC.** The host is the row with `(context_id, mac)`. If none exists, create it and emit `HOST_DISCOVERED`; if the same MAC already exists as a host on another context, also emit `MAC_MOVED` on the new host with `related_host_id` set to the other host. Update `hosts.last_seen` and presence.
2. **Observation has no MAC but has an IP** (TCP/UDP/ICMP probe results). If exactly one open binding for that IP exists in the context, attach to that host. If there are none or several (conflict), the observation is stored with `host_id = NULL`, changes no state, and increments `lan_sentinel_observations_unbound_total{source}`. A MAC-less observation never creates a host.
3. **Observation has neither** — dropped and counted the same way.

### 5.2 Which IPs are attributed

An IP from an observation is bound to the host only if it is on-link for the context:

- IPv4: inside one of the context's open `context_prefixes`, or the source is `passive_arp`, `arp_scan`, `passive_dhcp` or `netlink_neighbor` (L2 evidence; out-of-subnet ARP from misconfigured devices is still recorded).
- IPv6: link-local, or inside an open prefix, or the source is `passive_ndp`, `ndp_probe` or `netlink_neighbor`.
- `passive_ipv4` / `passive_ipv6` source addresses outside these rules are ignored for binding, because the frame's source MAC is the router's.

A host whose MAC answers ARP for IPs that are already bound to other live hosts, or for more than `identity.proxy_arp_threshold` (default 16) addresses, is flagged `proxy_arp` in `identifications`. Its further ARP-only claims do not open or take over bindings; they are recorded as observations only.

### 5.3 Address binding lifecycle

Let *H* be the bound host and *X* the attributed IP.

| Case | Action | Event |
| --- | --- | --- |
| *H* already has an open binding to *X* | Update `last_seen`, upsert `address_sources` | none |
| No open binding to *X* in the context | Open binding *(H, X)* | `IP_ADDED` (or none if this observation also produced `HOST_DISCOVERED`) — unless the replacement rule applies |
| **Replacement** (IPv4 only): *H* has an open IPv4 binding *O* whose `last_seen` is older than `identity.address_overlap` (default 5 m) | Close *O* with `ended_at = obs.ts`; open *(H, X)*. If several such bindings exist, close them all. | `IP_CHANGED` O → X for the most recently confirmed *O* (replaces the `IP_ADDED`); `IP_REMOVED` for any others |
| **Takeover:** *X* is held open by another host *G* that is not live (presence STALE or MISSING) | Close *(G, X)* with `ended_at = obs.ts`; open *(H, X)* | `IP_REMOVED` on *G*, `IP_ADDED`/`IP_CHANGED` on *H* |
| **Conflict:** *X* is held open by another host *G* that is live (ACTIVE or RECENT) | Open *(H, X)*; set `conflict = 1` on both bindings | `DUPLICATE_IP_DETECTED` with both host ids |
| **Conflict ends:** after any close, exactly one open binding for *X* remains | Clear `conflict` on it | `DUPLICATE_IP_RESOLVED` |
| **Expiry:** an open binding not confirmed for `identity.address_expiry` (default 24 h) while its host has been observed since | Close with `ended_at = now` | `IP_REMOVED` (cause `expiry`) |

Bindings are **not** closed when a host becomes MISSING: the last known state remains in effect (and shows as unconfirmed). IPv6 addresses never trigger replacement; they are opened with `IP_ADDED` and closed by expiry or takeover, because hosts hold several IPv6 addresses at once.

### 5.4 Names

A new name of a given type on a host opens a binding (`HOSTNAME_ADDED`). If the host already has an open name of the same type, that one is closed at `obs.ts` and the event is `HOSTNAME_CHANGED` instead. Open names not confirmed for `identity.name_expiry` (default 7 d) are closed with `HOSTNAME_REMOVED`. `preferred_name` is recomputed from open names using `identity.hostname_preference`.

### 5.5 Services

A probe result attached to a host upserts `services`. A transition into OPEN emits `SERVICE_OPENED`; out of OPEN emits `SERVICE_CLOSED`. Repeated identical results emit nothing.

## 6. Presence

| State | Default threshold (time since `hosts.last_seen`) |
| --- | --- |
| ACTIVE | < 5 min |
| RECENT | < 30 min |
| STALE | < 24 h |
| MISSING | ≥ 24 h |

Thresholds are configurable (`presence:`). Transitions into MISSING emit `HOST_DISAPPEARED` (cause `presence`); any observation of a MISSING host emits `HOST_REAPPEARED`. Transitions between ACTIVE, RECENT and STALE update `hosts.presence` but do not produce events. "Live" in §5.3 means ACTIVE or RECENT.

## 7. Event catalogue

| Type | CLI name | Severity | Meaning |
| --- | --- | --- | --- |
| `HOST_DISCOVERED` | `discovered` | notice | First observation of a new (context, MAC) |
| `HOST_DISAPPEARED` | `disappeared` | notice | Presence became MISSING |
| `HOST_REAPPEARED` | `reappeared` | notice | A MISSING host was observed again |
| `IP_ADDED` | `ip-added` | notice | Host gained an address binding |
| `IP_REMOVED` | `ip-removed` | notice | An address binding was closed without replacement on that host (expiry or takeover) |
| `IP_CHANGED` | `ip-changed` | notice | Host's IPv4 address replaced by another |
| `MAC_MOVED` | `mac-moved` | warning | A MAC known on another interface appeared on this one (new host, `related_host_id` = the other) |
| `HOSTNAME_ADDED` | `name-added` | notice | New name with provenance |
| `HOSTNAME_CHANGED` | `name-changed` | notice | Name of a given type changed |
| `HOSTNAME_REMOVED` | `name-removed` | notice | Name expired |
| `SERVICE_OPENED` | `service-opened` | notice | Probe result became OPEN |
| `SERVICE_CLOSED` | `service-closed` | notice | Probe result left OPEN |
| `VENDOR_IDENTIFIED` | `vendor-identified` | info | Manufacturer or device type determined or changed |
| `DUPLICATE_IP_DETECTED` | `duplicate-ip` | warning | Two live MACs claim the same IP |
| `DUPLICATE_IP_RESOLVED` | `duplicate-ip-resolved` | notice | Only one binding for a previously conflicting IP remains |
| `SCAN_STARTED` | `scan-started` | info | Scan run began |
| `SCAN_COMPLETED` | `scan-completed` | info | Scan run ended, with counts |
| `ACTIVE_DISABLED` | `active-disabled` | warning | Active discovery stopped by kill switch (API, CLI or env) |
| `ACTIVE_ENABLED` | `active-enabled` | notice | Kill switch cleared |
| `INTERFACE_UP` | `interface-up` | notice | Monitored interface came up |
| `INTERFACE_DOWN` | `interface-down` | warning | Monitored interface went down |
| `SUBNET_CHANGED` | `subnet-changed` | notice | A `context_prefixes` binding opened or closed |

### Provenance

Every event is self-contained, so pruning observations never weakens history:

| Column | Content |
| --- | --- |
| `old_value`, `new_value` | Text form of the changed attribute (IP, name, state, prefix) |
| `cause` | The observation's `Source`, or an internal cause (`presence`, `expiry`, `netlink_link`, `scheduler`, `operator`) |
| `observation_id` | ID of the causing observation if any. May point at a pruned row; informational only. |
| `evidence_json` | Snapshot copied at write time: `{ts, source, interface, mac, ip, hostname, name_type, service: {proto, port, state}, nud_state}` of the causing observation. For timer-driven events: the snapshot of the last supporting observation plus `reason` (e.g. `"no observation for 24h"`). For operator events: `{actor, reason}`. |
| `clock_synced` | false if written before NTP sync |

## 8. Runtime state

`runtime_state` holds operator state that must survive restarts. In v1 only `active_disabled` (`{"disabled": true, "reason": "...", "by": "cli", "at": ...}`). A kill switch set through the API or CLI stays set across daemon restarts until explicitly cleared. `LAN_SENTINEL_ACTIVE_DISABLED=1` forces active discovery off regardless of this row, and the API refuses to enable while it is set.

## 9. Retention and compaction

Configurable per site under `storage.retention`. Defaults: raw observations 7 days; hourly roll-ups (one row per host, source, IP, MAC and hour, including unbound observations with `host_id` NULL) 90 days; events 2 years. `max_db_size` (default 200 MB) prunes raw observations first, then roll-ups, then the oldest events. Compaction runs hourly in small batches so it never blocks the writer. Current-state and binding tables (`network_contexts`, `context_prefixes`, `hosts`, `addresses`, `address_sources`, `names`, `services`, `identifications`) are not pruned by age.

## 10. Golden reconstruction scenario

The central correlator fixture, committed in phase 0 under `test/golden/reconstruction/` (observation stream in, expected bindings, events and query answers out) and run on every change. Interface `eth1`, prefix `192.168.110.0/24`, `T0 = 2026-10-01T10:00:00Z`, default thresholds.

| # | Time | Observation | Expected |
| --- | --- | --- | --- |
| 1 | T0 | `passive_arp` MAC A, IP X = .50 | Host A created; binding A–X open; `HOST_DISCOVERED` A |
| 2 | T0+1h | `passive_dhcp` MAC A, IP Y = .51 | A–X closed at T0+1h; A–Y open; `IP_CHANGED` X → Y |
| 3 | T0+2h | `passive_arp` MAC B, IP X | Host B; B–X open; `HOST_DISCOVERED` B |
| 4 | T0+2h58m | `netlink_neighbor` MAC A, IP Y | A–Y `last_seen` updated; no event |
| 5 | T0+3h | `passive_arp` (gratuitous) MAC C, IP Y | Host C; C–Y open; A–Y and C–Y `conflict = 1`; `HOST_DISCOVERED` C, `DUPLICATE_IP_DETECTED` Y (A, C) |
| 6 | T0+3h30m | `passive_dhcp` MAC A, IP Z = .52 | A–Y closed at T0+3h30m; A–Z open; `IP_CHANGED` Y → Z; C–Y `conflict = 0`; `DUPLICATE_IP_RESOLVED` Y |
| 7 | T0+4h | `tcp_connect` IP X, tcp/502 OPEN (no MAC) | Attached to B; `SERVICE_OPENED` |
| 8 | T0+4h | `tcp_connect` IP .99, tcp/502 REFUSED (no MAC) | Unbound; no state change; unbound counter +1 |

| Query | Expected answer |
| --- | --- |
| `find X --at T0+30m` | A, binding [T0, T0+1h), unconfirmed (last_seen T0) |
| `find X --at T0+90m` | No holder; previous A until T0+1h; next B from T0+2h; exit 1 |
| `find X --at T0+150m` | B, from T0+2h, open |
| `find Y --at T0+3h10m` | A and C, CONFLICT |
| `find Y --at T0+3h40m` | C only |
| `history X` | `HOST_DISCOVERED` A (X), `IP_CHANGED` A X → Y, `HOST_DISCOVERED` B (X), `SERVICE_OPENED` B tcp/502 |
| After 7-day compaction | All answers and event evidence above unchanged |
