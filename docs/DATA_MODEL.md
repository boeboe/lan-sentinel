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
    NeighborState string        // kernel_neighbor only: NUD state
    Meta      map[string]string
}
```

### JSONL encoding

Replay files and the golden scenarios store one observation per line, with empty fields omitted:

```json
{"time": "2026-10-01T12:58:00Z", "source": "kernel_neighbor", "interface": "eth1", "mac": "00:1b:1b:aa:bb:01", "ip": "192.168.110.51", "neighbor_state": "REACHABLE"}
{"time": "2026-10-01T14:00:00Z", "source": "tcp_connect", "interface": "eth1", "ip": "192.168.110.50", "service": {"proto": "tcp", "port": 502, "state": "OPEN"}}
```

Fields: `time` (RFC 3339), `source`, `interface`, `mac`, `ip`, `hostname`, `name_type`, `service` (`proto`, `port`, `state`), `neighbor_state`, `meta`. Unknown fields are rejected. In a replay file `interface` may be omitted (it defaults to the replay interface); naming a different interface is an error.

An observation's `time` is the time of the evidence, not of its delivery. For `kernel_neighbor` it is when the kernel last confirmed reachability (`nda_cacheinfo.ndm_confirmed`), so an entry that lingers in the table as STALE carries its old time and adds no fresh evidence.

Replayed observations (pcap or JSONL) keep their recorded source and time; there is no separate replay source, so the correlator treats them exactly as live ones.

The capture decoders put protocol detail that is not identity evidence into `meta`:

| Source | `meta` keys |
| --- | --- |
| `passive_arp` | `arp`: `request`, `reply`, `gratuitous` (sender IP = target IP) or `probe` (sender IP 0.0.0.0, with `target`, the address probed) |
| `passive_ndp` | `ndp`: `router_solicitation`, `router_advertisement`, `neighbor_solicitation`, `neighbor_advertisement` (with `flags`: `router`, `solicited`, `override`) or `dad` (from `::`, with `target`) |
| `passive_dhcp` | `dhcp` (message type), `client_id` (option 61, hex), `parameter_request_list` (option 55), `vendor_class` (option 60) |
| `passive_mdns` | `services` (service types such as `_http._tcp`), `service_ports` (`_http._tcp=80`), `txt` |
| `passive_lldp` | `chassis_id`, `port_id`, `port_description`, `system_description`, `capabilities`, `management_ip` |
| `udp_probe` | `probe` (`ntp`, `enip`); service details: NTP `version`, `stratum`, `leap`, `reference_id`, `root_delay_ms`, `root_dispersion_ms` (and `kiss_code` for a kiss-o'-death reply); EtherNet/IP `vendor_id`, `device_type`, `product_code`, `revision`, `status`, `serial_number`, `product_name`, `state`; identity claims under `id.` (`id.product`, `id.device_type`), §5.5 |

The probes emit `arp_scan` (MAC and IP of an ARP reply to a sweep request), `icmp_scan` (IP of an echo reply), `tcp_connect` (IP and `service` with the connect result: OPEN, REFUSED, TIMEOUT, UNREACHABLE or UNKNOWN) and `udp_probe` (IP, `service` `udp/<port>` OPEN and `meta`, only when a protocol-specific probe got an answer; no answer emits nothing).

Which address an observation carries: the ARP sender address (none for a probe); the source address of an NDP message, or the target of an advertisement; `yiaddr` of a DHCP ACK or `ciaddr` of a renewing REQUEST or an INFORM (none for DISCOVER, OFFER, DECLINE, RELEASE, NAK); each A/AAAA address of an mDNS response; the address of a DNS PTR answer; the IPv4/IPv6 header source for `passive_ipv4`/`passive_ipv6`. LLDP observations carry no address.

Sources: `passive_arp`, `passive_ipv4`, `passive_ipv6`, `passive_ndp`, `passive_dhcp`, `passive_mdns`, `passive_dns`, `passive_lldp`, `kernel_neighbor`, `arp_scan`, `icmp_scan`, `ndp_probe`, `tcp_connect`, `udp_probe`.

Events that are not caused by an observation use one of these internal causes instead of a source: `presence` (presence ticker), `expiry` (binding expiry), `iface_monitor` (interface manager), `operator` (kill switch and operator scans), `integrity_check` (start-up database check).

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

## 4. Schema (`migrations/0001_init.sql`, read-side indexes in `0002_read_indexes.sql`, probe details in `0003_probes.sql`)

| Table | Columns | Purpose |
| --- | --- | --- |
| `network_contexts` | id, interface, first_seen, last_seen | One row per monitored interface name |
| `context_prefixes` | id, context_id, prefix, first_seen, last_seen, ended_at | The interface's own addresses/subnets over time (CIDR text) |
| `hosts` | host_id (UUID), context_id, mac, vendor, locally_administered, presence, preferred_name, manufacturer, device_type, first_seen, last_seen, tags | One row per (context, MAC) |
| `addresses` | id, context_id, host_id, ip, family, conflict, first_seen, last_seen, ended_at | IP bindings over time |
| `address_sources` | address_id, source, first_seen, last_seen | Which sources confirmed a binding |
| `names` | id, host_id, name, name_type, source, first_seen, last_seen, ended_at | Hostnames with provenance |
| `services` | id, host_id, proto, port, state, first_seen, last_seen, last_result_at, detail_json | Current probe result per host/port; `detail_json`: what a protocol-specific probe learnt (§5.5) |
| `identifications` | id, host_id, field, value, confidence, source, evidence_json, first_seen, last_seen | Device identification evidence |
| `observations` | id, ts, context_id, source, mac, ip, hostname, name_type, service_json, meta_json, host_id | Raw evidence, compacted; `host_id` NULL if unbound |
| `observation_rollups` | id, hour, context_id, host_id, source, mac, ip, count, first_ts, last_ts | Hourly roll-ups of observations |
| `events` | id, ts, type, severity, context_id, host_id, related_host_id, old_value, new_value, cause, observation_id, evidence_json, clock_synced | Permanent history |
| `scans` | id, context_id, kind, trigger, started_at, finished_at, targets, results_json | Operator scans, one row per interface: `kind` the probes (`arp,tcp/502`), `trigger` `operator` (periodic passes are not recorded), `targets` the larger of the sweep and known-host counts, `results_json` `{counts: {probe: {result: n}}, responders, seconds, aborted?}`. A scan left unfinished by a crash is closed at the next start (`finished_at` = `started_at`, aborted, with `SCAN_COMPLETED`) |
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
- `names(name COLLATE NOCASE)` — name queries are case-insensitive; `names(host_id, first_seen)` — every name of a host
- `events(ts)`, `events(host_id, ts)`, `events(related_host_id, ts)`, `events(type, ts)`, `events(context_id, ts)`, `events(context_id, type, ts)`
- `events(old_value)`, `events(new_value)`, `events(json_extract(evidence_json, '$.ip'))` — IP timelines
- `scans(started_at)` — the last scan (`daemon status`)
- `observations(ts)`, `observations(host_id, ts)`, `observation_rollups(hour)`, `observation_rollups(host_id, hour)`. Observations have no MAC or IP index (they are the high-volume table); `observations list --mac/--ip` walks the time index back from the latest until its limit is filled, so `--host` or `--since` keeps it cheap.

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

Applied by the correlator to each observation, in order, within the observation's context. Every rule is evaluated at the observation's `time`; timer-driven transitions (presence §6, expiry §5.3) are stamped with the moment their threshold was crossed. Results therefore do not depend on when evaluation runs, and a replay produces the same database every time.

Before the rules: an observation for an interface that is not configured is dropped. A MAC that is not a usable host MAC (multicast, broadcast, all-zero) and an IP that is not a unicast host address (unspecified, multicast, broadcast, loopback) are treated as absent.

### 5.1 Binding the observation to a host

1. **Observation has a MAC.** The host is the row with `(context_id, mac)`. If none exists, create it and emit `HOST_DISCOVERED`; if the same MAC already exists as a host on another context, also emit `MAC_MOVED` on the new host with `related_host_id` set to the other host. Update `hosts.last_seen` and presence.
2. **Observation has no MAC but has an IP** (TCP/UDP/ICMP probe results, DNS PTR answers). If exactly one open binding for that IP exists in the context, attach to that host. If there are none or several (conflict), the observation is stored with `host_id = NULL`, changes no state, and increments `lan_sentinel_observations_unbound_total{source}`. A MAC-less observation never creates a host. It updates presence and confirms the binding only when it is evidence that the host answered just now: a `tcp_connect` OPEN or REFUSED, an `icmp_scan` reply, a `udp_probe` reply. A TCP TIMEOUT or UNREACHABLE is no answer: it records the service result (§5.5) but neither updates presence nor confirms the binding, so it can neither keep a host ACTIVE nor bring a MISSING one back, and it never counts against the host either. A `passive_dns` observation is a resolver's statement about another host, not evidence from the host itself: it only adds its name (§5.4) and likewise neither updates presence nor confirms the binding.
3. **Observation has neither** — dropped and counted the same way.

### 5.2 Which IPs are attributed

An IP from an observation is bound to the host only if it is on-link for the context:

- IPv4: inside one of the context's open `context_prefixes`, or the source is `passive_arp`, `arp_scan`, `passive_dhcp` or `kernel_neighbor` (L2 evidence; out-of-subnet ARP from misconfigured devices is still recorded).
- IPv6: link-local, or inside an open prefix, or the source is `passive_ndp`, `ndp_probe` or `kernel_neighbor`.
- `passive_ipv4` / `passive_ipv6` source addresses outside these rules are ignored for binding, because the frame's source MAC is the router's.

**Proxy ARP.** Only ARP answers count: `passive_arp` replies and `arp_scan` results. A MAC is flagged `proxy_arp` when its answers within `identity.address_expiry` (default 24 h) claim two or more distinct IPs that are held by other live hosts, or more than `identity.proxy_arp_threshold` (default 16) distinct IPs; older claims are forgotten, so a device that changes address now and then is not a proxy. A late answer (§5.3) is counted but never sets the flag. A single contested answer stays an ordinary duplicate-IP conflict (§5.3). Requests and gratuitous ARP announce the sender's own address: they never count towards proxy ARP, but they do raise duplicate-IP conflicts. When the flag is set:

- an `identifications` row (`proxy_arp` = `true`, confidence 0.8, the observation's source, evidence with the counts) is written, and `VENDOR_IDENTIFIED` with new value `proxy_arp=true` records it in history;
- the host's bindings that only its ARP answers supported are closed at the observation's time (`IP_REMOVED`, followed by `DUPLICATE_IP_RESOLVED` where a conflict ends);
- from then on its ARP answers open, refresh or take over nothing, except to refresh addresses it holds on other evidence (its own ARP requests, IP traffic, DHCP); they are recorded as observations only.

The flag is kept across restarts (from `identifications`); the claim counts start again after a restart.

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
| **Expiry:** an open binding not confirmed for `identity.address_expiry` (default 24 h) while its host has been observed since | Close with `ended_at = last_seen + address_expiry`, the moment expiry applied | `IP_REMOVED` (cause `expiry`) |

Bindings are **not** closed when a host becomes MISSING: the last known state remains in effect (and shows as unconfirmed). IPv6 addresses never trigger replacement; they are opened with `IP_ADDED` and closed by expiry or takeover, because hosts hold several IPv6 addresses at once. The network and broadcast addresses of the context's IPv4 prefixes are never attributed.

**Late observations.** An observation older than the last binding change of its host or of its IP (open or close) only refreshes an existing open binding; it never opens, closes, replaces or takes over a binding. This keeps evidence that arrives out of order (e.g. an old neighbour-table entry read after an IP change) from reopening history.

### 5.4 Names

Names are last-known attributes with provenance and freshness: each binding keeps `first_seen`, `last_seen` (the last confirmation) and the `source` that opened it. A new name of a given type on a host opens a binding (`HOSTNAME_ADDED`, also when the same observation discovered the host). If the host already has an open name of the same type and a different name of that type arrives, the old one is closed at `obs.ts` and the event is `HOSTNAME_CHANGED` instead, so a host has at most one open name per type. That is the only way a name closes. Time alone never closes a name: on a switched port DHCP names are often seen only at boot and mDNS names only when someone queries, so not seeing a naming protocol again is not evidence that the name changed. This holds while the host stays visible and after it becomes MISSING. A name not confirmed for `identity.name_expiry` (default 7 d) is shown as *stale* when it is read (API, CLI), the way a binding past its `last_seen` is shown as unconfirmed; nothing is written. As with addresses, an observation older than the open name's last confirmation or the type's last change only refreshes and never changes a name. `preferred_name` is recomputed whenever a name opens or is replaced: the open name of the first type listed in `identity.hostname_preference`, stale or not; types missing from the list are never preferred.

### 5.5 Services

A probe result attached to a host upserts `services`. A transition into OPEN emits `SERVICE_OPENED`; out of OPEN emits `SERVICE_CLOSED`. Repeated identical results emit nothing.

A `udp_probe` result also records what the probe learnt, in the generic service and identification model (no protocol-specific host state): the `meta` keys without the `id.` prefix (including `probe`) replace `services.detail_json` of that service; each `id.<field>` key is an identification (`field`, value, source = the probe name, confidence 0.9: the device's own statement) with the details as evidence. A field a probe reports for the first time, or with a new value, emits `VENDOR_IDENTIFIED` (old `field=old value`, new `field=value`); the same value again only refreshes `last_seen`. A `device_type` claim also sets `hosts.device_type`. A probe that gets no answer emits no observation, so it changes nothing: it is never evidence that a host or service is gone.

## 6. Presence

| State | Default threshold (time since `hosts.last_seen`) |
| --- | --- |
| ACTIVE | < 5 min |
| RECENT | < 30 min |
| STALE | < 24 h |
| MISSING | ≥ 24 h |

Thresholds are configurable (`presence:`). Transitions into MISSING emit `HOST_DISAPPEARED` (cause `presence`) stamped `last_seen + presence.stale`, with old value STALE; an observation newer than that brings a MISSING host back and emits `HOST_REAPPEARED`. Transitions between ACTIVE, RECENT and STALE update `hosts.presence` but do not produce events. "Live" in §5.3 means ACTIVE or RECENT.

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
| `HOSTNAME_REMOVED` | `name-removed` | notice | Reserved: a name closed without a replacement. No v1 rule does this (§5.4) |
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
| `DATABASE_RECREATED` | `db-recreated` | warning | The database failed the start-up integrity check; it was quarantined and this new one created (FR-ST-4) |

### Values

| Type | `old_value` | `new_value` | Other columns |
| --- | --- | --- | --- |
| `HOST_DISCOVERED` | — | MAC | IP (if any) in evidence |
| `HOST_DISAPPEARED` | `STALE` | `MISSING` | evidence: last observation + `reason` |
| `HOST_REAPPEARED` | `MISSING` | presence after | |
| `IP_ADDED` / `IP_REMOVED` | — / IP | IP / — | `IP_REMOVED` on takeover: `related_host_id` = the new holder |
| `IP_CHANGED` | old IP | new IP | |
| `MAC_MOVED` | other interface | this interface | `related_host_id` = host on the other interface |
| `HOSTNAME_*` | old name (`type:name`) | new name (`type:name`) | |
| `SERVICE_OPENED` | previous state (empty for a first result) | `proto/port` | IP and state in evidence |
| `SERVICE_CLOSED` | `proto/port` | new state | IP in evidence |
| `VENDOR_IDENTIFIED` | old value | new value (`field=value`) | Not emitted for the OUI manufacturer set at discovery (recorded in `identifications`, source `oui`, confidence 0.7). Emitted with `proxy_arp=true` when a host is flagged as a proxy-ARP device (§5.2), and for each new or changed identity claim of a protocol-specific probe, e.g. `product=1756-L71/B LOGIX5571`, `device_type=Programmable Logic Controller` (§5.5) |
| `DUPLICATE_IP_DETECTED` | — | IP | `host_id` = new claimer, `related_host_id` = existing holder |
| `DUPLICATE_IP_RESOLVED` | — | IP | `host_id` = remaining holder, `related_host_id` = the host that left |
| `SCAN_STARTED`, `SCAN_COMPLETED` | — | summary text (probes, targets; counts, duration, or why it was aborted) | context of the scanned interface, no host; evidence `{actor, interface}` |
| `ACTIVE_DISABLED`, `ACTIVE_ENABLED` | — | `active discovery disabled by <actor>: <reason>` | no host or context; evidence `{actor, reason}`; actor `env` when `LAN_SENTINEL_ACTIVE_DISABLED=1` stopped it at start-up |
| `INTERFACE_*` | — | `up` / `down` | no host |
| `SUBNET_CHANGED` | prefix closed | prefix opened | no host |
| `DATABASE_RECREATED` | — | quarantined file (`<path>.corrupt-<UTC time>`) | no host or context; evidence `reason` = the integrity-check failure; always the new database's first event |

### Provenance

Every event is self-contained, so pruning observations never weakens history:

| Column | Content |
| --- | --- |
| `old_value`, `new_value` | Text form of the changed attribute (IP, name, state, prefix) |
| `cause` | The observation's `Source`, or an internal cause (`presence`, `expiry`, `iface_monitor`, `scheduler`, `operator`) |
| `observation_id` | ID of the causing observation if any. May point at a pruned row; informational only. |
| `evidence_json` | Snapshot copied at write time: `{ts, source, interface, mac, ip, hostname, name_type, service: {proto, port, state}, neighbor_state}` of the causing observation. For timer-driven events: the snapshot of the last supporting observation plus `reason` (e.g. `"no observation for 24h"`). For operator events: `{actor, reason}`. |
| `clock_synced` | false if written before NTP sync |

## 8. Runtime state

`runtime_state` holds operator state that must survive restarts. In v1 only `active_disabled` (`{"disabled": true, "reason": "...", "by": "<unix user>", "at": ...}`), written by the correlator when the API sets the kill switch and deleted when it is cleared. A kill switch set through the API or CLI stays set across daemon restarts until explicitly cleared. `LAN_SENTINEL_ACTIVE_DISABLED=1` forces active discovery off regardless of this row and is not written to it (the daemon records `ACTIVE_DISABLED` with actor `env` at start-up instead), and the API refuses to enable while it is set.

## 9. Retention and compaction

Configurable per site under `storage.retention`. Defaults: raw observations 7 days; hourly roll-ups (one row per host, source, IP, MAC and hour, including unbound observations with `host_id` NULL) 90 days; events 2 years. Raw observations past their retention are folded into roll-ups (adding to an existing row for the same hour) and deleted; roll-ups and events past theirs are deleted. `max_db_size` (default 200 MB) then applies to the data size (pages minus free pages): while above it, the oldest raw observations are rolled up first, then the oldest roll-ups and finally the oldest events are deleted, regardless of age. Freed pages are returned to the file system (`auto_vacuum=INCREMENTAL`). Compaction runs at start-up and hourly in batches of 2,000 rows, each its own committed op, so it never blocks the writer; replay mode does not compact. Current-state and binding tables (`network_contexts`, `context_prefixes`, `hosts`, `addresses`, `address_sources`, `names`, `services`, `identifications`) are not pruned by age. Because every event carries its evidence (§7), answers and provenance are unchanged by compaction (§10).

## 10. Golden reconstruction scenario

The central correlator fixture, committed in phase 0 under `test/golden/reconstruction/` (observation stream in, expected bindings, events and query answers out) and run on every change. Interface `eth1`, prefix `192.168.110.0/24`, `T0 = 2026-10-01T10:00:00Z`, default thresholds.

| # | Time | Observation | Expected |
| --- | --- | --- | --- |
| 1 | T0 | `passive_arp` MAC A, IP X = .50 | Host A created; binding A–X open; `HOST_DISCOVERED` A |
| 2 | T0+1h | `passive_dhcp` MAC A, IP Y = .51 | A–X closed at T0+1h; A–Y open; `IP_CHANGED` X → Y |
| 3 | T0+2h | `passive_arp` MAC B, IP X | Host B; B–X open; `HOST_DISCOVERED` B |
| 4 | T0+2h58m | `kernel_neighbor` MAC A, IP Y | A–Y `last_seen` updated; no event |
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
