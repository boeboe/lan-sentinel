# LAN Sentinel — Requirements

Status: agreed 5 October 2026, revised the same day after spec review. Requirement ids are stable; reference them in code reviews and tests.

## 1. Goal

LAN Sentinel SHALL maintain a persistent, interface-aware, historical inventory of hosts observed on local OT networks. It SHALL correlate MAC addresses, IP addresses, hostnames, services and device-identification evidence from multiple passive and active discovery mechanisms. It SHALL preserve historical state transitions and their provenance so that network changes can be reconstructed after the fact. Discovery methods SHALL be individually configurable and designed to minimise disruption to OT equipment.

### Primary acceptance criterion

For any interface and IP address, the CLI SHALL answer: what was using that address at a given past time, with which MAC, what we believed the device was, when that mapping changed, what replaced it, and which observations led to each conclusion.

```bash
lan-sentinel hosts find 192.168.1.200 --interface eth1 --at "2026-10-04 10:15"
lan-sentinel hosts history 192.168.1.200 --since 7d
```

## 2. Functional requirements

### 2.1 Identity and correlation

| Id | Requirement |
| --- | --- |
| FR-ID-1 | Each host SHALL have an internal persistent UUID (`host_id`) as its record key. Within a network context a host SHALL correspond to exactly one MAC address, and the MAC SHALL be the only evidence that decides host identity. IP, hostname and vendor are attributes, never identity. |
| FR-ID-2 | All data SHALL be scoped to a network context, which in v1 is the interface, stable across subnet changes. The interface's own subnets SHALL be kept as separate history. The same IP or MAC on different interfaces SHALL be treated as different bindings and different hosts. |
| FR-ID-3 | A host MAY have multiple IPs and names over time. Each binding SHALL carry `first_seen`, `last_seen` and `ended_at` with the interval semantics in `DATA_MODEL.md` §3. A device with several NICs is several hosts. |
| FR-ID-4 | Every discovery mechanism SHALL emit normalised observations; a single correlation engine SHALL turn observations into host state and events. |
| FR-ID-5 | Correlation SHALL follow the rules in `DATA_MODEL.md` §5, including raising `DUPLICATE_IP_DETECTED` instead of merging two live MACs on one IP. |
| FR-ID-6 | Hosts SHALL never be merged or split, automatically or manually. There are no merge/split operations in v1. |
| FR-ID-7 | An observation without a MAC SHALL only attach to a host that holds its IP unambiguously; otherwise it is stored unbound and counted. It SHALL never create a host. |

### 2.2 Passive discovery

| Id | Requirement |
| --- | --- |
| FR-PA-1 | The daemon SHALL capture on configured interfaces using `AF_PACKET` with a kernel BPF filter limited to discovery protocols. |
| FR-PA-2 | It SHALL decode ARP (including gratuitous ARP), IPv4 source addresses, IPv6 source addresses and NDP, DHCP, mDNS, DNS responses and LLDP. Each protocol SHALL be individually enabled/disabled; IPv6 SHALL be independently configurable. |
| FR-PA-3 | DHCP decoding SHALL extract hostname (option 12) and client identifier (option 61) and retain the parameter request list (option 55) for later fingerprinting. |
| FR-PA-4 | mDNS decoding SHALL extract A, AAAA, PTR, SRV and TXT records, including service types (e.g. `_http._tcp`, `_modbus._tcp`). |
| FR-PA-5 | Promiscuous mode SHALL be configurable per interface and default to off; it SHALL be set with `PACKET_ADD_MEMBERSHIP` (no `CAP_NET_ADMIN`). |
| FR-PA-6 | Passive capture SHALL never transmit frames. |

### 2.3 Kernel neighbour table

| Id | Requirement |
| --- | --- |
| FR-NL-1 | The daemon SHALL dump the neighbour table at startup and then subscribe to rtnetlink `RTM_NEWNEIGH` and `RTM_DELNEIGH`. It SHALL take a fresh dump after notification loss (`ENOBUFS`) and every `neighbor.resync_interval` (default 10 min). It SHALL NOT poll or shell out to `ip neigh`. |
| FR-NL-2 | Neighbour observations SHALL use source `kernel_neighbor` and record the NUD state (REACHABLE, STALE, DELAY, PROBE, FAILED) as `neighbor_state`. `STALE` SHALL NOT be interpreted as offline. |
| FR-NL-3 | The interface manager SHALL track link up/down and address/subnet changes via netlink and emit `INTERFACE_UP`, `INTERFACE_DOWN` and `SUBNET_CHANGED`. |

### 2.4 Active discovery

| Id | Requirement |
| --- | --- |
| FR-AC-1 | Active discovery SHALL be disabled by default and enabled per interface. |
| FR-AC-2 | Active probes SHALL only target explicitly configured networks. Discovered subnets SHALL never be scanned automatically. |
| FR-AC-3 | ARP sweeping SHALL be implemented natively in Go and be the primary IPv4 discovery probe. |
| FR-AC-4 | ICMP echo SHALL be supported, using unprivileged ping sockets where `net.ipv4.ping_group_range` allows, else raw sockets under `CAP_NET_RAW`. Disabled by default. |
| FR-AC-5 | TCP probing SHALL use full `connect()`, bound to the probed interface with `SO_BINDTODEVICE`, with a per-target timeout and immediate close, and classify each result as OPEN, REFUSED, TIMEOUT or UNREACHABLE. REFUSED counts as proof of a live IP stack. |
| FR-AC-6 | UDP probing SHALL only run protocol-specific probes with a defined payload and expected response. No generic UDP open/closed claims. v1 ships NTP (UDP 123) and EtherNet/IP ListIdentity (UDP 44818), both disabled by default; a valid reply is service evidence (OPEN, with the protocol's metadata) and identification evidence, and no reply records nothing and never means the host is offline. |
| FR-AC-7 | IPv6 discovery SHALL be limited to NDP solicitation of addresses already observed; no IPv6 sweeping. *Deferred: v1 active discovery is IPv4-first; NDP solicitation is not implemented in v1 (decided 6 Oct 2026).* |
| FR-AC-8 | Operators SHALL be able to trigger a scan on demand (`scan run`), which is subject to the same safety controls. |
| FR-AC-9 | Named scan profiles (e.g. `modbus`) SHALL be definable in config. |
| FR-AC-10 | A dry run (`scan plan`) SHALL report target count, excludes applied, probes and ports, rates, estimated packets and duration, and whether the scan would be refused and why, without transmitting. `scan run` SHALL refuse anything `scan plan` refuses. |

### 2.5 Names and vendor identification

| Id | Requirement |
| --- | --- |
| FR-NM-1 | Every hostname SHALL be stored with its type/provenance (mDNS, DHCP, DNS PTR, LLDP, NetBIOS) and all names SHALL be kept, not overwritten. |
| FR-NM-2 | A `preferred_name` SHALL be derived from configurable precedence (`identity.hostname_preference`). |
| FR-VD-1 | Vendor SHALL be looked up from the IEEE MA-L, MA-M and MA-S registries, embedded in the binary, with an optional override file. Locally administered MACs SHALL be flagged. |
| FR-VD-2 | The model SHALL keep `manufacturer` (from evidence such as OUI) separate from `device_type` (derived identification) with confidence and evidence. Identification plugins beyond OUI are phase 6+. |

### 2.6 Presence

| Id | Requirement |
| --- | --- |
| FR-PR-1 | Host presence SHALL be one of ACTIVE, RECENT, STALE, MISSING, never a boolean online flag. |
| FR-PR-2 | Thresholds SHALL be configurable; defaults ACTIVE < 5 min, RECENT < 30 min, STALE < 24 h, MISSING beyond. |

### 2.7 Events

| Id | Requirement |
| --- | --- |
| FR-EV-1 | State transitions SHALL produce events from the catalogue in `DATA_MODEL.md` §7. Repeated identical observations SHALL NOT produce events. |
| FR-EV-2 | Each event SHALL reference its host, context, old and new values and its cause, and SHALL carry a self-contained snapshot of the causing evidence (`DATA_MODEL.md` §7) so that provenance survives compaction of raw observations. |
| FR-EV-3 | Events SHALL be written to the `events` table and to journald with structured fields. |

### 2.8 Storage and retention

| Id | Requirement |
| --- | --- |
| FR-ST-1 | Data SHALL be stored in SQLite (WAL) at the configured path, default `/data/lan-sentinel/hosts.db`, with schema migrations embedded and applied at startup. |
| FR-ST-2 | Current state and event history SHALL be stored separately; raw observations SHALL be compacted. |
| FR-ST-3 | Retention SHALL be configurable per site: raw observations (default 7 days), hourly roll-ups (default 90 days), events (default 2 years) and a maximum database size (default 200 MB). When over the size cap, prune raw observations first, then roll-ups, then the oldest events. |
| FR-ST-4 | At startup the daemon SHALL run an integrity check; a corrupt database SHALL be quarantined and recreated, with an event and a log entry. |

### 2.9 API, CLI, logging, metrics, configuration

| Id | Requirement |
| --- | --- |
| FR-API-1 | The daemon SHALL serve a local REST API over a Unix socket (`/run/lan-sentinel/api.sock`, owned by `lan-sentinel`, mode 0660). No additional authentication in v1. An optional `127.0.0.1` TCP listener MAY be enabled. |
| FR-CLI-1 | The CLI SHALL implement the contract in `CLI.md`, in the same binary as the daemon. |
| FR-CLI-2 | The CLI SHALL work through the daemon socket by default and SHALL support `--offline` read-only access to the database following the contract in `CLI.md` §1. |
| FR-LOG-1 | Logging SHALL use journald with structured fields; text or JSON on stderr when run from a terminal or without journald. Observations SHALL NOT be logged; state transitions SHALL. |
| FR-STAT-1 | `daemon status` and the API SHALL report, per interface and collector (capture, neighbour, interface monitor, each probe engine, replay), whether it is running, disabled, unsupported or failed, with the error (e.g. permission denied on the `AF_PACKET` socket). A configured collector that is not running SHALL make the status degraded. |
| FR-MET-1 | The daemon SHALL expose Prometheus metrics on the local listener with prefix `lan_sentinel_` and no per-host labels. |
| FR-CFG-1 | Configuration precedence SHALL be CLI flags > `LAN_SENTINEL_*` environment > config file > compiled defaults. |
| FR-CFG-2 | Unknown config keys and invalid values SHALL fail validation. `config validate` SHALL be usable before rollout. |
| FR-CFG-3 | SIGHUP SHALL reload probes, intervals, thresholds and log level; interface and storage changes require a restart. |
| FR-CFG-4 | A kill switch (`LAN_SENTINEL_ACTIVE_DISABLED=1`, API or `active disable`) SHALL stop all active probes without a restart. A kill switch set through the API or CLI SHALL persist across restarts until cleared, and SHALL be audited with `ACTIVE_DISABLED`/`ACTIVE_ENABLED` events. |

### 2.10 Platform, development and replay

| Id | Requirement |
| --- | --- |
| FR-PLAT-1 | LAN Sentinel SHALL run on Linux only (kernel 5.10+), delivered as `linux/amd64` and `linux/arm64` binaries under systemd. |
| FR-PLAT-2 | The code base SHALL target Linux only, without build tags or stubs for other OSes. Kernel access (AF_PACKET, rtnetlink, raw and ping sockets, `SO_BINDTODEVICE`) SHALL sit behind small interfaces in `internal/platform`, and sd_notify and journald in `internal/service`, so the rest is testable with fakes. Every build, lint and test SHALL run in a Linux dev container via `make`, on Linux and macOS development machines and in CI. |
| FR-PLAT-3 | Network integration tests SHALL run in Docker containers on Docker networks with simulated hosts, as an unprivileged user with only `CAP_NET_RAW` (`make test-net`), and the systemd unit SHALL be tested in a systemd container (`make test-systemd`). |
| FR-RP-1 | A replay collector SHALL feed an interface's observations from a pcap/pcapng file (decoded by the same decoders as live capture) or from a JSONL observation stream. Replayed observations SHALL keep their recorded `Source` and timestamp. |
| FR-RP-2 | Replay SHALL drive a simulated clock from the observation timestamps (as fast as possible) or replay in real time scaled by a speed factor, so presence and expiry behave as they did at the site. The golden scenarios SHALL run through the same mechanism. |
| FR-RP-3 | Replay is configured per interface and is mutually exclusive with live passive and active discovery; the interface's prefixes come from config. All interfaces of a daemon are replay interfaces or none is, since replay runs the daemon on recorded time; several replay files are merged in time order. Replay works in the dev container. |

## 3. Non-functional requirements

| Id | Requirement |
| --- | --- |
| NFR-SAFE-1 | Global active-probe budget defaults: 20 packets/s total, 10 concurrent probes, 30 s startup delay plus jitter, ±10% interval jitter, randomised target order. |
| NFR-SAFE-2 | Scan prefixes wider than `/24` IPv4 SHALL be refused at validation unless `allow_wide_scan: true`. |
| NFR-SAFE-3 | A host returning TIMEOUT three times in a row SHALL be probed at 4× its interval. |
| NFR-SAFE-4 | Excludes (IPs and CIDRs) SHALL be checked before every transmitted probe. |
| NFR-SAFE-5 | Each probe protocol SHALL have its own rate budget beneath the global one (defaults: ARP 10 pps, ICMP 5 pps, NDP 5 pps, UDP 5 pps, TCP 5 connects/s). TCP SHALL additionally be capped at 4 concurrent connects per interface and 1 per target host, and any two probes to the same target SHALL be at least 1 s apart. A TCP connect consumes 3 tokens of the global packet budget. |
| NFR-PERF-1 | On a RevPi Connect class device: < 5% average CPU, < 50 MB RSS, database < 200 MB after 90 days on a 50-host LAN. |
| NFR-PERF-2 | SQLite commits SHALL be batched (target every 5 s) to limit SD-card wear; `synchronous=NORMAL` with WAL. |
| NFR-SEC-1 | The service SHALL run as user `lan-sentinel` with only `CAP_NET_RAW`, under the hardened unit in `ARCHITECTURE.md` §8; target `systemd-analyze security` exposure ≤ 2.5. This SHALL be verified on every change in Docker (`make test-net`, `make test-systemd`) and on each target board in phase 0; any need for another capability stops the project for a decision. |
| NFR-PORT-1 | Deliverables SHALL be static `CGO_ENABLED=0` binaries for `linux/amd64` and `linux/arm64` with SHA-256 checksums. No `.deb` or other packages. Minimum kernel 5.10. |
| NFR-PORT-2 | CI SHALL, on every change, run the same make targets as developers in the dev container: `check` (format, tidy, vet, lint, vulnerabilities, tests with race and coverage of `internal/` of at least 90%), `fuzz`, the Docker network and systemd suites, and the release build of both targets. |
| NFR-REL-1 | The daemon SHALL use `Type=notify` with READY and WATCHDOG, shut down gracefully on SIGTERM, and tolerate interfaces appearing and disappearing at runtime. |
| NFR-REL-2 | Timestamps SHALL survive clock jumps on devices without an RTC: events written before NTP sync SHALL be marked (`adjtimex` `STA_UNSYNC`). |

## 4. Out of scope for v1

SYN scanning; generic UDP port scanning; IPv6 sweeping; running on or building for any OS other than Linux; VLAN-tagged networks; a web UI; any consumption of the data off the box (fleet aggregation, remote API access), which comes in a later phase; identification plugins beyond OUI (mDNS services, Modbus FC 43/14, HTTP/TLS banners, DHCP fingerprinting, SNMP) planned for phase 6+.

## 5. Recorded decisions

| Question | Decision |
| --- | --- |
| Target hardware | amd64 and arm64 Linux edge devices |
| Platforms | Linux only, `linux/amd64` and `linux/arm64`; the code base has no stubs for other OSes. Every build and test runs in a Linux dev container via `make`, so Linux and macOS machines work for development (decided 5 Oct 2026) |
| Minimum kernel | Linux 5.10 |
| Go toolchain | Go 1.26+, the floor set by `x/net`, `x/sys` and `modernc.org/sqlite` (decided in phase 0) |
| Network tests | Docker bridge networks with simulated hosts; runner as uid 65534 with ambient `CAP_NET_RAW` (`make test-net`) |
| Neighbour source | `kernel_neighbor`, NUD state in `neighbor_state` |
| API authentication | Unix socket permissions only; no UI in this project |
| Retention | Configurable per site, with defaults and a size cap |
| Host data leaving the box | Out of scope; later phase; local API is the integration point |
| VLAN tagging | Out of scope; no VLAN sites today |
| Promiscuous mode | Configurable per interface, default off; useful only on mirror/SPAN ports or hubs |
| Deliverables | Static binaries only, no packages |
| Naming | `lan-sentinel` for repo, binary, unit, user, paths |
| Packet capture | Pure-Go `AF_PACKET` (no libpcap, no cgo) |
| Host identity | Within an interface, host = MAC. No merge/split. Multi-NIC devices are several hosts (decided 5 Oct 2026) |
| Network context | The interface only; subnet changes are history (`context_prefixes`), not new contexts |
| Interval semantics | `ended_at` NULL = open; `last_seen` = last evidence; half-open intervals |
| Event provenance | Evidence snapshot copied into every event; `observation_id` is informational |
| Kill switch | Persists across restarts when set via API/CLI; audited with events |
| Extra OT controls | `scan plan` dry run and per-protocol / per-host TCP budgets in v1 |
| Extra CLI | `observations list`, `hosts evidence`, `active enable` and `active disable` in v1 |
| Probe targets | ARP sweeps every address of the configured networks; ICMP, TCP and UDP probe only known hosts (open bindings inside those networks); `scan plan` estimates use the known-host count (decided 6 Oct 2026) |
| Scan records | Only operator-triggered `scan run` writes `scans` rows and `SCAN_STARTED`/`SCAN_COMPLETED`; scheduled probe runs show in `daemon status` and metrics (decided 6 Oct 2026) |
| UDP probes | NTP and EtherNet/IP ListIdentity, disabled by default, enrichment only; their metadata is kept as service and identification evidence, with no protocol-specific host state (decided 6 Oct 2026) |
| IPv4-first | v1 active discovery is IPv4 with ARP as the primary mechanism; NDP solicitation and other IPv6 active probing are deferred (decided 6 Oct 2026) |
| Probe libraries | Probe frames built with gopacket/layers, raw frame I/O behind a generic frame connection in `internal/platform` bound to one interface; no mdlayher/arp or mdlayher/ndp (decided 6 Oct 2026) |
| Probe presence | A MAC-less probe result is presence evidence only when the host answered: TCP OPEN or REFUSED, an ICMP echo reply, a UDP probe reply. TCP TIMEOUT and UNREACHABLE record the service result but neither refresh presence nor count against the host (`DATA_MODEL.md` §5.1, 6 Oct 2026) |
| Budget enforcement | Budgets are paced and enforced over a sliding window of 1.02 s on actual send times (a late send is re-booked when it leaves), so no one-second window on the wire exceeds a budget (6 Oct 2026) |
| TCP close and packets | The bare TCP connect probe closes with a RST (`SO_LINGER` 0) and caps SYN retransmissions at 2 (`TCP_SYNCNT`); it is charged 3 packets and sends 3 when OPEN, 1 when REFUSED, at most 3 on TIMEOUT. The RST close does not apply to protocol-specific TCP probes that exchange data over the connection (none in v1): those close with FIN and are charged for what they send (`ARCHITECTURE.md` §5, 6 Oct 2026) |
| Back-off scope | NFR-SAFE-3 applies per interface, address, probe type and port (TCP) or probe (UDP), to every known-host probe that gets no answer (ICMP or UDP without reply, TCP TIMEOUT or UNREACHABLE); a miss of one probe never slows another. An answer to the probe ends its back-off; fresh positive evidence for the address (its binding confirmed after the last miss) eases it: the next probe goes at the normal interval, and one more miss restores the back-off. ARP sweeps are exempt, so new devices are still found (6 Oct 2026) |
| Sweep size | With `allow_wide_scan` the limit is a target count, not a prefix: an interface's networks less excludes may hold at most `active.max_sweep_targets` addresses (default 65,536). Raising it is an expert override: it needs `allow_wide_scan`, and the global and ARP rates and the concurrency cap may not exceed their defaults; `config validate` shows sweep sizes and durations, and an operator sweep beyond 65,536 needs `--allow-wide` after its `scan plan` preview. Sweeps stream their addresses, so /16 is no architectural ceiling (validation keeps the value at most a /8) (6 Oct 2026) |
| Probe metric ports | `lan_sentinel_probe_total`'s `port` label is a UDP probe port or a configured TCP port; ports given only to `scan run` count as `other` (rule 9, 6 Oct 2026) |
| Scan estimate | `scan plan` gives two durations, labelled the estimated typical duration (known hosts answer at once; only the ARP sweep waits out its reply timeout) and the estimated no-response duration (every phase waits out its reply timeout), and lists the assumptions they rest on (6 Oct 2026) |
| Corrupt database | Quarantined as `<path>.corrupt-<UTC time>`, a new one created, logged as an error and recorded as the new database's first event, `DATABASE_RECREATED` (decided 6 Oct 2026) |
| Proxy ARP vs duplicate IP | Only ARP answers count. Two or more contested addresses, or more than `proxy_arp_threshold` addresses, flag proxy ARP; a single contested address is a duplicate IP. Gratuitous ARP never counts as proxy behaviour but does raise duplicate-IP conflicts (`DATA_MODEL.md` §5.2, decided 6 Oct 2026) |
| Name expiry | Names are last-known attributes: they close only when a different name of the same type replaces them, never because time passed, whether the host stays visible or goes MISSING. `name_expiry` only marks a name stale when read and never clears `preferred_name` (`DATA_MODEL.md` §5.4, decided 6 Oct 2026, replacing the same day's expire-like-addresses rule) |
