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
| FR-PA-1 | The daemon SHALL capture on configured interfaces with a kernel BPF filter limited to discovery protocols: `AF_PACKET` on Linux, `/dev/bpf*` devices on darwin. |
| FR-PA-2 | It SHALL decode ARP (including gratuitous ARP), IPv4 source addresses, IPv6 source addresses and NDP, DHCP, mDNS, DNS responses and LLDP. Each protocol SHALL be individually enabled/disabled; IPv6 SHALL be independently configurable. |
| FR-PA-3 | DHCP decoding SHALL extract hostname (option 12) and client identifier (option 61) and retain the parameter request list (option 55) for later fingerprinting. |
| FR-PA-4 | mDNS decoding SHALL extract A, AAAA, PTR, SRV and TXT records, including service types (e.g. `_http._tcp`, `_modbus._tcp`). |
| FR-PA-5 | Promiscuous mode SHALL be configurable per interface and default to off (`PACKET_ADD_MEMBERSHIP` on Linux, `BIOCPROMISC` on darwin). |
| FR-PA-6 | Passive capture SHALL never transmit frames. |

### 2.3 Kernel neighbour table

| Id | Requirement |
| --- | --- |
| FR-NL-1 | The daemon SHALL read the kernel neighbour table at startup and then follow changes through kernel notifications: rtnetlink `RTM_NEWNEIGH`/`RTM_DELNEIGH` on Linux; routing-socket messages for `RTF_LLINFO` routes on darwin. It SHALL resynchronise with a full table read after notification loss (e.g. `ENOBUFS`) and periodically (`neighbor.resync_interval`, default 10 min on Linux, 60 s on darwin where notification coverage is weaker). It SHALL NOT shell out to `ip neigh` or `arp -a`. |
| FR-NL-2 | Neighbour observations SHALL use the portable source `kernel_neighbor`, with the backend (`netlink`, `darwin_route`) and the backend's raw state in metadata, plus a normalised state (Linux NUD states; darwin `RESOLVED`, `INCOMPLETE`, `STATIC`). `STALE` SHALL NOT be interpreted as offline. |
| FR-NL-3 | The interface manager SHALL track link up/down and address/subnet changes (netlink on Linux; routing-socket `RTM_IFINFO`/`RTM_NEWADDR`/`RTM_DELADDR` on darwin) and emit `INTERFACE_UP`, `INTERFACE_DOWN` and `SUBNET_CHANGED`. |

### 2.4 Active discovery

| Id | Requirement |
| --- | --- |
| FR-AC-1 | Active discovery SHALL be disabled by default and enabled per interface. |
| FR-AC-2 | Active probes SHALL only target explicitly configured networks. Discovered subnets SHALL never be scanned automatically. |
| FR-AC-3 | ARP sweeping SHALL be implemented natively in Go and be the primary IPv4 discovery probe. |
| FR-AC-4 | ICMP echo SHALL be supported, using unprivileged datagram ICMP sockets (Linux where `net.ipv4.ping_group_range` allows, else raw sockets under `CAP_NET_RAW`; darwin always unprivileged). Disabled by default. |
| FR-AC-5 | TCP probing SHALL use full `connect()`, bound to the probed interface (`SO_BINDTODEVICE` on Linux, `IP_BOUND_IF`/`IPV6_BOUND_IF` on darwin), with a per-target timeout and immediate close, and classify each result as OPEN, REFUSED, TIMEOUT or UNREACHABLE. REFUSED counts as proof of a live IP stack. |
| FR-AC-6 | UDP probing SHALL only run protocol-specific probes with a defined payload and expected response; otherwise the result is UNKNOWN. No generic UDP open/closed claims. |
| FR-AC-7 | IPv6 discovery SHALL be limited to NDP solicitation of addresses already observed; no IPv6 sweeping. |
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
| FR-EV-3 | Events SHALL be written to the `events` table and to the platform log (journald on Linux, JSON lines on darwin; see FR-LOG-1) with structured fields. |

### 2.8 Storage and retention

| Id | Requirement |
| --- | --- |
| FR-ST-1 | Data SHALL be stored in SQLite (WAL) at the configured path (platform defaults in `ARCHITECTURE.md` §6), with schema migrations embedded and applied at startup. |
| FR-ST-2 | Current state and event history SHALL be stored separately; raw observations SHALL be compacted. |
| FR-ST-3 | Retention SHALL be configurable per site: raw observations (default 7 days), hourly roll-ups (default 90 days), events (default 2 years) and a maximum database size (default 200 MB). When over the size cap, prune raw observations first, then roll-ups, then the oldest events. |
| FR-ST-4 | At startup the daemon SHALL run an integrity check; a corrupt database SHALL be quarantined and recreated, with an event and a log entry. |

### 2.9 API, CLI, logging, metrics, configuration

| Id | Requirement |
| --- | --- |
| FR-API-1 | The daemon SHALL serve a local REST API over a Unix socket (platform default path, owned by the service user and group, mode 0660). No additional authentication in v1. An optional `127.0.0.1` TCP listener MAY be enabled. |
| FR-CLI-1 | The CLI SHALL implement the contract in `CLI.md`, in the same binary as the daemon. |
| FR-CLI-2 | The CLI SHALL work through the daemon socket by default and SHALL support `--offline` read-only access to the database following the contract in `CLI.md` §1. |
| FR-LOG-1 | Logging SHALL use journald with structured fields on Linux, and JSON lines on stderr on darwin (captured by launchd to a log file rotated by `newsyslog`); text on a terminal. Observations SHALL NOT be logged; state transitions SHALL. |
| FR-STAT-1 | `daemon status` and the API SHALL report, per interface and collector (capture, neighbour, interface monitor, each probe engine, replay), whether it is running, disabled, unsupported or failed, with the error (e.g. permission denied on `/dev/bpf*`). A configured collector that is not running SHALL make the status degraded. |
| FR-MET-1 | The daemon SHALL expose Prometheus metrics on the local listener with prefix `lan_sentinel_` and no per-host labels. |
| FR-CFG-1 | Configuration precedence SHALL be CLI flags > `LAN_SENTINEL_*` environment > config file > compiled defaults. |
| FR-CFG-2 | Unknown config keys and invalid values SHALL fail validation. `config validate` SHALL be usable before rollout. |
| FR-CFG-3 | SIGHUP SHALL reload probes, intervals, thresholds and log level; interface and storage changes require a restart. |
| FR-CFG-4 | A kill switch (`LAN_SENTINEL_ACTIVE_DISABLED=1`, API or `active disable`) SHALL stop all active probes without a restart. A kill switch set through the API or CLI SHALL persist across restarts until cleared, and SHALL be audited with `ACTIVE_DISABLED`/`ACTIVE_ENABLED` events. |

### 2.10 Platforms and replay

| Id | Requirement |
| --- | --- |
| FR-PLAT-1 | The same code base SHALL build and run on `linux/amd64`, `linux/arm64`, `darwin/amd64` and `darwin/arm64` from phase 0. Linux and darwin SHALL both be supported development platforms, and all four targets SHALL be delivered with the full v1 feature set. Minimum OS versions: Linux kernel 5.10; macOS 14 (Sonoma). |
| FR-PLAT-2 | Passive capture, neighbour monitoring, interface monitoring and probe transmission/socket setup SHALL each sit behind a small platform interface with one backend per OS (`_linux.go`, `_darwin.go`). Everything above those interfaces (observations, correlator, store, events, API, CLI, config, scheduler and budgets) SHALL be shared code with no OS-specific imports. |
| FR-PLAT-3 | The service SHALL run under systemd on Linux (`Type=notify`, watchdog) and launchd on darwin (`KeepAlive`), with reference files for both in `deploy/`. |
| FR-PLAT-4 | OT-safety behaviour (budgets, caps, excludes, guards, kill switch) SHALL be identical on both platforms and verified on both with packet counting. |
| FR-PLAT-5 | Cross-compilation SHALL NOT count as platform support: each platform's capture, neighbour, interface and probe backends SHALL have native integration tests on that OS (network namespaces on Linux, `feth` interface pairs on darwin). |
| FR-RP-1 | A replay collector SHALL feed an interface's observations from a pcap/pcapng file (decoded by the same decoders as live capture) or from a JSONL observation stream. Replayed observations SHALL keep their recorded `Source` and timestamp. |
| FR-RP-2 | Replay SHALL drive a simulated clock from the observation timestamps (as fast as possible) or replay in real time scaled by a speed factor, so presence and expiry behave as they did at the site. The golden scenarios SHALL run through the same mechanism. |
| FR-RP-3 | Replay is configured per interface and is mutually exclusive with live passive and active discovery on that interface; the interface's prefixes come from config. Replay works identically on both platforms. |

## 3. Non-functional requirements

| Id | Requirement |
| --- | --- |
| NFR-SAFE-1 | Global active-probe budget defaults: 20 packets/s total, 10 concurrent probes, 30 s startup delay plus jitter, ±10% interval jitter, randomised target order. |
| NFR-SAFE-2 | Scan prefixes wider than `/24` IPv4 SHALL be refused at validation unless `allow_wide_scan: true`. |
| NFR-SAFE-3 | A host returning TIMEOUT three times in a row SHALL be probed at 4× its interval. |
| NFR-SAFE-4 | Excludes (IPs and CIDRs) SHALL be checked before every transmitted probe. |
| NFR-SAFE-5 | Each probe protocol SHALL have its own rate budget beneath the global one (defaults: ARP 10 pps, ICMP 5 pps, NDP 5 pps, UDP 5 pps, TCP 5 connects/s). TCP SHALL additionally be capped at 4 concurrent connects per interface and 1 per target host, and any two probes to the same target SHALL be at least 1 s apart. A TCP connect consumes 3 tokens of the global packet budget. |
| NFR-PERF-1 | On a RevPi Connect class device: < 5% average CPU, < 50 MB RSS, database < 200 MB after 90 days on a 50-host LAN. On darwin the RSS and database budgets apply; CPU is measured but has no v1 target. |
| NFR-PERF-2 | SQLite commits SHALL be batched (target every 5 s) to limit SD-card wear; `synchronous=NORMAL` with WAL. |
| NFR-SEC-1 | Linux: the service SHALL run as user `lan-sentinel` with only `CAP_NET_RAW`, under the hardened unit in `ARCHITECTURE.md` §8; target `systemd-analyze security` exposure ≤ 2.5. Darwin: the daemon SHALL run as the unprivileged user `_lan-sentinel`, a member of group `access_bpf`; only a separate boot-time job (`daemon prepare`, `ARCHITECTURE.md` §9) runs as root, to grant that group access to `/dev/bpf*` and create the runtime directory. Both SHALL be verified on target systems in phase 0; any need for more privilege stops the project for a decision. |
| NFR-PORT-1 | Deliverables SHALL be `CGO_ENABLED=0` binaries for `linux/amd64`, `linux/arm64`, `darwin/amd64` and `darwin/arm64` with SHA-256 checksums. Linux binaries are fully static; darwin binaries link only the system `libSystem`, as all Go darwin binaries do. No `.deb`, `.pkg`, Homebrew formula or other packages. Darwin binaries are not notarised in v1. |
| NFR-PORT-2 | CI SHALL build all four targets on every change, and run unit, golden and native network integration tests on a Linux and a macOS runner. |
| NFR-REL-1 | The daemon SHALL shut down gracefully on SIGTERM and tolerate interfaces appearing and disappearing at runtime. On Linux it SHALL use `Type=notify` with READY and WATCHDOG; on darwin launchd restarts it on exit (`KeepAlive`). |
| NFR-REL-2 | Timestamps SHALL survive clock jumps on devices without an RTC: events written before NTP sync SHALL be marked (Linux: `adjtimex` `STA_UNSYNC`; darwin hardware has an RTC and is treated as synced). |

## 4. Out of scope for v1

SYN scanning; generic UDP port scanning; IPv6 sweeping; platforms other than Linux and darwin; notarised or packaged darwin distribution; VLAN-tagged networks; a web UI; any consumption of the data off the box (fleet aggregation, remote API access), which comes in a later phase; identification plugins beyond OUI (mDNS services, Modbus FC 43/14, HTTP/TLS banners, DHCP fingerprinting, SNMP) planned for phase 6+.

## 5. Recorded decisions

| Question | Decision |
| --- | --- |
| Target hardware | amd64 and arm64 only |
| Platforms | Linux and darwin, amd64 and arm64, are development platforms and delivery targets with full feature parity from day one; platform backends for capture, neighbours, interfaces and probes; systemd and launchd (decided 5 Oct 2026) |
| Minimum OS | Linux kernel 5.10; macOS 14 |
| Darwin privileges | Daemon as `_lan-sentinel` in `access_bpf`; root only for the boot-time `daemon prepare` job (ChmodBPF approach) |
| Neighbour source | Portable `kernel_neighbor` with backend in metadata |
| API authentication | Unix socket permissions only; no UI in this project |
| Retention | Configurable per site, with defaults and a size cap |
| Host data leaving the box | Out of scope; later phase; local API is the integration point |
| VLAN tagging | Out of scope; no VLAN sites today |
| Promiscuous mode | Configurable per interface, default off; useful only on mirror/SPAN ports or hubs |
| Deliverables | Four cgo-free binaries (static on Linux), no packages, darwin not notarised |
| Naming | `lan-sentinel` for repo, binary, unit, user, paths |
| Packet capture | Pure Go, no libpcap, no cgo: `AF_PACKET` on Linux, BPF devices on darwin |
| Host identity | Within an interface, host = MAC. No merge/split. Multi-NIC devices are several hosts (decided 5 Oct 2026) |
| Network context | The interface only; subnet changes are history (`context_prefixes`), not new contexts |
| Interval semantics | `ended_at` NULL = open; `last_seen` = last evidence; half-open intervals |
| Event provenance | Evidence snapshot copied into every event; `observation_id` is informational |
| Kill switch | Persists across restarts when set via API/CLI; audited with events |
| Extra OT controls | `scan plan` dry run and per-protocol / per-host TCP budgets in v1 |
| Extra CLI | `observations list`, `hosts evidence`, `active enable` and `active disable` in v1 |
