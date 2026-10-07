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
| FR-PA-3 | DHCP decoding SHALL extract hostname (option 12) and client identifier (option 61) and retain the parameter request list (option 55) and vendor class (option 60) for later fingerprinting, as evidence, never as identity. Address evidence SHALL keep its provenance: `yiaddr` in a server's ACK is a server-confirmed lease (`passive_dhcp_lease`, with lease time and server identifier); `ciaddr` in a client's REQUEST or INFORM is the client's claim (`passive_dhcp`) and never a lease; offers, NAKs and the ACK to an INFORM assign no address. Lease state SHALL NOT affect presence (`DATA_MODEL.md` §5.6). |
| FR-PA-4 | mDNS decoding SHALL extract A, AAAA, PTR, SRV and TXT records, including service types (e.g. `_http._tcp`, `_modbus._tcp`). |
| FR-PA-5 | Promiscuous mode SHALL be configurable per interface and default to off; it SHALL be set with `PACKET_ADD_MEMBERSHIP` (no `CAP_NET_ADMIN`). |
| FR-PA-6 | Passive capture SHALL never transmit frames. |
| FR-PA-7 | The daemon SHALL monitor DHCPv4 servers per interface from their replies (OFFER, ACK, NAK), passively: the server identifier (option 54) kept apart from the sender MAC and IP (the server, or the relay: `giaddr`), and the router, DNS servers and subnet mask they advertise. It SHALL emit `DHCP_SERVER_DISCOVERED` for a server identity new on the interface; `DHCP_SERVER_UNEXPECTED` for one outside the interface's allowlist (`interfaces[].dhcp.servers`), where a reply without a valid identifier is never allowed and no allowlist means no verdict is claimed; `DHCP_SERVER_MAC_CHANGED` when a known identity replies from another sender MAC; and `DHCP_CONFIG_CHANGED` when an offer or lease ACK advertises other settings. Routine lease acknowledgements SHALL NOT produce events. The allowlist detects unexpected advertised identities; it does not authenticate servers. (`DATA_MODEL.md` §5.6) |

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
| FR-VD-2 | The model SHALL keep `manufacturer` (from evidence such as OUI) separate from `device_type` (derived identification) with confidence and evidence. |
| FR-MD-1 | An operator SHALL be able to set, change and remove a free-text description on a host (`lan-sentinel hosts set <host> --description`, `hosts unset <host> --description`) for context the network cannot tell, e.g. "Solar panel rooftop". The description SHALL be one line of at most 200 characters, changed only through the running daemon, and each change SHALL be recorded as `HOST_DESCRIBED` with the old and new text and the calling user. It SHALL show in `hosts show` and `hosts list` and be searchable (`hosts list --description`) (`DATA_MODEL.md` §5.8). |
| FR-VD-3 | Passive identifiers (phase 6) SHALL derive `device_type`, `os` and `model` claims, each with a confidence and its evidence, from evidence already captured: mDNS service types and the `_device-info` model, the DHCP vendor class and parameter request list a client sends, the names devices choose (mDNS, DHCP, LLDP; never a PTR name), and LLDP capabilities. They SHALL send nothing. A source's current value SHALL change only to a more confident claim, so differing announcements do not flip it; `hosts.device_type` SHALL be the most confident current claim of any source, so a probe's statement outranks a passive guess. Each identifier SHALL be switchable (`identity.identifiers`) on reload (`DATA_MODEL.md` §5.7). |

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
| FR-API-1 | The daemon SHALL serve a local REST API over a Unix socket (`/run/lan-sentinel/api.sock`, owned by the daemon's user, root under the reference unit, mode 0660). No additional authentication in v1. An optional `127.0.0.1` TCP listener MAY be enabled. |
| FR-CLI-1 | The CLI SHALL implement the contract in `CLI.md`, in the same binary as the daemon. |
| FR-CLI-2 | The CLI SHALL work through the daemon socket by default and SHALL support `--offline` read-only access to the database following the contract in `CLI.md` §1. |
| FR-LOG-1 | Logging SHALL use journald with structured fields; text or JSON on stderr when run from a terminal or without journald. Observations SHALL NOT be logged; state transitions SHALL. |
| FR-STAT-1 | `daemon status` and the API SHALL report, per interface and collector (capture, neighbour, interface monitor, each probe engine, replay), whether it is running, disabled, unsupported or failed, with the error (e.g. permission denied on the `AF_PACKET` socket). A configured collector that is not running SHALL make the status degraded. |
| FR-MET-1 | The daemon SHALL expose Prometheus metrics on the local listener with prefix `lan_sentinel_` and no per-host labels. |
| FR-CFG-1 | Configuration precedence SHALL be CLI flags > `LAN_SENTINEL_*` environment > config file > compiled defaults. |
| FR-CFG-2 | Unknown config keys and invalid values SHALL fail validation. `config validate` SHALL be usable before rollout. |
| FR-CFG-3 | SIGHUP and `lan-sentinel config reload` SHALL reload probes (each interface's `active` settings included), DHCP allowlists, intervals, budgets, thresholds and log level, all or nothing: a file that does not validate changes nothing. Adding, removing or renaming interfaces and passive capture, storage, API, metrics and log-format changes require a restart and SHALL be reported as not applied. |
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
| NFR-SEC-1 | The service SHALL hold only `CAP_NET_RAW` (it runs as root, with that capability alone in its bounding set) under the hardened unit in `ARCHITECTURE.md` §8; target `systemd-analyze security` exposure ≤ 2.5 on each target systemd (247, 252, 257). This SHALL be verified on every change in Docker (`make test-net`, `make test-systemd`) and on each target board in phase 0; any need for another capability stops the project for a decision. |
| NFR-PORT-1 | Deliverables SHALL be static `CGO_ENABLED=0` binaries for `linux/amd64` and `linux/arm64` with SHA-256 checksums, shipped as one tarball per target with the reference deploy files. No `.deb` or other packages. Minimum kernel 5.10. |
| NFR-PORT-2 | CI SHALL, on every change, run the same make targets as developers in the dev container: `check` (format, tidy, vet, lint, vulnerabilities, tests with race and coverage of `internal/` of at least 90%), `fuzz`, the Docker network and systemd suites, and the release build of both targets. |
| NFR-REL-1 | The daemon SHALL use `Type=notify` with READY and WATCHDOG, shut down gracefully on SIGTERM, and tolerate interfaces appearing and disappearing at runtime. |
| NFR-REL-2 | Timestamps SHALL survive clock jumps on devices without an RTC: events written before NTP sync SHALL be marked (`adjtimex` `STA_UNSYNC`). |

## 4. Out of scope for v1

SYN scanning; generic UDP port scanning; IPv6 sweeping; running on or building for any OS other than Linux; VLAN-tagged networks; a web UI; any consumption of the data off the box (fleet aggregation, remote API access), which comes in a later phase; identification by active probes that send payloads (Modbus FC 43/14, HTTP and TLS banners, SNMP `sysDescr`), which rule 7 of the OT safety contract excludes until it is decided otherwise; the passive identifiers (FR-VD-3) are in.

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
| Clock sync detection | NFR-REL-2 reads the kernel's NTP status with a read-only `adjtimex` (`STA_UNSYNC`), independent of the NTP client (chrony on the deployed devices; no chronyc or chrony files) and without `CAP_SYS_TIME`. Each event records `synced`, `unsynced` or `unknown`; a state that cannot be read is `unknown`, never assumed synchronised. The unit allows `adjtimex` alone of the `@clock` calls, with `ProtectClock=` off (exposure 2.0 on Debian 11, 12 and 13) (6 Oct 2026) |
| Service identity | The daemon runs as root, not as a `lan-sentinel` user: no `sysusers.d` or `tmpfiles.d`, so installing needs only the binary, the config, `/data/lan-sentinel` and the unit (a failed `sysusers.d` install on a Debian 11 board prompted it). `CapabilityBoundingSet=CAP_NET_RAW` leaves root that capability alone and the sandbox is unchanged; exposure 2.3. The socket and database are root's, so the CLI runs with `sudo`. The code still needs only `CAP_NET_RAW` as any user (`make test-net` runs it as uid 65534) (6 Oct 2026) |
| Host descriptions | Operators describe hosts with free text (requested 7 Oct 2026): `hosts set <host> --description` and `hosts unset <host> --description`, a form that leaves room for more fields later; one line of at most 200 characters on a host (a MAC on an interface: a phone that changes its MAC gets a new host, without the description); every change a `HOST_DESCRIBED` event with the caller, through the daemon so the single writer holds (7 Oct 2026) |
| Identification plugins | Phase 6 started with the passive identifiers only (requested 7 Oct 2026): mDNS, DHCP, hostname and LLDP, built-in, from evidence already captured, each switchable; confidences 0.4 (names people choose) to 0.8 (LLDP capabilities, the device's own statement), below a probe's 0.9. The active candidates (Modbus FC 43/14, HTTP `Server` and title, TLS certificate subject, SNMP `sysDescr`) send payloads, which the OT safety rules forbid; they wait for a decision (7 Oct 2026) |
| DHCP server monitoring | Passive DHCPv4 server monitoring and lease evidence in v1, on the existing capture (requested 6 Oct 2026): server identities matched by option 54 per interface against an optional allowlist (no allowlist: servers are reported as `unchecked`, never as authorised; empty list: no server expected); sender MAC changes kept and flagged; discovery, unexpected-server, MAC-change and configuration-change events. Receive only: synthetic DHCP requests would change server state and need their own specification; DHCPv6 needs its own decoder and identity model; both deferred. On a switched port unicast replies are not seen, so silence never proves there is no server (6 Oct 2026) |
| DHCP lease evidence | Lease ACKs are evidence only, not events (an event per ACK would be noise, and some ACKs only answer an INFORM): `passive_dhcp_lease` observations and address sources, distinct from the client's own claims in `passive_dhcp`; `IP_ADDED`/`IP_CHANGED` announce assignments (6 Oct 2026) |
| Config reload | `lan-sentinel config reload` (requested 6 Oct 2026) makes the daemon re-read its file through `POST /v1/config/reload` and prints which keys took effect and which need a restart; SIGHUP (`systemctl reload`) does the same. Each interface's `active` settings became reloadable, so active discovery is switched on or off per site without a restart; the set of interfaces and passive capture (whose protocols are compiled into the kernel filter) stay restart-only (6 Oct 2026) |
| Target systems | Debian 11 bullseye (systemd 247), 12 bookworm (252) and 13 trixie (257); `make test-systemd` checks the unit on each (6 Oct 2026) |
| Releases | Cut from `main` only, by the manual `release` workflow with a patch, minor or major bump from the highest `vX.Y.Z` tag (the first release is v0.0.1). After the same gates as CI and a reproducibility check, it tags the tested commit and publishes a GitHub Release with one tarball per target (binary, `capcheck`, reference deploy files, inner `SHA256SUMS`) and `SHA256SUMS` for the tarballs (6 Oct 2026) |
| Scan estimate | `scan plan` gives two durations, labelled the estimated typical duration (known hosts answer at once; only the ARP sweep waits out its reply timeout) and the estimated no-response duration (every phase waits out its reply timeout), and lists the assumptions they rest on (6 Oct 2026) |
| Corrupt database | Quarantined as `<path>.corrupt-<UTC time>`, a new one created, logged as an error and recorded as the new database's first event, `DATABASE_RECREATED` (decided 6 Oct 2026) |
| Proxy ARP vs duplicate IP | Only ARP answers count. Two or more contested addresses, or more than `proxy_arp_threshold` addresses, flag proxy ARP; a single contested address is a duplicate IP. Gratuitous ARP never counts as proxy behaviour but does raise duplicate-IP conflicts (`DATA_MODEL.md` §5.2, decided 6 Oct 2026) |
| Name expiry | Names are last-known attributes: they close only when a different name of the same type replaces them, never because time passed, whether the host stays visible or goes MISSING. `name_expiry` only marks a name stale when read and never clears `preferred_name` (`DATA_MODEL.md` §5.4, decided 6 Oct 2026, replacing the same day's expire-like-addresses rule) |
