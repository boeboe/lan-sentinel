# ADR 0011: Opt-in identification probes inside the safety envelope

- Status: Accepted
- Date: 8 Oct 2026
- Specified in: `ARCHITECTURE.md` §3 (Active probes), §5; `REQUIREMENTS.md` FR-AC-11, §4, §5 (Active identification); `DATA_MODEL.md` §2, §5.5; AGENTS.md rules 7 and 11
- Amends: [0008](0008-active-discovery-safety-envelope.md) identification bullet only. The rest of the envelope stands.

## Context

Passive identifiers and EtherNet/IP ListIdentity already record what a device says about itself. Some OT hosts never announce a vendor or model unless spoken to. Payload-sending identification (Modbus FC 43/14, HTTP, TLS, SNMP, banners) was ruled out of v1 until a contract existed (ADR 0008, AGENTS.md rules 7 and 11). The maintainer asked for that contract: opt-in only, per interface, once per MAC, with a manual retry.

## Decision

Identification probes that send a bounded payload are allowed under this contract:

- **Opt-in per interface.** `interfaces[].active.identify` is an object list. Absent or empty sends nothing. `deploy/config.yaml` ships empty. A probe name that is not on the allow-list fails validation.
- **Known hosts only.** An address is eligible only with exactly one open IPv4 binding on that interface, `conflict = 0`, `last_seen` within `active.identify.host_max_age` (default 30 m), and a holder that is not flagged `proxy_arp`. Duplicate-IP or ambiguous ownership suppresses the probe. Suppression is not an attempt.
- **Once per MAC.** A host is one MAC on one interface (`host_id`). Each probe is attempted at most once per host. Success and failure both consume the attempt. An IP change, a restart or the next look does not send again. A new MAC is a new host. The daemon looks for never-attempted hosts on `active.identify.interval` (default 1 h); that is not a repeat period. There is no identification back-off. The latch is the `identify_probe` observation: the bus must not drop it (`PublishWait`). It is durable after the writer commits (the same batched WAL as every other row, at most 5 s). Until then the scheduler also remembers, in memory, the hosts it has sent to, so a look that starts before the commit does not send again. A kill during that window can retry once after restart.
- **Manual retry.** `identify run` goes through the daemon and bypasses only the once-latch. The kill switch, budget, excludes, configured networks and the freshness rule still apply.
- **Bounded exchange.** Each probe has a fixed maximum of requests, bytes, writes and state transitions. It may not expand because of what a device sends.
- **Budget.** Every send takes `probe.Budget`. `BudgetCost()` is a logical charge on the global packet budget (3 for TCP setup and close plus one per application write; UDP is one datagram), not a promise about segments or kernel ACKs. Payload TCP probes call `Close()` and must not use the bare connect probe's immediate RST.
- **No inference.** Claims are what the device asserted, at a per-claim confidence. This work does not classify banners into `device_type`.
- **Credentials.** No SSH, Telnet, FTP or HTTP authentication, no credential guessing, no community enumeration. SNMPv2c may send exactly one configured read-only community on a single `GetRequest`. There is no compiled default community: listing `snmp` without one fails validation.

Slice 1 builds Modbus FC 43/14 (function `0x2B`, MEI `0x0E`, Read Device ID code `0x01` basic, unit id from config). Slice 2 (8 Oct 2026) builds HTTP, TLS (one ClientHello, TLS 1.2 certificate, `BudgetCost` 4), SNMPv2c, SSH banner, Telnet and FTP. `ssh-kex` is not specified.

## Consequences

- A new engine in `internal/probe/idprobe` owns the exchange, dials and enforces the Session caps. The scheduler owns eligibility, jobs and the interval. The correlator writes `identify_attempts` and the claims. An operator `identify run` is recorded as `IDENTIFY_RAN` with the caller.
- A default configuration sends no identification payload. `make test-net` must keep showing that.
- Existing ICMP, TCP and UDP discovery keeps its own interval and back-off.

## Ruled out

- Repeating identification on a timer or after a failure.
- Binding the once-latch to an IP rather than `host_id`.
- Importing `github.com/otfabric/go-modbus` or any other identification library.
- Unit-id sweeps, Modbus register reads or writes, SunSpec, SNMP walks or sets, HTTP paths other than `/`, redirects, SNI by default, SSH key exchange, Telnet or FTP login.
- Inferring `device_type` from banners.
- SYN scanning, generic port scanning and IPv6 active identification.
