# LAN Sentinel — Status

Snapshot as of **8 Oct 2026**: `main` at a6e9eee, latest release **v0.0.6** (v0.0.5 = 5cb80c4, v0.0.4 = e222d3b). Update this file whenever an area changes state.

`IMPLEMENTATION_PLAN.md` remains the authority for tasks and exit criteria; this page summarises it and adds what the plan does not hold: deferred work, blocked items, open questions and rejected proposals.

## Summary

- **Phases 0–4** are built and verified in Docker and replay. They wait only for hardware and field checks.
- **Phase 5** (releases, hardening, rollout) is in progress: the release pipeline, hardening, config reload, DHCP server monitoring and host descriptions are in; board audits, pilots and rollout follow `TEST_PLAN.md`.
- **Phase 6** has its passive identifiers. Identification probes are in (ADR 0011, opt-in, once per MAC): Modbus FC 43/14, HTTP, TLS, SNMPv2c, SSH banner, Telnet and FTP. `ssh-kex` is not specified.

## By area

| Area | Status | Notes | Validated by |
| --- | --- | --- | --- |
| Passive capture and decoders (ARP, IPv4, IPv6/NDP, DHCP, mDNS, DNS PTR, LLDP) | Done | Synthetic site capture only; real site captures pending | Decoder tests and fuzz targets, `test/net` capture tests, `TestCaptureScenario` |
| Kernel neighbour table, interfaces, contexts | Done | | `test/net` netlink tests |
| Correlator, golden reconstruction scenario | Done | Also passes after a simulated 7-day compaction | `TestScenarios`, `TestCLIReconstruction` |
| Store: WAL writer, retention, compaction, integrity, quarantine | Done | 158.8 MB after 90 simulated days (budget 200 MB) | `test/crash` (in `make check`), `make soak` |
| API, CLI (online and `--offline`), metrics | Done | | `internal/{api,cli}` tests, `test/golden/cli_test.go` |
| Active discovery: ARP sweep, ICMP, bare TCP connect, UDP NTP and ListIdentity | Done in Docker | Off by default; budgets measured on the wire | `TestActiveDiscovery` (`make test-net`) |
| Kill switch, `scan plan`, `scan run` | Done | | `make test-net` |
| Config reload (`config reload`, SIGHUP) | Done | Interfaces' `active` and `dhcp` reload; passive settings need a restart | `internal/daemon` tests, `make test-systemd` |
| DHCP server monitoring | Done | Receive only, DHCPv4 | `TestCaptureScenario`, `make test-net` |
| Host descriptions (`hosts set` / `hosts unset`) | Done | | `internal/{cli,api,daemon,correlate,store}` tests |
| Passive identification (mDNS, DHCP, hostname, LLDP), device type in `hosts list` | Done | | `internal/identify`, `internal/correlate` tests |
| Active identification: Modbus, HTTP, TLS, SNMP, SSH banner, Telnet, FTP | Done in Docker | Opt-in per interface, once per MAC; `identify run` is the only retry. TLS is a 1.2/1.3 handshake (`BudgetCost` 7); SNI is opt-in (`sni: auto` or `identify run --sni`). Hosts already latched `tls` `malformed` need `identify run --probe tls` | `internal/probe/idprobe`, `make test-net` |
| Identification probes on the OT rig | **Pending (hardware)** | One named probe at a time; do not tick from Docker | `TEST_PLAN.md` I1 |
| Clock-sync marking of events | Done | Read-only `adjtimex` | `make test-systemd` |
| Release pipeline (tarballs, checksums, manual `release` workflow) | Done | | CI, releases v0.0.1–v0.0.6 |
| Unit hardening, root with `CAP_NET_RAW` bounding set | Done in containers and on a CM4 | Exposure 2.3 on Debian 11, 12 and 13 | `make test-systemd`; CM4 row in `ARCHITECTURE.md` §8 |
| Board audits: RevPi Connect, amd64 edge box | **Pending (hardware)** | | `TEST_PLAN.md` A1–A4 |
| Neighbour-only run on a real test LAN | **Pending (hardware)** | Phase 1 exit | `TEST_PLAN.md` B1 |
| Real site pcap fixtures | **Pending (field)** | | `TEST_PLAN.md` G1 |
| Passive pilot, 7 days on 3 sites; CPU and RSS budget on a RevPi | **Pending (field)** | Phase 2 exit | `TEST_PLAN.md` E1, F1 |
| 7-day OT soak with active discovery (PLC, inverter, HMI) | **Pending (field)** | Phase 4 exit | `TEST_PLAN.md` H1 |
| Staged fleet rollout | **Pending (field)** | Runbook in `deploy/README.md` | — |

## Deferred: decided, do not build

| Item | Why | Recorded in |
| --- | --- | --- |
| IPv6 active probing (NDP solicitation) | v1 is IPv4-first; passive IPv6/NDP decoding stays | `REQUIREMENTS.md` §5 (IPv4-first), AGENTS.md rule 12 |
| SSH key exchange identification (`ssh-kex`) | Not specified; ADR 0011 reads only the server identification line | `REQUIREMENTS.md` §5 (Active identification), ADR 0011 |
| DHCPv6 monitoring; synthetic DHCP requests | DHCPv6 needs its own decoder and identity model; requests would change server state | `REQUIREMENTS.md` §5 (DHCP server monitoring) |
| VLAN tagging, web UI, any data leaving the box | Out of scope for v1 | `REQUIREMENTS.md` §4, AGENTS.md rule 11 |

## Blocked on the maintainer

- The hardware and field checks above. The maintainer runs `TEST_PLAN.md` on the boards; agents record the results they are given (`ARCHITECTURE.md` §8 table, plan checkboxes) and never tick these from Docker results.
- `ssh-kex` if it is ever requested: a new bounded exchange under ADR 0011, not a scaffold of the banner probe.

## Open questions and rejected proposals

- **Throwaway mDNS names.** On a lab LAN (6 Oct 2026), browsers announced `<uuid>.local` names during WebRTC calls (several `HOSTNAME_CHANGED` events within a second), and Android phones rotated `Android_XXXXXXXX` names.
  - Two proposals were rejected by the maintainer:
    - the mDNS decoder ignoring a name that is exactly a UUID plus `.local`;
    - leaving Android names alone and counting them first.
  - No approach has been decided. Do not re-propose either. Ask before changing how names are handled.

## Known caveats

- On Debian 11 (systemd 247) the unit runs without `PrivateIPC=`, and the journal shows a warning. This is expected.
- On a switched port, capture does not see unicast DHCP replies, so silence never proves there is no DHCP server.
- Docker's kernel is not the target kernel, so the board audits stay mandatory.
- The unit's `CPUQuota=20%` stretches CPU-heavy start-up work. Parsing the text OUI registry took 6 s on a CM4 under it, which is why the table is precomputed (ADR 0010). Keep start-up work small.

## Next tasks

1. Maintainer: run `TEST_PLAN.md` on the RevPi Connect and the amd64 edge box. Then record the results in `ARCHITECTURE.md` §8 and the plan.
2. Add real site captures to `test/fixtures` with decoder table tests (`TEST_PLAN.md` G1).
3. Run the passive pilot (3 sites, 7 days) and the OT soak with active discovery.
4. Run `make oui` before each release.
5. Start the staged fleet rollout per `deploy/README.md`.
