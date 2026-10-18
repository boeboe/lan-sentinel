# LAN Sentinel — Backlog

Everything that is **not** implemented, in one place. The functionality of v0.1.0 is frozen (`REQUIREMENTS.md` §5, Feature freeze, 16 Oct 2026): passive discovery, active discovery and identification are what the code does today. Nothing below is built, stubbed or scaffolded. Picking an item up needs the maintainer's request and, where the column says so, a recorded decision first (`AGENTS.md` §2, rule 11).

Other documents point here instead of keeping their own lists. `STATUS.md` keeps the state of what is built; `IMPLEMENTATION_PLAN.md` keeps the phase checkboxes; `TEST_PLAN.md` keeps the hardware procedure.

## 1. Deferred features: decided, not built

| Item | Why it is not built | Needs before any code | Recorded in |
| --- | --- | --- | --- |
| IPv6 active probing (NDP solicitation of known addresses) | v1 active discovery is IPv4-first; passive IPv6/NDP decoding stays. Reserved for it, unused: the `active.budgets.ndp` key, the `ndp_probe` source, and `capcheck --ndp-target` (a feasibility check that sends one solicitation) | A request; rule 12 changed | `REQUIREMENTS.md` §5 (IPv4-first), rule 12 |
| SSH key-exchange identification (`ssh-kex`) | Not specified; the `ssh-banner` probe reads only the server identification line | A recorded decision under ADR 0011: a new bounded exchange, not a scaffold of the banner probe | ADR 0011, `REQUIREMENTS.md` §4 |
| Another payload-sending identification probe, or `device_type` from banners | The ADR 0011 catalogue is closed | A recorded decision (rules 7 and 11) | ADR 0011 |
| Active LAN discovery queries: SSDP M-SEARCH, WS-Discovery Probe, NetBIOS node status, UPnP description fetches | Each sends a payload; the LAN discovery protocols are receive only | Rule 7 or ADR 0011 changed | `REQUIREMENTS.md` §5 (LAN discovery protocols) |
| Joining multicast groups (IGMP) so a snooping switch forwards 239.255.255.250 | Passive capture never transmits (FR-PA-6) | A recorded decision | `REQUIREMENTS.md` §5 (LAN discovery protocols), `TEST_PLAN.md` B9 |
| LLMNR decoding | Answers are unicast, so a switched port sees only the questions | Sites with mirror ports that want it | `REQUIREMENTS.md` §5 (LAN discovery protocols) |
| DHCPv6 server monitoring | Needs its own decoder and identity model | A request | `REQUIREMENTS.md` §5 (DHCP server monitoring) |
| Synthetic DHCP requests (probing for rogue servers) | A request changes server state | A recorded decision (rule 7) | `REQUIREMENTS.md` §5 (DHCP server monitoring) |
| More operator fields on a host (beyond `--description`) | Only the description was requested; `hosts set` leaves room for more | A request | `REQUIREMENTS.md` §5 (Host descriptions) |

## 2. Out of scope for v1

Do not build, design, scaffold or stub these without an explicit request and a recorded decision (rule 11).

| Item | Recorded in |
| --- | --- |
| VLAN-tagged networks (the capture filter drops tagged frames) | `REQUIREMENTS.md` §4, §5 (VLAN tagging) |
| A web UI | `REQUIREMENTS.md` §4 |
| Any data leaving the box: fleet aggregation, a remote API | `REQUIREMENTS.md` §4, §5 (Host data leaving the box) |
| SYN scanning, generic UDP port scanning, IPv6 sweeping | Rule 7, `REQUIREMENTS.md` §4 |
| Other operating systems; packages (`.deb`, `.rpm`, installers) | Rules 1–3 |

## 3. Open decisions

Questions that came up and have no answer yet. Ask the maintainer; do not pick one.

| Question | Context | Where it came up |
| --- | --- | --- |
| Throwaway mDNS names | Browsers announce `<uuid>.local` names during WebRTC calls and Android phones rotate `Android_XXXXXXXX` names, which gives bursts of `HOSTNAME_CHANGED`. Two proposals were rejected (ignore UUID names in the decoder; leave Android names alone and count them first). Do not re-propose either | A lab LAN, 6 Oct 2026 |
| The prefix guard can be loosened without `allow_wide_scan` | NFR-SAFE-2 says networks wider than /24 need `allow_wide_scan`. The guard is `active.max_auto_scan_prefix_v4` (default 24, accepted 8–32), and setting it to 16 lets a /16 pass without `allow_wide_scan`. Either require `allow_wide_scan` below 24 (as `max_sweep_targets` does above 65,536) or amend NFR-SAFE-2 | Documentation audit, 17 Oct 2026 |
| `scan plan` counts identification work that `scan run` does not send | The plan adds the never-attempted identification exchanges of the interfaces' `active.identify` opt-in (`identify_jobs`, in the packet estimate), and they keep it from refusing with "no targets left"; `scan run` sends no identification probes (the hourly loop does). Leave the plan as a preview of all pending work, or count only what the run sends | Documentation audit, 17 Oct 2026 |
| Start-up-only settings | `neighbor.resync_interval`, `identity.oui_override` and the probe concurrency caps take effect only at a restart (a reload says so since 17 Oct 2026). Make them reload, or keep them restart-only. `config validate` does not check that the `oui_override` file exists, so a wrong path is found only at the next start | Documentation audit, 17 Oct 2026 |
| TLS version range of the `tls` identification probe | It offers TLS 1.2 and 1.3 with ECDHE (X25519, P-256). A device that speaks only TLS 1.0/1.1 or RSA key exchange is recorded `malformed`. Widen the range only if the rig finds such devices | `TEST_PLAN.md` I1, ADR 0011 (amended) |

## 4. Hardware and field checks

The maintainer runs these; agents record the results they are given and never tick them from Docker results (`AGENTS.md` §9). Procedure: `TEST_PLAN.md`. Checkboxes: `IMPLEMENTATION_PLAN.md` (Open hardware and field checks).

| Check | Procedure |
| --- | --- |
| `capcheck` and `systemd-analyze security` under the reference unit on the RevPi Connect and the amd64 edge box (passed on a Raspberry Pi CM4) | `TEST_PLAN.md` A1–A4 |
| Neighbour-only run on a real test LAN (phase 1 exit) | `TEST_PLAN.md` B1 |
| Which LAN discovery protocols a site's switches let through (IGMP snooping, CDP-only switches) | `TEST_PLAN.md` B9 |
| Real site pcap captures as decoder fixtures | `TEST_PLAN.md` G1 |
| Passive pilot: 7 days on 3 sites; < 5% CPU and < 50 MB RSS on a RevPi (phase 2 exit) | `TEST_PLAN.md` E1, F1 |
| 7-day OT soak with active discovery against a PLC, inverter and HMI (phase 4 exit) | `TEST_PLAN.md` H1 |
| Identification probes on the OT rig, one named probe at a time | `TEST_PLAN.md` I1 |
| Staged fleet rollout (phase 5 exit, v1.0) | `deploy/README.md` (Rollout) |

## 5. Housekeeping

Small tasks that are neither features nor field work.

| Task | Notes |
| --- | --- |
| Run `make oui` before each release | Keeps the vendor table current (ADR 0010) |
