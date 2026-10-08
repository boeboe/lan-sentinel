# ADR 0008: Active discovery inside a fixed OT safety envelope

- Status: Accepted
- Date: 5 Oct 2026 (v1 specification); refined 6 Oct 2026
- Specified in: `ARCHITECTURE.md` §3 (Active probes), §5; `REQUIREMENTS.md` §2.4, NFR-SAFE-1 to NFR-SAFE-5, §4, §5 (Probe targets, IPv4-first, Budget enforcement, TCP close and packets, Back-off scope, Sweep size, Identification plugins); AGENTS.md rules 7, 11, 12

## Context

The networks are industrial. PLCs, inverters and HMIs can fault under unexpected traffic, and a fault can stop a site. About a thousand boxes may update and start probing at once. Some devices never speak unless spoken to, so passive discovery alone misses them.

## Decision

Active discovery is off by default, enabled per interface, and scoped:

- **What runs.** An ARP sweep of explicitly configured networks is the primary mechanism. ICMP echo, bare TCP connects to configured ports, and the protocol-specific UDP probes (NTP, EtherNet/IP ListIdentity) touch known hosts only.
- **The budget.** Every send passes one shared budget, which checks:
  - the kill switch and the policy;
  - excludes;
  - a global rate (20 pps) and per-protocol rates;
  - concurrency caps;
  - at least 1 s between probes to one target.

  Budgets are paced and enforced over a sliding 1.02 s window on actual send times.
- **Timing.** A start-up delay with jitter, randomised target order, and back-off after three unanswered probes.
- **Scope guards.** Prefixes wider than /24 are refused unless explicitly allowed. `scan plan` previews exactly what `scan run` does.
- **TCP.** A plain `connect()`, closed at once with a RST, with no payload and at most 3 packets.
- **No answer means nothing.** It is never "offline".

## Consequences

- Probe code is concentrated in `internal/probe`. Engines only emit observations and send only through the platform `Transmitter`.
- `make test-net` measures every one-second window on the wire against the budgets.
- The kill switch persists across restarts and stops running passes at once.

## Ruled out

- SYN scanning, generic UDP port scanning, and IPv6 sweeping. NDP solicitation is deferred: v1 is IPv4-first.
- Scanning discovered subnets automatically.
- Identification probes that send payloads (Modbus FC 43/14, HTTP, TLS, SNMP). *Superseded for this bullet by [ADR 0011](0011-active-identification-probes.md) (8 Oct 2026).*
