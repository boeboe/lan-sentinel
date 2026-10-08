# ADR 0005: A host is one MAC on one interface

- Status: Accepted
- Date: 5 Oct 2026
- Specified in: `REQUIREMENTS.md` §2.1, §5 (Host identity, Network context); `DATA_MODEL.md` §1 (Identity decision), §3, §5.1; `ARCHITECTURE.md` §2

## Context

The product's purpose is reconstruction: what used this IP at that time, with which MAC. Any rule that merges or splits identities on weaker evidence (hostnames, fingerprints, IP continuity) produces history that may be wrong and cannot be audited. On layer 2 the MAC is the only reliable same-device evidence. The same addresses can appear on several interfaces of one box.

## Decision

- **Scope.** The network context is the interface. Subnet changes are history (`context_prefixes`), not new contexts.
- **Identity.** Within a context, a host has exactly one MAC, and the MAC is the only identity evidence. Rows are keyed by an internal UUID `host_id`.
- **No merging.** Hosts are never merged or split. A multi-NIC device is several hosts; a NIC swap or a phone's new random MAC is a new host.
- **Bindings.** IPs, names and services are bindings with `first_seen`, `last_seen` and `ended_at` (NULL means open), with half-open interval semantics.
- **Conflicts.** Duplicate IPs are kept as parallel bindings.

## Consequences

- The same MAC or IP on two interfaces is two hosts or bindings (`MAC_MOVED` records a MAC that appears on another interface).
- Operator metadata such as descriptions belongs to the host. A device that changes its MAC loses it.
- Point-in-time queries (`hosts find --at`) are exact over intervals.

## Ruled out

- Fingerprint- or name-based host merging.
- A global (cross-interface) host identity.
- Keying hosts by IP.
