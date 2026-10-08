# ADR 0010: Precomputed OUI table, searched in place

- Status: Accepted (replaces parsing the embedded text registry at start-up)
- Date: 6 Oct 2026
- Specified in: `ARCHITECTURE.md` §3 (Identification); `IMPLEMENTATION_PLAN.md` phase 1 (OUI task)

## Context

Vendor lookup uses the IEEE MA-L, MA-M and MA-S registries, about 54,000 assignments. The daemon parsed the embedded text registry at start-up. On a Raspberry Pi CM4 that took about 0.6 s of CPU, which became about 6 s under the unit's `CPUQuota=20%`. The maintainer confirmed this experimentally on the board and chose the precomputed table.

## Decision

`make oui` downloads the registries each release. It writes them readable as `data/oui/oui.tsv.gz` and derives `data/oui/oui.bin`, a binary table that is embedded in the binary:

- sorted keys per prefix length;
- name offsets;
- each distinct name stored once.

The table's format lives in `internal/ouitable`. `internal/identify` searches it in place by binary search, longest prefix first, so start-up parses nothing and the table takes no heap. A test keeps `oui.bin` in step with `oui.tsv.gz` and checks that every lookup answers as the text registry does.

## Consequences

- Both data files are generated. Never edit them by hand; regenerate with `make oui` (or `-from-tsv` in the generator).
- The generator (`data/oui/gen`) must not import `internal/identify`, which embeds the table it generates. That is why the format lives in its own package, `internal/ouitable`.
- Start-up work under `CPUQuota=20%` is expensive. Keep it small.

## Ruled out

- Parsing a text registry at start-up.
