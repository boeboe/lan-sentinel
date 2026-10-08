# Architecture decision records

An ADR records why a foundational decision was taken and what it rules out, so the decision is not reopened by accident. ADRs do not specify behaviour:

- **What** the system does is in the specifications (`REQUIREMENTS.md`, `DATA_MODEL.md`, `CLI.md`, `API.md`, `ARCHITECTURE.md`).
- **Every** decision, small or large, has a dated row in `REQUIREMENTS.md` §5.
- An ADR is written only for decisions that shape the code base.

If an ADR and a specification disagree, stop and ask (`AGENTS.md` §2).

## Rules

- **Numbering.** One file per decision, `NNNN-short-title.md`, numbered in order. Never renumber.
- **Changes.** A refinement of an accepted decision (a corrected detail, an added case, a changed limit) is edited into the ADR as a dated amendment: say in the text what changed and when, and add an `Amended:` line to its header. Record the same change, with its date, in `REQUIREMENTS.md` §5. Reversing a decision, or part of one, takes a new ADR that supersedes it: set the old one's status to `Superseded by NNNN`, or mark the superseded part inline (as ADR 0008 does for its identification bullet). Typo fixes and link updates need no amendment line.
- **Who decides.** A new ADR needs the maintainer's decision. An agent may draft one only to record a decision the user has made, and adds the `REQUIREMENTS.md` §5 row in the same change.
- **Format.** Keep each short: Status, Date, Context, Decision, Consequences, Ruled out. Link to the specification sections instead of repeating them.

## Index

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-single-static-binary.md) | One static binary is the daemon, CLI, inspector and scanner | Accepted |
| [0002](0002-linux-only-dev-container.md) | Linux only; every Go command in a Linux dev container; kernel access behind platform interfaces | Accepted |
| [0003](0003-observations-before-correlation.md) | Collectors emit observations; a single correlator owns state and events | Accepted |
| [0004](0004-sqlite-wal-single-writer.md) | SQLite in WAL mode with one writer goroutine and batched commits | Accepted |
| [0005](0005-host-is-mac-per-interface.md) | A host is one MAC on one interface, keyed by a UUID; never merged or split | Accepted |
| [0006](0006-systemd-type-notify.md) | systemd `Type=notify` in the foreground with a watchdog | Accepted |
| [0007](0007-root-with-cap-net-raw-bounding-set.md) | Run as root with `CAP_NET_RAW` as the only capability | Accepted |
| [0008](0008-active-discovery-safety-envelope.md) | Active discovery inside a fixed OT safety envelope | Accepted |
| [0009](0009-operator-changes-through-the-daemon.md) | Operator changes travel through the bus to the correlator | Accepted |
| [0010](0010-precomputed-oui-table.md) | The OUI table is precomputed and searched in place | Accepted |
| [0011](0011-active-identification-probes.md) | Opt-in identification probes inside the safety envelope | Accepted |
