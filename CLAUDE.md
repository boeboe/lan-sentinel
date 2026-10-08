# CLAUDE.md — LAN Sentinel

@AGENTS.md

The import above loads `AGENTS.md`, the instructions every agent in this repository follows: the hard rules (§4, cited in code and docs as "AGENTS.md rule N"), where the truth lives and what wins when sources disagree, the package map, what to run, the common tasks and the generated files. All of it applies to Claude Code. This file adds only what is specific to Claude Code.

## Claude Code notes

- **Go only through make.** This is often a macOS host: never run `go`, `gofmt` or `golangci-lint` directly, not even `go list`.
  - For a quick loop, use `make test PKGS=...` or `make shell`.
  - If a make target fails because Docker is not running, say so and wait; do not work around it on the host.
- **Long runs go to the background.** `make check` takes a few minutes, `make check-all` and `make soak` longer. Run them with `run_in_background` and keep working; do not poll.
- **Read sections, not whole files.** `docs/ARCHITECTURE.md` is about 50 KB. Use the map in `AGENTS.md` §5 and `docs/AI_REPO_MAP.md` to open the section you need. Delegate wide searches to an Explore subagent.
- **Plan first** (plan mode, or a short plan in chat) for anything that touches rules 4–7, the schema, the unit or the safety envelope, and for any change that spans more than one package.
- **Ask with `AskUserQuestion`** when a decision is missing (AGENTS.md §2). Record the answer in `docs/REQUIREMENTS.md` §5 in the same change.
- **Commits.** Commit or push only when the user asks; the user cuts releases from the `release` workflow. When asked, one squashed commit with a plain summary line is the usual form.
- **Memory is not the record.** Durable project knowledge belongs in the repository (the docs, an ADR, `docs/STATUS.md`), not only in Claude's memory or a conversation.
