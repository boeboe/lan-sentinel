# ADR 0002: Linux only, built and tested in a Linux dev container

- Status: Accepted
- Date: 5 Oct 2026
- Specified in: `REQUIREMENTS.md` §5 (Platforms); `ARCHITECTURE.md` §2 (Development), §3 (Platform layer), §9

## Context

The first specification draft (5 Oct 2026) also supported darwin. That meant stubs, build tags and a second set of kernel backends, all for an OS the product never runs on. Developers use macOS and Linux machines.

## Decision

- **Linux only.** The product and the code base are Linux only: no build tags, and no stubs for other OSes.
- **One toolchain.** Every make target that runs Go (build, vet, lint, vuln, test, fuzz, release) runs in the Linux dev container `build/dev.Dockerfile`, as the calling user, with caches on a named volume. CI runs the same targets.
- **Kernel access behind interfaces.** Everything kernel-facing sits behind four small interfaces in `internal/platform`: `Capturer`, `NeighborSource`, `InterfaceMonitor` and `Transmitter`. sd_notify and journald sit in `internal/service`. Fakes in `platform/fake` let everything above them run in unit tests.
- **Real kernel paths are tested in Docker.** `make test-net` runs on a test network with simulated hosts, as uid 65534 with only `CAP_NET_RAW`.

## Consequences

- A development machine needs only Docker, make and git. Go is never run directly on a macOS host; editors run gopls with `GOOS=linux`.
- AF_PACKET, netlink and raw sockets appear only in `internal/platform`. Code elsewhere that needs the kernel needs a new platform method and a fake.
- Docker's kernel is not the target kernel, so board audits (`tools/capcheck`) remain mandatory.

## Ruled out

- darwin or other OS support.
- Running Go directly on developer hosts.
- Direct kernel access outside the platform layer.
