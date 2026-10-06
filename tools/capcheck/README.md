# capcheck: the phase 0 privilege and feasibility check

`capcheck` runs every kernel operation LAN Sentinel's collectors and probes need, under the identity it is started with, and prints PASS, FAIL or SKIP per operation, together with the privilege the design expects (`docs/ARCHITECTURE.md` §8). It exits 1 if anything fails. It is Linux only.

By default it captures and opens sockets but **transmits nothing**. Each transmit test needs an explicit target and then sends exactly one probe:

| Flag | Sends |
| --- | --- |
| `--arp-target IP` | one ARP request |
| `--ndp-target IPv6` | one neighbour solicitation |
| `--icmp-target IP` | one ICMP echo |
| `--tcp-target IP:PORT` | one TCP connect, closed immediately, no payload |

`--watch 30m` also follows rtnetlink neighbour notifications and compares them with neighbour-table dumps taken every `--snapshot-every` (default 5 s); `--verbose` logs every notification and change. That measures how many changes the notifications miss, which informs `neighbor.resync_interval`. `--json` prints a machine-readable report.

Build both targets with `make tools` (output in `dist/tools/`). `make test-net` runs it in Docker on every change, with and without `CAP_NET_RAW`.

## On a target board: run it as the daemon runs

Run it on each target board, as the `lan-sentinel` user with only `CAP_NET_RAW` and the reference unit's sandboxing:

```bash
sudo systemd-run --pty --wait --collect \
  -p User=lan-sentinel -p Group=lan-sentinel \
  -p AmbientCapabilities=CAP_NET_RAW -p CapabilityBoundingSet=CAP_NET_RAW \
  -p NoNewPrivileges=true -p ProtectSystem=strict -p ProtectHome=true -p PrivateTmp=true \
  -p PrivateDevices=true -p ProtectKernelTunables=true -p ProtectKernelModules=true \
  -p ProtectControlGroups=true -p RestrictNamespaces=true -p LockPersonality=true \
  -p MemoryDenyWriteExecute=true -p SystemCallArchitectures=native \
  -p "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET AF_NETLINK" \
  -p "SystemCallFilter=@system-service" -p "SystemCallFilter=~@privileged @resources" \
  -p "SystemCallFilter=adjtimex" -p SystemCallErrorNumber=EPERM \
  /usr/local/bin/capcheck --interface eth1 --arp-target 192.168.110.1
```

The `privilege` line must show `CAP_NET_RAW` only, and the `adjtimex read` row must pass: the daemon reads the clock's sync state that way (NFR-REL-2), so the unit's call filter has to allow it. `make test-systemd` passes every `[Service]` setting of the reference unit instead of this list. Record the kernel version, board, Debian release, `systemd-analyze security lan-sentinel` exposure and results in `docs/ARCHITECTURE.md` §8.
