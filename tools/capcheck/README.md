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

Run it on each target board as the daemon runs: root, with only `CAP_NET_RAW` in the bounding set and the installed unit's sandboxing. Running it plainly, with or without `sudo`, tests something else: no capabilities at all, or all of them.

From the unpacked release, with `lan-sentinel.service` installed (`deploy/README.md`), and the interface and a target on it (the gateway, say) filled in:

```bash
sudo install -m 0755 capcheck /usr/local/bin/capcheck
mapfile -t props < <(systemctl cat lan-sentinel.service | awk '
  /^\[/ { svc = ($0 == "[Service]"); next }
  svc && /^[A-Za-z]/ && $0 !~ /^(Type|ExecStart|ExecReload|WatchdogSec|Restart|RuntimeDirectory|RuntimeDirectoryMode|PrivateIPC)=/ { print "-p" $0 }')
sudo systemd-run --pty --wait --collect "${props[@]}" \
  /usr/local/bin/capcheck --interface eth0 --arp-target 192.168.0.1 --icmp-target 192.168.0.1 --tcp-target 192.168.0.1:80
```

The transient unit gets every `[Service]` setting of the installed unit except the service plumbing and `PrivateIPC=`, which systemd 247 does not know (capcheck uses no IPC). capcheck has to be in `/usr/local/bin`, because `PrivateTmp=` and `ProtectHome=` hide `/tmp` and home directories from it. `--tcp-target` needs a port that is open or closed on the target; each target gets one probe.

The `privilege` line must read `CapEff=0x2000: euid 0 (root), CAP_NET_RAW`, and every row must pass or skip, including `adjtimex read`: the daemon reads the clock's sync state that way (NFR-REL-2), so the unit's call filter has to allow it. `make test-systemd` runs the same check on Debian 11, 12 and 13. Record the board, kernel, Debian release, `systemd-analyze security lan-sentinel` exposure and results in `docs/ARCHITECTURE.md` §8.
