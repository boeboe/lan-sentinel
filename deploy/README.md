# Deployment

Reference files for running LAN Sentinel under systemd (docs/ARCHITECTURE.md §8). There are no packages: a release is the static binary for `linux/amd64` or `linux/arm64`, `SHA256SUMS`, and `capcheck` for the board audit with `capcheck-SHA256SUMS`, attached to the GitHub Release of each `v*` tag. The binaries are reproducible: `make release` on the tagged commit gives the same checksums. `config.dev.yaml` is for local development (`make run-dev`).

Targets: Debian 11 (systemd 247), 12 (252) and 13 (257), kernel 5.10 or newer; `make test-systemd` runs this unit on each. On Debian 11 the unit runs without `PrivateIPC=` (not in systemd 247; the journal shows a warning). Debian 11's regular security support ended in August 2026.

## Install

```bash
sha256sum --check --ignore-missing SHA256SUMS
sudo install -m 0755 lan-sentinel-linux-arm64 /usr/local/bin/lan-sentinel   # or -amd64
sudo install -m 0644 lan-sentinel.sysusers /etc/sysusers.d/lan-sentinel.conf
sudo install -m 0644 lan-sentinel.tmpfiles /etc/tmpfiles.d/lan-sentinel.conf
sudo systemd-sysusers && sudo systemd-tmpfiles --create
sudo install -m 0640 -g lan-sentinel config.yaml /etc/lan-sentinel/config.yaml
lan-sentinel config validate --config /etc/lan-sentinel/config.yaml
sudo install -m 0644 lan-sentinel.service /etc/systemd/system/lan-sentinel.service
sudo systemctl daemon-reload && sudo systemctl enable --now lan-sentinel
```

Then check:

| Check | Command | Expect |
| --- | --- | --- |
| Healthy | `lan-sentinel daemon status` | `State: ok` (exit 0); every collector of a configured interface `running` |
| Clock | same | `Clock: synced` once chrony has synchronised; events written before that are marked `unsynced` (`clock_sync` in `events list -o json`) |
| Hosts appear | `lan-sentinel hosts list` | the devices of the site within a few minutes |
| Privileges | `grep Cap /proc/$(systemctl show -p MainPID --value lan-sentinel)/status` | `CapEff` and `CapBnd` `0000000000002000` (`CAP_NET_RAW` only) |
| Sandbox | `systemd-analyze security lan-sentinel` | exposure ≤ 2.5 (2.0 in the container tests) |
| Board audit (once per board type) | `capcheck` under the unit's identity and sandbox, as in `tools/capcheck/README.md` | every row `PASS` or `SKIP`, including the `adjtimex` read; record it in `docs/ARCHITECTURE.md` §8 |

## Upgrade and rollback

Migrations run at start-up and only forward; an older binary refuses a newer database (`database schema version N is newer than this binary supports`). Keep a copy for rollback:

```bash
sudo systemctl stop lan-sentinel        # a clean stop removes the WAL
sudo cp -a /data/lan-sentinel/hosts.db /data/lan-sentinel/hosts.db.pre-$(lan-sentinel version --quiet)
sudo install -m 0755 lan-sentinel-linux-arm64 /usr/local/bin/lan-sentinel
sudo systemctl start lan-sentinel && lan-sentinel daemon status
```

To roll back, stop the service, put the previous binary and the copied database back, and start it. `lan-sentinel --offline` refuses a database whose schema differs from the binary's until the daemon has migrated it.

## Staged rollout (each release, docs/IMPLEMENTATION_PLAN.md)

1. Lab rig, passive only, full soak (7 days with a real PLC, inverter and HMI).
2. Three pilot sites passive only for two weeks; compare `hosts list` with what field support knows is there.
3. 50 sites (5%) passive only, then the whole fleet passive only. Watch in Prometheus (`api.listen` and `metrics.enabled`):

   | Metric | Watch for |
   | --- | --- |
   | `lan_sentinel_collector_up` | 0: a collector failed (`daemon status` names it) |
   | `lan_sentinel_capture_drops_total`, `lan_sentinel_bus_dropped_total` | growth: a busy mirror port; raise `passive.ring_size` |
   | `lan_sentinel_db_size_bytes` | approaching `storage.retention.max_db_size` (budget: < 200 MB after 90 days on a 50-host LAN) |
   | process CPU and RSS (`systemctl show -p CPUUsageNSec,MemoryCurrent lan-sentinel`) | above 5% CPU or 50 MB on a RevPi Connect |

   A misbehaving decoder is switched off fleet-wide through `passive.protocols` and `systemctl reload lan-sentinel`, without a new build.
4. Active discovery on the pilot sites, then site by site after reviewing the site's device mix:
   - set `active.enabled: true` with the site's `networks` and `exclude` (fragile devices, gateways) on the interface, and the periodic probes under `active:`; `lan-sentinel config validate` shows the sweep size and duration;
   - preview with `lan-sentinel scan plan --profile <profile>`, then `lan-sentinel scan run --profile <profile>` while someone watches the devices;
   - `systemctl reload lan-sentinel` to start the periodic probes;
   - watch `lan_sentinel_probe_total` and `lan_sentinel_probe_throttled_total`.

   If anything misbehaves: `lan-sentinel active disable --reason "..."` stops every probe at once and stays set across restarts (`active enable` clears it). `LAN_SENTINEL_ACTIVE_DISABLED=1` in the unit's environment forces it off fleet-wide.

## Everyday tasks

| Task | Command |
| --- | --- |
| Status | `systemctl status lan-sentinel`, `lan-sentinel daemon status` |
| Reload configuration | `sudo systemctl reload lan-sentinel` |
| Events in the journal | `journalctl -u lan-sentinel EVENT=ip_changed` |
| Security exposure | `systemd-analyze security lan-sentinel` (target ≤ 2.5) |

To use `lan-sentinel --offline`, add your account to group `lan-sentinel`.
