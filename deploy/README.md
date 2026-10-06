# Deployment

Reference files for running LAN Sentinel under systemd (docs/ARCHITECTURE.md §8). There are no packages. Each release on the [Releases page](https://github.com/boeboe/lan-sentinel/releases) has one tarball per target and `SHA256SUMS` for both:

| Asset | Contents |
| --- | --- |
| `lan-sentinel-vX.Y.Z-linux-amd64.tar.gz`, `lan-sentinel-vX.Y.Z-linux-arm64.tar.gz` | a directory of the same name with `lan-sentinel` (the static binary), `capcheck` (the privilege check for the board audit), `lan-sentinel.service` and `config.yaml` (the reference files in this directory), this `README.md`, and `SHA256SUMS` for the two binaries |
| `SHA256SUMS` | the checksums of the two tarballs |

Releases are reproducible: `make package VERSION=vX.Y.Z` on the tagged commit gives the same checksums. `config.dev.yaml` is for local development (`make run-dev`).

Targets: Debian 11 (systemd 247), 12 (252) and 13 (257), kernel 5.10 or newer; `make test-systemd` runs this unit on each. On Debian 11 the unit runs without `PrivateIPC=` (not in systemd 247; the journal shows a warning). Debian 11's regular security support ended in August 2026.

## Install

### 1. Verify and unpack

Download the tarball for the board (`linux-arm64` for a RevPi or Raspberry Pi, `linux-amd64` for an x86 edge box) and `SHA256SUMS`, then:

```bash
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf lan-sentinel-vX.Y.Z-linux-arm64.tar.gz && cd lan-sentinel-vX.Y.Z-linux-arm64
```

### 2. Install

From the unpacked directory, as a user with `sudo`. The daemon runs as root, limited by the unit to `CAP_NET_RAW` and a read-only view of the system; it needs no user, group or extra directories beyond these. `make test-systemd` runs exactly this block on Debian 11, 12 and 13.

```bash
sha256sum --check SHA256SUMS
sudo install -D -m 0755 lan-sentinel /usr/local/bin/lan-sentinel
sudo install -D -m 0640 config.yaml /etc/lan-sentinel/config.yaml
sudo install -d -m 0750 /data/lan-sentinel
sudo lan-sentinel config validate --config /etc/lan-sentinel/config.yaml
sudo install -D -m 0644 lan-sentinel.service /etc/systemd/system/lan-sentinel.service
sudo systemctl daemon-reload
sudo systemctl enable --now lan-sentinel
```

Edit `/etc/lan-sentinel/config.yaml` for the site (interfaces, and active discovery only after review, see below), check it with `sudo lan-sentinel config validate`, then apply it with `sudo lan-sentinel config reload`, which prints what took effect and what needs `sudo systemctl restart lan-sentinel` (new interfaces, passive capture, storage, API, metrics, log format). The API socket and the database are root's (mode 0660 and 0640): run `lan-sentinel` commands with `sudo`.

Then check:

| Check | Command | Expect |
| --- | --- | --- |
| Healthy | `sudo lan-sentinel daemon status` | `State: ok` (exit 0); every collector of a configured interface `running` |
| Clock | same | `Clock: synced` once chrony has synchronised; events written before that are marked `unsynced` (`clock_sync` in `events list -o json`) |
| Hosts appear | `sudo lan-sentinel hosts list` | the devices of the site within a few minutes |
| Privileges | `grep Cap /proc/$(systemctl show -p MainPID --value lan-sentinel)/status` | `CapEff` and `CapBnd` `0000000000002000`: root, but with `CAP_NET_RAW` only |
| Sandbox | `systemd-analyze security lan-sentinel` | exposure ≤ 2.5 (2.3 in the container tests) |
| Board audit (once per board type) | `capcheck` under the unit's sandbox, as in `tools/capcheck/README.md` | every row `PASS` or `SKIP`, including the `adjtimex` read; record it in `docs/ARCHITECTURE.md` §8 |

## Upgrade and rollback

Migrations run at start-up and only forward; an older binary refuses a newer database (`database schema version N is newer than this binary supports`). Keep a copy for rollback. From the extracted directory of the new release:

```bash
sudo systemctl stop lan-sentinel        # a clean stop removes the WAL
sudo cp -a /data/lan-sentinel/hosts.db /data/lan-sentinel/hosts.db.pre-$(lan-sentinel version --quiet)
sudo install -m 0755 lan-sentinel /usr/local/bin/lan-sentinel
sudo systemctl start lan-sentinel && sudo lan-sentinel daemon status
```

Compare the release's `lan-sentinel.service` with `/etc/systemd/system/lan-sentinel.service`; if the unit changed, install it and run `sudo systemctl daemon-reload` before the start.

To roll back, stop the service, put the previous binary and the copied database back, and start it. `lan-sentinel --offline` refuses a database whose schema differs from the binary's until the daemon has migrated it.

## Cutting a release

Releases are made from `main` only, by the **release** workflow (`.github/workflows/release.yml`):

1. GitHub → Actions → **release** → **Run workflow**, on branch `main`.
2. Choose the bump: `patch` (v0.0.1 → v0.0.2), `minor` (→ v0.1.0) or `major` (→ v1.0.0). The next version follows the highest `vX.Y.Z` tag (`build/next-version.sh`; pre-release tags are ignored); the first release is v0.0.1 whatever the bump.
3. The workflow refuses any branch but `main` and a version whose tag exists already, runs the same gates as CI on the commit (`make mod-verify check`, `make fuzz`, `make test-net`, `make test-systemd`), builds the tarballs twice and compares their checksums, checks that the binary reports the version, creates the annotated tag `vX.Y.Z` on the tested commit and publishes the GitHub Release with the two tarballs and `SHA256SUMS`, with notes generated from the commits.

Runs are serialised, so two releases never pick the same version. If a run fails after the tag was pushed (the release step), delete the tag before running it again, or the next run picks the following version.

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

   A misbehaving decoder is switched off fleet-wide through `passive.protocols` and `systemctl restart lan-sentinel`, without a new build (the protocols are compiled into the capture filter, so a reload does not change them).
4. Active discovery on the pilot sites, then site by site after reviewing the site's device mix:
   - set `active.enabled: true` with the site's `networks` and `exclude` (fragile devices, gateways) on the interface, and the periodic probes under `active:`; `lan-sentinel config validate` shows the sweep size and duration;
   - preview with `lan-sentinel scan plan --profile <profile>`, then `lan-sentinel scan run --profile <profile>` while someone watches the devices;
   - `sudo lan-sentinel config reload` to start the periodic probes (it lists `interfaces[N].active.enabled` as applied);
   - watch `lan_sentinel_probe_total` and `lan_sentinel_probe_throttled_total`.

   If anything misbehaves: `lan-sentinel active disable --reason "..."` stops every probe at once and stays set across restarts (`active enable` clears it). `LAN_SENTINEL_ACTIVE_DISABLED=1` in the unit's environment forces it off fleet-wide.

## Everyday tasks

| Task | Command |
| --- | --- |
| Status | `systemctl status lan-sentinel`, `sudo lan-sentinel daemon status` |
| Reload configuration | `sudo lan-sentinel config reload` (prints what took effect; `systemctl reload lan-sentinel` does the same silently) |
| Events in the journal | `journalctl -u lan-sentinel EVENT=ip_changed` |
| Security exposure | `systemd-analyze security lan-sentinel` (target ≤ 2.5) |

`lan-sentinel` commands, online or `--offline`, need `sudo`: the socket and the database belong to root.
