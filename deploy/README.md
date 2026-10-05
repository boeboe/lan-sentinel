# Deployment

Reference files for running LAN Sentinel under systemd (docs/ARCHITECTURE.md §8). There are no packages; install the static binary and these files. `config.dev.yaml` is for local development (`make run-dev`).

```bash
sudo install -m 0755 lan-sentinel-linux-arm64 /usr/local/bin/lan-sentinel   # or -amd64
sudo install -m 0644 lan-sentinel.sysusers /etc/sysusers.d/lan-sentinel.conf
sudo install -m 0644 lan-sentinel.tmpfiles /etc/tmpfiles.d/lan-sentinel.conf
sudo systemd-sysusers && sudo systemd-tmpfiles --create
sudo install -m 0640 -g lan-sentinel config.yaml /etc/lan-sentinel/config.yaml
lan-sentinel config validate --config /etc/lan-sentinel/config.yaml
sudo install -m 0644 lan-sentinel.service /etc/systemd/system/lan-sentinel.service
sudo systemctl daemon-reload && sudo systemctl enable --now lan-sentinel
```

| Task | Command |
| --- | --- |
| Status | `systemctl status lan-sentinel` |
| Reload configuration | `sudo systemctl reload lan-sentinel` |
| Events in the journal | `journalctl -u lan-sentinel EVENT=ip_changed` |
| Security exposure | `systemd-analyze security lan-sentinel` (target ≤ 2.5) |

To use `lan-sentinel --offline`, add your account to group `lan-sentinel`.
