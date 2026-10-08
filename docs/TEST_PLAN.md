# LAN Sentinel — Hardware test plan

A plan to follow on the two target boards, the **RevPi Connect** (`linux/arm64`) and the **amd64 edge box**, that closes the open boxes in `IMPLEMENTATION_PLAN.md` (Open hardware and field checks, and the phase tasks that wait for them). Run it in order: the audit first, the 7-day runs last. Record each result in the table of its section (one column per board) and send the filled plan back as feedback; failures and surprises matter more than passes.

Every command runs on the board as a user with `sudo` unless it says otherwise. `<iface>` is the board's monitored interface (`eth0`, `eth1`, `enp1s0`, ...).

## Safety rules for this plan

- Tests marked **LAB ONLY** disturb a network (a second DHCP server, a duplicate IP, a pulled cable). Run them on an isolated lab LAN with test devices only, never on a production OT network.
- Active discovery stays off until section D, and on a site only after the site's device mix has been reviewed (`deploy/README.md`, staged rollout). Keep `sudo lan-sentinel active disable --reason "..."` at hand: it stops every probe at once.
- Take a database copy before every upgrade and before section C5.

## What you need

| Item | Notes |
| --- | --- |
| Release | The latest `vX.Y.Z` from the Releases page, `linux-arm64` for the RevPi, `linux-amd64` for the edge box |
| Lab LAN | A switch with a few devices: a laptop, a phone, a printer or NAS, ideally a PLC or HMI |
| Two test laptops | For the IP-change and duplicate-IP tests (B4) |
| A spare device that can run `dnsmasq` | For the rogue DHCP server test (B5) |
| OT rig (sections D, H) | A real PLC, inverter and HMI the site team can watch for faults |
| Tools on the boards | `tcpdump`, `curl`; `jq` helps but is optional |

## Results summary

Fill in **PASS**, **FAIL** or **SKIP** (with the reason) and copy the per-test notes into the sections.

| Test | Closes | RevPi Connect | amd64 edge box |
| --- | --- | --- | --- |
| A1 Board facts | §8 board table | | |
| A2 Install from the release | Phase 5 (install) | | |
| A3 Sandbox and capabilities | Open check: `systemd-analyze` and capcheck per board; Phase 5 audit | | |
| A4 capcheck under the unit | Open check: capcheck per board; Phase 0 capability check | | |
| B1 Neighbour table only | Open check: Phase 1 exit (real test LAN) | | |
| B2 Per-interface scoping | Open check: Phase 1 exit (scoping) | | |
| B3 Passive capture and names | Phase 2 on hardware | | |
| B4 IP change and duplicate IP (LAB ONLY) | Open check: Phase 2 exit (injected change and duplicate) | | |
| B5 DHCP server monitoring (LAB ONLY) | FR-PA-7 on hardware | | |
| B6 Passive identification | FR-VD-3 on hardware | | |
| B7 Point-in-time queries | Phase 3 exit on hardware | | |
| B8 Host descriptions | FR-MD-1 on hardware | | |
| C1 Reload | FR-CFG-3 on hardware | | |
| C2 Restart and clean stop | NFR-REL-1 | | |
| C3 Watchdog | NFR-REL-1 | | |
| C4 Link down and up (LAB ONLY) | NFR-REL-1, FR-NL-3 | | |
| C5 Power cut and clock | NFR-REL-2, FR-ST-4 | | |
| C6 Corrupt database (LAB ONLY) | FR-ST-4 | | |
| C7 Upgrade and rollback | Phase 5 (upgrade) | | |
| D1 Active discovery on the lab LAN | Phase 4 exit on hardware | | |
| D2 Budgets on the wire | Phase 4 exit (rates on a counting rig) | | |
| D3 Kill switch | Phase 4 exit (kill switch) | | |
| E1 Resource budget, 7 days | Open check: Phase 2 exit (CPU and RSS on a RevPi) | | |
| F1 Pilot sites, passive, 7 days | Open check: Phase 2 exit (3 pilot sites); Phase 5 staged rollout | | |
| G1 Site captures | Open check: Phase 2 pcap fixtures | | |
| H1 OT soak with active discovery, 7 days | Open check: Phase 4 exit (soak) | | |
| I1 Identification probes, one name at a time | ADR 0011 on the OT rig | | |

---

## A. Install and audit

### A1 Board facts

```bash
cat /proc/device-tree/model 2>/dev/null || cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name
. /etc/os-release && echo "$PRETTY_NAME"
uname -r -m
systemctl --version | head -1
ip -br link
sysctl net.ipv4.ping_group_range
timedatectl | grep -E 'RTC|synchronized|NTP'
```

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Model | | |
| Debian release, kernel, systemd | | |
| Interfaces to monitor | | |
| `ping_group_range` | | |
| RTC present, NTP client | | |

### A2 Install from the release

Follow `deploy/README.md` step 1 (verify and unpack) and step 2 (install) exactly.

**Expect:** `sha256sum --check` OK; `config validate` valid; `systemctl status lan-sentinel` active; the journal shows `active discovery: off` and `lan-sentinel running` within a few seconds (start-up under the 20% CPU cap should take about a second); `sudo lan-sentinel daemon status` shows the release version and `State: OK`.

Then edit `/etc/lan-sentinel/config.yaml` for the board's interface(s), `sudo lan-sentinel config validate`, `sudo lan-sentinel config reload`.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result, start-up time (journal) | | |

### A3 Sandbox and capabilities

```bash
systemd-analyze security lan-sentinel | tail -1
grep Cap /proc/$(systemctl show -p MainPID --value lan-sentinel)/status
ls -l /run/lan-sentinel/api.sock /data/lan-sentinel/
```

**Expect:** exposure ≤ 2.5 (2.3 in the containers); `CapEff` and `CapBnd` `0000000000002000`, `CapAmb` 0; socket `srw-rw---- root root`. On Debian 11 `daemon-reload` logs `Unknown key name 'PrivateIPC'` (expected).

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Exposure | | |
| Capabilities, socket | | |

### A4 capcheck under the unit

Run the board audit in `tools/capcheck/README.md` from the unpacked release, with the board's interface and a target on it (the gateway). Also run it once plainly, `./capcheck --interface <iface>`, without capabilities.

**Expect:** under the unit, the `privilege` line `CapEff=0x2000: euid 0 (root), CAP_NET_RAW` and every row PASS or SKIP (NDP SKIP: IPv6 probing is deferred), including `adjtimex read`. Without capabilities exactly the `CAP_NET_RAW` rows fail. Paste both outputs; they become the board's row in `ARCHITECTURE.md` §8.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result under the unit | | |
| Result without capabilities | | |

---

## B. Functional, on the lab LAN

### B1 Neighbour table only

Discovery from the kernel neighbour table alone (Phase 1 exit). Turn capture off on the interface; passive settings need a restart:

```yaml
interfaces:
  - name: <iface>
    passive: { enabled: false }
    active:  { enabled: false }
```

```bash
sudo lan-sentinel config validate && sudo systemctl restart lan-sentinel
ping -c1 <a lab device>          # puts it in the neighbour table
sudo lan-sentinel hosts list --interface <iface>
sudo lan-sentinel observations list --source kernel_neighbor --limit 10
```

**Expect:** devices the board talks to appear (source `kernel_neighbor`) with their vendor; `daemon status` shows `capture disabled`. Restore `passive: { enabled: true }` and restart afterwards.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Hosts found, vendors right | | |

### B2 Per-interface scoping

Needs two monitored interfaces on two networks (the RevPi Connect has two ports). Configure both, restart, then move one test laptop from the first network to the second.

```bash
sudo lan-sentinel hosts list
sudo lan-sentinel events list --type mac-moved
sudo lan-sentinel hosts find <laptop MAC>
```

**Expect:** the laptop is two hosts, one per interface; `MAC_MOVED` names both interfaces; `hosts find` shows both, grouped by interface. The same IP used on both networks is two bindings, never a conflict.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result | | |

### B3 Passive capture and names

With capture on (the default), connect or reboot a few lab devices.

```bash
sudo lan-sentinel watch --interface <iface>      # leave running while devices join; Ctrl-C to stop
sudo lan-sentinel hosts list --interface <iface> --active
sudo lan-sentinel hosts show <host-id>
```

**Expect:** `HOST_DISCOVERED`, `IP_ADDED` and `HOSTNAME_ADDED` (mDNS, DHCP, LLDP names) as devices join; no journal line per packet; `daemon status` `capture running`, no growing drop counter. Compare `hosts list` with what you know is on the LAN: note anything missing or wrong.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Devices found / expected | | |
| Missing or wrong | | |

### B4 IP change and duplicate IP (LAB ONLY)

With two test laptops A and B and a spare address X on the lab LAN (never a production device's address):

1. Note the time, give laptop A address X (static), ping the board.
2. Ten minutes later give laptop A address Y.
3. Give laptop B address Y while A still holds it, ping from both; then take B off Y.

```bash
sudo lan-sentinel events list --type ip-changed,duplicate-ip,duplicate-ip-resolved --since 1h
sudo lan-sentinel hosts find X --at "<time of step 1 + 5 min>"
sudo lan-sentinel hosts history Y --since 1h
```

**Expect:** `IP_CHANGED` X → Y for A; `DUPLICATE_IP_DETECTED` for Y naming both laptops, then `DUPLICATE_IP_RESOLVED`; `hosts find X --at` returns laptop A; the history shows the whole sequence.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result | | |

### B5 DHCP server monitoring (LAB ONLY)

A second DHCP server disrupts every client on the LAN: lab LAN only.

```bash
sudo lan-sentinel dhcp servers                 # after a client renews: the lab's server, status unchecked
```

Put the lab server's identifier in the allowlist (`interfaces[].dhcp.servers: [<server IP>]`), `config reload`, then start `dnsmasq` on the spare device for a few minutes and renew a client's lease.

```bash
sudo lan-sentinel dhcp servers --status unexpected
sudo lan-sentinel events list --type dhcp-server-unexpected,dhcp-server-discovered --since 1h
```

**Expect:** the lab server `allowed`; the spare device `DHCP_SERVER_DISCOVERED` and `DHCP_SERVER_UNEXPECTED`; on a plain switch port some replies may not be seen (unicast to the client), which the docs expect. Stop `dnsmasq` afterwards.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result, replies seen | | |

### B6 Passive identification

```bash
sudo lan-sentinel hosts list --interface <iface>
sudo lan-sentinel hosts show <host-id of a printer, a phone, a laptop>
sudo lan-sentinel hosts evidence <MAC>
```

**Expect:** `Device:` and `Identification:` for devices that announce themselves (printers over mDNS, Windows and Android over DHCP, switches over LLDP, Apple models over mDNS); `hosts evidence` lists every claim with `*` on the current ones. Note every wrong label: that is what the rules need.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Correct / wrong labels | | |

### B7 Point-in-time queries

```bash
sudo lan-sentinel hosts find <IP> --at "<a time from B4>"
sudo lan-sentinel --offline hosts find <IP> --at "<same time>"
sudo lan-sentinel hosts history <MAC> --since 24h
```

**Expect:** online and `--offline` answers identical, also with the daemon running.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result | | |

### B8 Host descriptions

```bash
sudo lan-sentinel hosts set <MAC of a known device> --description "Solar panel rooftop"
sudo lan-sentinel hosts list --description solar
sudo lan-sentinel hosts show <host-id>
sudo lan-sentinel hosts unset <MAC> --description
sudo lan-sentinel events list --type described
sudo lan-sentinel hosts set <MAC> --description "x" --offline
```

**Expect:** the description in `hosts list` (last column) and `hosts show`; `HOST_DESCRIBED` for the set and the unset, with your user; setting the same text twice records one event; a MAC on two interfaces asks for `--interface`; `--offline` refuses (exit 64). The description survives `sudo systemctl restart lan-sentinel`.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result | | |

---

## C. Robustness

### C1 Reload

Change `logging.level` to `debug`, then add an unknown key, then put both back:

```bash
sudo lan-sentinel config reload
```

**Expect:** the first reload lists `logging.level` as applied and the journal says `configuration reloaded; active discovery: ...`; the unknown key is rejected (exit 2, per-key error) and nothing changes; a restart-only change (e.g. `passive.ring_size`) is listed as needing a restart.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result | | |

### C2 Restart and clean stop

```bash
sudo systemctl restart lan-sentinel
sudo journalctl -u lan-sentinel -o short-precise -n 20 --no-pager
ls /data/lan-sentinel/
```

**Expect:** `lan-sentinel stopped` before the new start; no `-wal`/`-shm` left after a stop; no second `HOST_DISCOVERED` for known hosts after the restart.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result, stop and start times | | |

### C3 Watchdog

```bash
sudo kill -STOP $(systemctl show -p MainPID --value lan-sentinel)
sudo journalctl -u lan-sentinel -f       # wait about 60 s
```

**Expect:** systemd reports a watchdog timeout, kills and restarts the daemon (`Restart=on-failure`); `daemon status` OK afterwards.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result, time to restart | | |

### C4 Link down and up (LAB ONLY)

Pull the monitored cable for two minutes, plug it back.

**Expect:** `INTERFACE_DOWN` then `INTERFACE_UP`; capture shows `failed` while down and `running` again after; hosts are not all marked disappeared (presence thresholds are minutes to hours); no restart needed.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result | | |

### C5 Power cut and clock

Take a database copy (`deploy/README.md`, Upgrade). Cut the power while the daemon runs; if possible boot without network for a few minutes, then connect.

```bash
sudo lan-sentinel daemon status
sudo lan-sentinel events list --since 1h
sudo lan-sentinel db check
```

**Expect:** the daemon starts, no `DATABASE_RECREATED`, `db check` ok; `Clock: unsynced` until chrony synchronises, events written before that marked `*` (unsynced); on a board with an RTC the clock may already be right at boot but still `unsynced` until NTP.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result, clock state at boot | | |

### C6 Corrupt database (LAB ONLY)

On a copy-backed test board only:

```bash
sudo systemctl stop lan-sentinel
sudo cp -a /data/lan-sentinel/hosts.db /root/hosts.db.keep
sudo dd if=/dev/urandom of=/data/lan-sentinel/hosts.db bs=4096 seek=2 count=4 conv=notrunc
sudo systemctl start lan-sentinel
sudo lan-sentinel events list --type db-recreated
ls /data/lan-sentinel/
```

**Expect:** the daemon starts on a new database, `DATABASE_RECREATED` is its first event, the corrupt file kept as `hosts.db.corrupt-<time>`. Put `/root/hosts.db.keep` back afterwards (stop, copy, start).

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result | | |

### C7 Upgrade and rollback

Upgrade from the previous release to the latest with `deploy/README.md` (Upgrade and rollback), then roll back with the database copy, then upgrade again.

**Expect:** the upgrade keeps `/etc/lan-sentinel/config.yaml`, restarts the daemon, migrates the database (`daemon status` shows the new version); the older binary refuses the migrated database (`database schema version N is newer than this binary supports`) and starts with the copy put back.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| From → to, result | | |

---

## D. Active discovery, lab LAN first

### D1 Active discovery on the lab LAN

Enable it on the lab interface, excluding the gateway and anything fragile:

```yaml
interfaces:
  - name: <iface>
    active: { enabled: true, networks: [<lab /24>], exclude: [<gateway>] }
```

```bash
sudo lan-sentinel config validate          # shows the sweep size and duration
sudo lan-sentinel config reload            # journal: active discovery: arp every 5m on <iface> (...)
sudo lan-sentinel scan plan
sudo lan-sentinel scan run
sudo lan-sentinel daemon status            # after 5 minutes: arp ... last pass ...
```

**Expect:** `scan run` finds devices that never announce themselves; `daemon status` shows `arp running afpacket last pass ...: N swept, M replied`; periodic sweeps write nothing to the journal unless they find something new.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result, swept / replied | | |

### D2 Budgets on the wire

While `scan run` and a periodic sweep run:

```bash
sudo tcpdump -i <iface> -n -tttt -w /tmp/probes.pcap ether src $(cat /sys/class/net/<iface>/address) and arp
```

Count per second afterwards (`tcpdump -r /tmp/probes.pcap -tt | cut -d. -f1 | uniq -c | sort -n | tail`).

**Expect:** never more than 10 ARP requests in any second (20 packets for all probes); no request to an excluded address or outside the configured network; the measured packets and duration within 10% of `scan plan`.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Peak per second, plan vs measured | | |

### D3 Kill switch

Start `scan run`, then from a second shell:

```bash
sudo lan-sentinel active disable --reason "kill switch test"
sudo systemctl restart lan-sentinel && sudo lan-sentinel daemon status
sudo lan-sentinel active enable
```

**Expect:** probing stops within a second (tcpdump), the scan is recorded as aborted, `ACTIVE_DISABLED` in the journal; after the restart `Active: DISABLED (kill switch test)` and the journal says `active discovery: stopped by the kill switch (...)`; `active enable` resumes.

| | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Result, stop latency | | |

---

## E. Resource budget

### E1 Resource budget, 7 days

Passive only (active off), on a LAN of at least 50 devices if possible. Take readings at start, day 1 and day 7:

```bash
systemctl show -p CPUUsageNSec,MemoryCurrent lan-sentinel
ps -o etimes=,rss= -p $(systemctl show -p MainPID --value lan-sentinel)
sudo grep write_bytes /proc/$(systemctl show -p MainPID --value lan-sentinel)/io
sudo lan-sentinel db info
journalctl -u lan-sentinel --since -24h | wc -l
```

CPU % = (CPUUsageNSec difference in ns) / (seconds between readings × 10⁹) × 100.

**Expect (NFR-PERF-1):** average CPU < 5%, RSS < 50 MB and not growing, database on track for < 200 MB after 90 days, SD-card writes modest (batched commits), journal lines only for events. For comparison, the simulation (`make soak`, worst case with a mirror port and the ARP sweep) reached 158.8 MB after 90 days, about 80 MB after the first week, with an RSS of about 27 MB.

| Reading | RevPi Connect | amd64 edge box |
| --- | --- | --- |
| Hosts on the LAN | | |
| CPU % day 1 / day 7 | | |
| RSS day 1 / day 7 | | |
| DB size day 1 / day 7 | | |
| Bytes written per day | | |
| Journal lines per day | | |

---

## F. Pilot sites

### F1 Pilot sites, passive, 7 days

Three pilot sites, passive only, with the staged-rollout checks of `deploy/README.md`. At each site, after 7 days:

```bash
sudo lan-sentinel daemon status
sudo lan-sentinel hosts list
sudo lan-sentinel dhcp servers
sudo lan-sentinel events list --since 7d -o csv > /tmp/events.csv
```

**Expect:** `hosts list` matches what field support knows is there (note anything missing or unknown); CPU and RSS within E1's budget; no capture drops; the DHCP servers are the expected ones. B4's IP change and duplicate reconstruction is done on the lab LAN, not on a pilot site.

| Site | Board | Hosts found / expected | CPU, RSS | Notes |
| --- | --- | --- | --- | --- |
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

---

## G. Field captures

### G1 Site captures

At a pilot site (with permission), capture 30 minutes of discovery traffic on the monitored interface:

```bash
sudo tcpdump -i <iface> -w /tmp/site-<name>.pcap 'arp or (udp port 67 or udp port 68) or udp port 5353 or ether proto 0x88cc or icmp6'
```

Check what it gives by replaying it through a separate daemon (its own database and socket, the live one keeps running):

```yaml
# /tmp/replay.yaml
version: 1
interfaces:
  - name: eth9
    prefixes: [<site network>]
    replay: { file: /tmp/site-<name>.pcap }
replay: { exit_when_done: true }
storage: { path: /tmp/replay.db }
api: { socket: /tmp/replay.sock }
logging: { format: text, level: warn }
```

```bash
lan-sentinel daemon run --config /tmp/replay.yaml
lan-sentinel --db /tmp/replay.db --offline hosts list
```

Send the captures (they contain the site's addresses and names: handle them as site data) for the decoder fixtures.

| Site | Board | Capture size, devices in the replay | Notes |
| --- | --- | --- | --- |
| | | | |

---

## H. OT soak

### H1 OT soak with active discovery, 7 days

On the OT rig with a real PLC, inverter and HMI, with the site team watching the devices' diagnostics. Enable in steps, a day each, only after the previous step showed nothing:

1. ARP sweep of the rig's network (`interfaces[].active` as in D1; the sweep runs every 5 min by default).
2. ICMP echo to known hosts: `active: { icmp: { enabled: true } }`.
3. TCP connect to the devices' Modbus port: `active: { tcp: { enabled: true, targets: [{ port: 502, name: modbus, timeout: 750ms }] } }`, a plain connect, closed at once, no data.

Identification probes (`interfaces[].active.identify`) are a separate opt-in (ADR 0011) and are not part of this soak; use section I.

Apply each step with `sudo lan-sentinel config validate && sudo lan-sentinel config reload`; the journal line says what runs.

**Expect:** no device fault, alarm, diagnostic-buffer entry or dropped session on the PLC, inverter or HMI; budgets as in D2; `services list --port 502` shows OPEN for the Modbus devices. Note anything the devices log about the probes.

| Step | Days | Device faults or log entries | Notes |
| --- | --- | --- | --- |
| ARP | | | |
| ICMP | | | |
| TCP 502 | | | |

---

## I. Identification probes (LAB / OT rig)

### I1 One named probe at a time

On the OT rig with a real PLC, inverter or HMI, with the site team watching the device diagnostics. Enable **one** name under `interfaces[].active.identify` at a time (ADR 0011). For SNMPv2c write an explicit community (`community: public` or the site's read-only string); there is no compiled default. After each name:

```bash
sudo lan-sentinel config validate && sudo lan-sentinel config reload
sudo journalctl -u lan-sentinel -n 50 --no-pager
sudo lan-sentinel hosts show <mac-or-ip>
```

Expect no device fault. A first look writes `identify_attempts`; a second interval does not send again. `identify run` is the only retry and records `IDENTIFY_RAN` with your user. Silence is never offline. Do not tick this from Docker.

Measure each probe on the wire once, as in D2. Its charge on the budget is a logical cost (ADR 0011) that does not count the ACKs and FIN of the exchange, so this is the only measurement of what it really sends. Capture the box's own packets to the device on the probe's port, force one exchange, then stop the capture:

```bash
sudo tcpdump -i <iface> -n -tttt -w /tmp/identify-<probe>.pcap ether src $(cat /sys/class/net/<iface>/address) and ip host <device-ip> and port <port>
sudo lan-sentinel identify run <mac-or-ip> --probe <probe>
```

Count the packets sent (`tcpdump -r /tmp/identify-<probe>.pcap | wc -l`) and the busiest second (`tcpdump -r /tmp/identify-<probe>.pcap -tt | cut -d. -f1 | uniq -c | sort -n | tail -1`). **Expect:** the busiest second within the 20-packet global budget; record how far the packets sent exceed the charge.

For `tls`, the device completes a full handshake, including its private-key operation: watch its CPU load and diagnostics during the exchange, not only afterwards. The probe offers TLS 1.2 and 1.3 with ECDHE (X25519, P-256); a device that speaks only TLS 1.0 or 1.1, or only RSA key exchange, is recorded `malformed`. Note such devices under Notes, so the range can be decided. The probe sends no SNI unless asked: a server that answers only to its name (a reverse proxy, some HMIs) can be tried with `sudo lan-sentinel identify run <host> --probe tls --sni <name>`, or every TLS host on the interface with `{name: tls, sni: auto}`, which sends the host's name when it is a DNS name; note which devices needed it.

| Probe | Port | Charge | Device | Faults or diagnostics | Packets sent / busiest second | `identify_attempts` / `IDENTIFY_RAN` | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| modbus | 502 | 8 | | | | | |
| http | 80 | 4 | | | | | |
| tls | 443 | 7 | | | | | |
| snmp | 161 | 1 | | | | | |
| ssh-banner | 22 | 3 | | | | | |
| telnet | 23 | 11 | | | | | |
| ftp | 21 | 5 | | | | | |

---

## Feedback

Send back this file with the tables filled, plus:

- the outputs of A3 and A4 per board (they go into `ARCHITECTURE.md` §8);
- any failing command with its full output and `sudo journalctl -u lan-sentinel -n 200 --no-pager`;
- wrong or missing hosts, names or labels (B3, B6, F1);
- the captures from G1;
- identification-probe notes from I1;
- anything in this plan that was unclear or impossible on the hardware.

Each passed test lets the matching box in `IMPLEMENTATION_PLAN.md` be ticked; each failure becomes a fix or a decision.
