# LAN Sentinel — User guide

This guide is for the people who install LAN Sentinel on an edge device and use it to answer questions about a site's network: field engineers, OT support and integrators. It covers configuration, every everyday command with its output, the systemd journal, active discovery, identification and troubleshooting. The command reference with every option is [`CLI.md`](CLI.md); installation steps are in the [README](../README.md#install-the-latest-release) and [`deploy/README.md`](../deploy/README.md).

**About the examples.** Every output below is real output of v0.1.0 on Debian 12 under systemd, recorded on 17 Oct 2026; nothing is edited except long tables, where `…` marks left-out rows. Two set-ups were used:

- *Site capture.* A four-hour capture of a small plant network on `192.168.110.0/24` (three Siemens PLCs, an HMI, a Windows server that is also the DHCP server, an Axis camera, a Cisco switch and a laptop that briefly ran its own DHCP server), replayed through the daemon (`interfaces[].replay`). A replay has no clock to check, so its events carry a `?` marker (see [Clock synchronisation](#clock-synchronisation)), and the interface shows state `unknown`.
- *Live box.* The daemon on a test network `172.31.240.0/24` with three devices, with active discovery enabled.

Host IDs, MACs and times differ on your box. The test boxes run in UTC; the CLI prints the box's local time. The test box had no `curl`, so the metrics example was fetched with an equivalent request.

## Contents

1. [How LAN Sentinel sees a network](#1-how-lan-sentinel-sees-a-network)
2. [Configuration](#2-configuration)
3. [Is it working?](#3-is-it-working)
4. [The inventory](#4-the-inventory)
5. [One host in detail](#5-one-host-in-detail)
6. [Who had this IP address?](#6-who-had-this-ip-address)
7. [History and events](#7-history-and-events)
8. [Why it believes what it shows](#8-why-it-believes-what-it-shows)
9. [DHCP servers](#9-dhcp-servers)
10. [Describing hosts](#10-describing-hosts)
11. [The systemd journal](#11-the-systemd-journal)
12. [Active discovery](#12-active-discovery)
13. [Identification probes](#13-identification-probes)
14. [Reading the database without the daemon](#14-reading-the-database-without-the-daemon)
15. [Scripts, monitoring and metrics](#15-scripts-monitoring-and-metrics)
16. [Troubleshooting](#16-troubleshooting)
17. [Upgrading and removing](#17-upgrading-and-removing)

## 1. How LAN Sentinel sees a network

**A host is one MAC address on one interface.** The same device on two interfaces is two hosts (and a `MAC_MOVED` event); a device whose network card is replaced becomes a new host. Hosts are never merged or split, so the history of a MAC is never rewritten.

**Addresses and names are intervals.** Each IP address a host holds is a *binding* with a first seen, a last seen and, once it ends, an end time. A name is kept the same way, with its type (`mdns`, `dhcp`, `dns_ptr`, `lldp`, `netbios`). This is what lets you ask who had an address at any moment.

**Where the evidence comes from.** Every source only reports what it saw (an *observation*); the daemon correlates them:

| Source | Sends anything? | What it reveals |
| --- | --- | --- |
| Passive capture (`passive_arp`, `passive_dhcp`, `passive_dhcp_lease`, `passive_dhcp_server`, `passive_mdns`, `passive_dns`, `passive_lldp`, `passive_cdp`, `passive_netbios`, `passive_ssdp`, `passive_wsd`, `passive_ipv4`, `passive_ipv6`, `passive_ndp`) | No, receive only | MAC and IP pairs, names, DHCP servers and leases, the switch port, device types and models |
| Kernel neighbour table (`kernel_neighbor`) | No | Pairs the box itself resolved |
| Active discovery (`arp_scan`, `icmp_scan`, `tcp_connect`, `udp_probe`) | Yes, only when enabled | Devices that never speak on their own; open TCP ports |
| Identification probes (`identify_probe`) | Yes, only when enabled per interface | Model, firmware, banners and certificates |

On a switched port, capture sees the box's own traffic, broadcasts and multicast: enough to learn most devices over time. On a mirror (SPAN) port with `promiscuous: true` it sees everything.

**Presence.** Each host has a state from the time since it was last seen:

| State | Last seen |
| --- | --- |
| `ACTIVE` | less than 5 minutes ago |
| `RECENT` | less than 30 minutes ago |
| `STALE` | less than 24 hours ago |
| `MISSING` | 24 hours ago or more (raises `HOST_DISAPPEARED`) |

A host that goes quiet keeps its addresses: the last known state stays in effect and shows as unconfirmed, and a probe that gets no answer never makes a host offline. An address a host stops using while it is still seen elsewhere expires after 24 hours (`identity.address_expiry`, `IP_REMOVED` with cause `expiry`).

**Events** record state changes: a host discovered, an IP added, changed or removed, a duplicate IP, a name change, a new or unexpected DHCP server, an operator action. They are stored for two years and written to the journal. The full list is in [`DATA_MODEL.md` §7](DATA_MODEL.md#7-event-catalogue).

## 2. Configuration

The configuration is `/etc/lan-sentinel/config.yaml`. Unknown keys are errors, so a typo never goes unnoticed. The shipped file listens passively on `eth0`; a typical site names its interfaces and leaves everything else at its default:

```yaml
version: 1
interfaces:
  - name: eth0                        # the plant network
    passive: { enabled: true }
    dhcp: { servers: [192.168.110.2] }  # the DHCP server(s) expected here
  - name: eth1                        # a mirror port of the line switch
    passive: { enabled: true, promiscuous: true }
```

| Setting | What it does | Default |
| --- | --- | --- |
| `interfaces[].passive.promiscuous` | See all traffic on a mirror (SPAN) port or hub | `false` |
| `interfaces[].dhcp.servers` | DHCP server identifiers (option 54) expected on the interface; any other raises `DHCP_SERVER_UNEXPECTED`. `[]` means none should exist; unset gives no verdict | unset |
| `passive.protocols` | Switch a decoder off: `arp`, `ipv4`, `ipv6`, `dhcp`, `mdns`, `dns`, `lldp`, `netbios`, `cdp`, `ssdp`, `wsd` | all on except `ipv6` |
| `presence` | The presence thresholds | `{ active: 5m, recent: 30m, stale: 24h }` |
| `storage.retention` | How long raw observations, hourly roll-ups and events are kept, and the database size cap | 7 days, 90 days, 2 years, 200 MB |
| `api.listen` | Also serve the API read-only and Prometheus `/metrics` on `127.0.0.1:<port>` | off |
| `interfaces[].active` | Active discovery, off until you enable it ([§12](#12-active-discovery)) | off |

Every key, its value and where the value came from (default, file, `LAN_SENTINEL_*` environment variable or flag):

```bash
sudo lan-sentinel config show --sources
```

Check a file before you use it. `config validate` prints what the daemon will do with it, including how long an ARP sweep takes and the highest probe rate:

```
$ sudo lan-sentinel config validate
Configuration /etc/lan-sentinel/config.yaml is valid.

Interfaces:
  NAME  PASSIVE  ACTIVE                                                                                  DHCP SERVERS
  eth0  passive  active on  networks 172.31.240.0/24  exclude 172.31.240.1  sweep 253 addresses (~26 s)  no allowlist

Probes:   arp every 5m; icmp every 10m; tcp 502 (modbus) every 5m; identify http every 1h
Budgets:  global 20 pps; arp 10 pps; icmp 5 pps; ndp 5 pps; udp 5 pps; tcp 5 connects/s (≤4 per interface, ≤1 per host)
Estimated maximum probe rate: 20 pps
```

The `ndp` budget is reserved for IPv6 neighbour probing, which is not built: nothing uses it.

**Applying a change.** `sudo lan-sentinel config reload` (or `sudo systemctl reload lan-sentinel`) applies most changes at once and prints what took effect. A reload is all or nothing: a file that does not validate changes nothing.

```
$ sudo lan-sentinel config reload
Configuration /etc/lan-sentinel/config.yaml reloaded.

Applied:
  KEY                  OLD  NEW
  active.arp.interval  5m   15m
```

| Applies on reload | Needs `sudo systemctl restart lan-sentinel` |
| --- | --- |
| Each interface's `active` settings and `dhcp` allowlist, probes, intervals, rate budgets, presence thresholds, identity settings, log level | Adding, removing or renaming interfaces; `passive` settings; `storage`; `api`; `metrics`; `logging.format`; `replay`; and the settings read once at start-up: `neighbor.resync_interval`, `identity.oui_override`, `active.max_concurrent_probes` and the TCP concurrency caps |

Changed keys that need a restart are listed under *Not applied, needs a restart* and keep their running values until then.

## 3. Is it working?

`daemon status` is the health check. Exit code 0 means healthy, 1 degraded (for example a configured collector not running), 2 unhealthy, 3 the daemon is not reachable.

```
$ sudo lan-sentinel daemon status
Version:    v0.1.0 (linux/arm64)   PID 103   up 40s
Database:   /data/lan-sentinel/hosts.db  ok  750 KB
Active:     enabled
Clock:      unsynced (events are marked until the clock is synchronised)
Last scan:  never
Interfaces:
  eth0   up      172.31.240.0/24
         hosts      3 active
         arp        running     afpacket
         capture    running     afpacket
         icmp       running     ping socket
         identify   running     socket
         interface  running     netlink
         neighbor   running     netlink
         tcp        running     socket
         udp        disabled    socket
State:      OK
```

- `Active` is the kill switch: `enabled`, or `DISABLED` with the reason ([§12](#the-kill-switch)).
- `Clock` turns `synced` once chrony (or another NTP client) has synchronised the clock.
- Each interface lists its collectors. `capture` and `neighbor` should be `running`; probes show `disabled` until active discovery is enabled.

`interfaces list` shows each interface, its prefixes, its mode and the switch and port it is plugged into, learned from LLDP or CDP (`(+N)` after it means N more neighbours):

```
$ sudo lan-sentinel interfaces list
NAME  STATE    MAC  PREFIXES          PASSIVE  ACTIVE  HOSTS  NEIGHBOR
eth1  unknown  -    192.168.110.0/24  replay   off     8      IE4000-PLANT1 GigabitEthernet1/0/12
```

On a live box the state is `up` and the MAC is the interface's own:

```
$ sudo lan-sentinel interfaces list
NAME  STATE  MAC                PREFIXES         PASSIVE  ACTIVE  HOSTS  NEIGHBOR
eth0  up     fa:3d:a0:fd:31:a4  172.31.240.0/24  on       on      3      -
```

## 4. The inventory

`hosts list` is the current inventory, one row per host:

```
$ sudo lan-sentinel hosts list
MAC                IP              HOSTNAME       VENDOR                  DEVICE  IFACE  STATE   LAST SEEN  DESCRIPTION
00:0e:8c:11:22:33  192.168.110.20  HMI-LINE3      Siemens AG              -       eth1   ACTIVE  2m ago     
00:15:5d:00:00:02  192.168.110.2   PLANT-SRV01    Microsoft Corporation   Server  eth1   RECENT  7m ago     
00:1b:1b:aa:bb:01  192.168.110.52  plc-a.local    Siemens AG              -       eth1   ACTIVE  2m ago     
00:1b:1b:aa:bb:02  192.168.110.50  -              Siemens AG              -       eth1   ACTIVE  2m ago     
00:1b:1b:aa:bb:03  192.168.110.51  -              Siemens AG              -       eth1   STALE   1h ago     
00:1d:a2:4c:7e:01  -               IE4000-PLANT1  Cisco Systems, Inc      Switch  eth1   ACTIVE  2m ago     
00:40:8c:5e:10:21  192.168.110.60  -              Axis Communications AB  Camera  eth1   ACTIVE  4m ago     
02:00:00:00:00:66  192.168.110.66  -              -                       -       eth1   STALE   1h ago     
```

- `IP` is the first open address (IPv4 before IPv6); `(+N)` after it means the host holds N more.
- `HOSTNAME` is the preferred name: mDNS first, then DHCP, DNS PTR, LLDP/CDP and NetBIOS (`identity.hostname_preference`).
- `VENDOR` comes from the IEEE registry; a locally administered MAC (`02:…`, typical of virtual machines and randomised phone MACs) has none.
- `DEVICE` is the most confident device type any source has claimed.

Filters combine:

| Option | Shows |
| --- | --- |
| `--interface eth1` | hosts on one interface |
| `--active` / `--stale` | live hosts (`ACTIVE`, `RECENT`) / the others (`STALE`, `MISSING`) |
| `--vendor siemens` | vendor or manufacturer contains the text |
| `--device camera` | device type contains the text |
| `--description K3` | description contains the text |
| `--port 502` | hosts with an open service on the port |
| `--seen-within 24h` | last seen within a duration, or since a time |

```
$ sudo lan-sentinel hosts list --stale
MAC                IP              HOSTNAME  VENDOR      DEVICE  IFACE  STATE  LAST SEEN  DESCRIPTION
00:1b:1b:aa:bb:03  192.168.110.51  -         Siemens AG  -       eth1   STALE  1h ago     
02:00:00:00:00:66  192.168.110.66  -         -           -       eth1   STALE  1h ago     
```

## 5. One host in detail

`hosts show` takes a MAC, an IP, a name or a host ID and prints everything known about the current host: addresses with their history and sources, names, services, the description and the identification by source.

A PLC whose address changed twice, once into a conflict:

```
$ sudo lan-sentinel hosts show 192.168.110.52
Host ID:     01a148fb-8e30-7a37-9231-22a6336714c1
Interface:   eth1
MAC:         00:1b:1b:aa:bb:01  Siemens AG
State:       STALE
Name:        plc-a.local
First seen:  2026-10-17 04:26:26
Last seen:   2026-10-17 07:56:26

Addresses:
  192.168.110.50   2026-10-17 04:26:26 → 2026-10-17 05:26:26   sources: passive_arp, passive_mdns
  192.168.110.51   2026-10-17 05:26:26 → 2026-10-17 07:56:26   sources: passive_dhcp_lease, passive_arp   CONFLICT
  192.168.110.52   2026-10-17 07:56:26 → open   sources: passive_dhcp_lease

Names:
  plc-a.local      mdns     confirmed 4h ago

Identification:
  oui  (0.70)  4h ago
    manufacturer  Siemens AG
```

`CONFLICT` marks a binding that was held by two live hosts at once (a duplicate IP). The Windows server, named and identified from its NetBIOS broadcasts:

```
$ sudo lan-sentinel hosts show PLANT-SRV01
Host ID:     01a148fb-8e30-7dba-a754-d63a1aa8c0a0
Interface:   eth1
MAC:         00:15:5d:00:00:02  Microsoft Corporation
State:       STALE
Name:        PLANT-SRV01
Device:      Server
First seen:  2026-10-17 04:32:26
Last seen:   2026-10-17 07:56:26

Addresses:
  192.168.110.2    2026-10-17 04:32:26 → open   sources: passive_netbios, passive_arp, passive_dhcp_server, passive_ipv4

Names:
  PLANT-SRV01      netbios  confirmed 3h ago

Identification:
  netbios  (0.70)  3h ago
    device_type   Server                 (0.50)
    os            Windows                (0.60)
    os_version    10.0                   (0.60)
    workgroup     PLANT
  oui      (0.70)  3h ago
    manufacturer  Microsoft Corporation
```

The switch, from its CDP advertisements, and the camera, from its WS-Discovery `Hello` (ONVIF) and SSDP announcements:

```
$ sudo lan-sentinel hosts show IE4000-PLANT1
Host ID:     01a148fd-fee0-7899-b5f3-8a2f1b3ab844
Interface:   eth1
MAC:         00:1d:a2:4c:7e:01  Cisco Systems, Inc
State:       ACTIVE
Name:        IE4000-PLANT1
Device:      Switch
First seen:  2026-10-17 04:30:43
Last seen:   2026-10-17 08:30:43

Names:
  IE4000-PLANT1    lldp     confirmed 2m ago

Identification:
  cdp  (0.80)  2m ago
    device_type   Switch
    firmware      Cisco IOS Software, IE4000 Software (IE4000-UNIVERSALK9-M), Version 15.2(7)E8
    model         cisco IE-4000-8GT4G-E
  oui  (0.70)  4h ago
    manufacturer  Cisco Systems, Inc

$ sudo lan-sentinel hosts show 192.168.110.60
Host ID:     01a148fb-8e31-7042-a725-b783c8556851
Interface:   eth1
MAC:         00:40:8c:5e:10:21  Axis Communications AB
State:       STALE
Device:      Camera
First seen:  2026-10-17 04:36:26
Last seen:   2026-10-17 04:36:28

Addresses:
  192.168.110.60   2026-10-17 04:36:26 → open   sources: passive_arp, passive_wsd, passive_ssdp

Identification:
  wsd   (0.70)  3h ago
    device_type   Camera
    model         P3245-LVE
  oui   (0.70)  3h ago
    manufacturer  Axis Communications AB
  ssdp  (0.50)  3h ago
    os            Linux
```

CDP and LLDP names are stored with name type `lldp`. A source's identification only changes to a more confident claim, except what a device reports about itself (firmware, system description, workgroup, OS version), which follows the device.

## 6. Who had this IP address?

`hosts find` answers for now, or for any past moment with `--at`. An address held by two hosts shows both:

```
$ sudo lan-sentinel hosts find 192.168.110.51 --at '2026-10-17 07:40'
Host ID:     01a148fd-ff31-7d60-9c86-92faf71c854b
Interface:   eth1
MAC:         00:1b:1b:aa:bb:03  Siemens AG
Binding:     192.168.110.51   2026-10-17 07:30:23 → open   sources: passive_arp   CONFLICT   (unconfirmed since 2026-10-17 07:30:23)
Conflict:    2026-10-17 07:30:23 DUPLICATE_IP_DETECTED 192.168.110.51 between 00:1b:1b:aa:bb:03 and 00:1b:1b:aa:bb:01

Host ID:     01a148fd-fee0-779b-a016-6063ce7ac3e3
Interface:   eth1
MAC:         00:1b:1b:aa:bb:01  Siemens AG
Name:        plc-a.local
Description: Filling line 2 PLC, cabinet K3
Binding:     192.168.110.51   2026-10-17 05:30:23 → 2026-10-17 08:00:23   sources: passive_dhcp_lease, passive_arp   CONFLICT   (unconfirmed since 2026-10-17 07:20:23)
Moved to:    192.168.110.52 at 2026-10-17 08:00:23
Conflict:    2026-10-17 07:30:23 DUPLICATE_IP_DETECTED 192.168.110.51 between 00:1b:1b:aa:bb:03 and 00:1b:1b:aa:bb:01
```

Read it as: at 07:40 two Siemens devices claimed `.51`. The PLC `plc-a.local` had it from DHCP since 05:30 and moved to `.52` at 08:00; the other device announced `.51` at 07:30 and was not heard from again. *Unconfirmed since* is the last time any source confirmed the binding.

`--at` takes `YYYY-MM-DD HH:MM[:SS]` in local time, or RFC 3339. Without `--at`, `hosts find` shows the current holder; it exits 1 when nothing matches, which makes it usable in scripts. `--interface` restricts it to one interface; `--ip`, `--mac`, `--hostname` or `--id` force how the query is read.

## 7. History and events

**One host or address over time.** `hosts history` takes a MAC, IP, name or host ID:

```
$ sudo lan-sentinel hosts history 00:1b:1b:aa:bb:01
TIME                  TYPE                   IFACE  MAC                VALUE                             RELATED            CAUSE
2026-10-17 04:26:26?  HOST_DISCOVERED        eth1   00:1b:1b:aa:bb:01  192.168.110.50                    -                  passive_arp
2026-10-17 04:26:27?  HOSTNAME_ADDED         eth1   00:1b:1b:aa:bb:01  mdns:plc-a.local                  -                  passive_mdns
2026-10-17 05:26:26?  IP_CHANGED             eth1   00:1b:1b:aa:bb:01  192.168.110.50 -> 192.168.110.51  -                  passive_dhcp_lease
2026-10-17 07:26:26?  DUPLICATE_IP_DETECTED  eth1   00:1b:1b:aa:bb:03  192.168.110.51                    00:1b:1b:aa:bb:01  passive_arp
2026-10-17 07:56:26?  IP_CHANGED             eth1   00:1b:1b:aa:bb:01  192.168.110.51 -> 192.168.110.52  -                  passive_dhcp_lease
2026-10-17 07:56:26?  DUPLICATE_IP_RESOLVED  eth1   00:1b:1b:aa:bb:03  192.168.110.51                    00:1b:1b:aa:bb:01  passive_dhcp_lease
? written while the clock's synchronisation was unknown

$ sudo lan-sentinel hosts history 192.168.110.51
TIME                  TYPE                   IFACE  MAC                VALUE                             RELATED            CAUSE
2026-10-17 05:26:26?  IP_CHANGED             eth1   00:1b:1b:aa:bb:01  192.168.110.50 -> 192.168.110.51  -                  passive_dhcp_lease
2026-10-17 07:26:26?  HOST_DISCOVERED        eth1   00:1b:1b:aa:bb:03  192.168.110.51                    -                  passive_arp
2026-10-17 07:26:26?  DUPLICATE_IP_DETECTED  eth1   00:1b:1b:aa:bb:03  192.168.110.51                    00:1b:1b:aa:bb:01  passive_arp
2026-10-17 07:56:26?  IP_CHANGED             eth1   00:1b:1b:aa:bb:01  192.168.110.51 -> 192.168.110.52  -                  passive_dhcp_lease
2026-10-17 07:56:26?  DUPLICATE_IP_RESOLVED  eth1   00:1b:1b:aa:bb:03  192.168.110.51                    00:1b:1b:aa:bb:01  passive_dhcp_lease
? written while the clock's synchronisation was unknown
```

`CAUSE` is the source of the evidence, or an internal cause (`presence`, `expiry`, `iface_monitor`, `operator`). `--since 24h`, `--since 7d` or `--until` narrow the window.

**Everything on the box.** `events list` shows the latest 1000 events (`--limit`) in time order:

```
$ sudo lan-sentinel events list
TIME                  TYPE                    IFACE  MAC                VALUE                                                                                   RELATED            CAUSE
2026-10-17 04:26:26?  SUBNET_CHANGED          eth1   -                  192.168.110.0/24                                                                        -                  iface_monitor
2026-10-17 04:26:26?  HOST_DISCOVERED         eth1   00:1b:1b:aa:bb:01  192.168.110.50                                                                          -                  passive_arp
2026-10-17 04:26:27?  HOSTNAME_ADDED          eth1   00:1b:1b:aa:bb:01  mdns:plc-a.local                                                                        -                  passive_mdns
…
2026-10-17 04:32:26?  HOST_DISCOVERED         eth1   00:15:5d:00:00:02  192.168.110.2                                                                           -                  passive_netbios
2026-10-17 04:32:26?  HOSTNAME_ADDED          eth1   00:15:5d:00:00:02  netbios:PLANT-SRV01                                                                     -                  passive_netbios
2026-10-17 04:32:27?  VENDOR_IDENTIFIED       eth1   00:15:5d:00:00:02  workgroup=PLANT                                                                         -                  passive_netbios
…
2026-10-17 04:36:28?  DHCP_SERVER_DISCOVERED  eth1   00:15:5d:00:00:02  192.168.110.2                                                                           -                  passive_dhcp_server
…
2026-10-17 06:56:26?  HOST_DISCOVERED         eth1   02:00:00:00:00:66  192.168.110.66                                                                          -                  passive_dhcp_server
2026-10-17 06:56:26?  DHCP_SERVER_DISCOVERED  eth1   02:00:00:00:00:66  192.168.110.66                                                                          -                  passive_dhcp_server
2026-10-17 06:56:26?  DHCP_SERVER_UNEXPECTED  eth1   02:00:00:00:00:66  192.168.110.66                                                                          -                  passive_dhcp_server
2026-10-17 07:26:26?  HOST_DISCOVERED         eth1   00:1b:1b:aa:bb:03  192.168.110.51                                                                          -                  passive_arp
2026-10-17 07:26:26?  DUPLICATE_IP_DETECTED   eth1   00:1b:1b:aa:bb:03  192.168.110.51                                                                          00:1b:1b:aa:bb:01  passive_arp
2026-10-17 07:56:26?  IP_CHANGED              eth1   00:1b:1b:aa:bb:01  192.168.110.51 -> 192.168.110.52                                                        -                  passive_dhcp_lease
2026-10-17 07:56:26?  DUPLICATE_IP_RESOLVED   eth1   00:1b:1b:aa:bb:03  192.168.110.51                                                                          00:1b:1b:aa:bb:01  passive_dhcp_lease
2026-10-17 07:56:26?  DHCP_CONFIG_CHANGED     eth1   00:15:5d:00:00:02  dns=192.168.110.2 -> dns=192.168.110.2,192.168.110.4                                    -                  passive_dhcp_server
? written while the clock's synchronisation was unknown
```

Filter by type (kebab-case names, repeatable), time, interface, MAC or IP:

```
$ sudo lan-sentinel events list --type duplicate-ip
TIME                  TYPE                   IFACE  MAC                VALUE           RELATED            CAUSE
2026-10-17 07:26:26?  DUPLICATE_IP_DETECTED  eth1   00:1b:1b:aa:bb:03  192.168.110.51  00:1b:1b:aa:bb:01  passive_arp
? written while the clock's synchronisation was unknown
```

Event types you will filter on most:

| `--type` | Event | Means |
| --- | --- | --- |
| `discovered` | `HOST_DISCOVERED` | a new MAC on an interface |
| `ip-changed`, `ip-added`, `ip-removed` | `IP_CHANGED`, … | a host's addresses changed |
| `duplicate-ip`, `duplicate-ip-resolved` | `DUPLICATE_IP_DETECTED`, … | two live hosts claim one address, and when that ended |
| `mac-moved` | `MAC_MOVED` | a MAC known on another interface appeared on this one |
| `disappeared`, `reappeared` | `HOST_DISAPPEARED`, … | a host went MISSING, or came back |
| `name-added`, `name-changed` | `HOSTNAME_ADDED`, … | names |
| `dhcp-server-unexpected`, `dhcp-server-mac-changed`, `dhcp-config-changed` | | DHCP servers ([§9](#9-dhcp-servers)) |
| `service-opened`, `service-closed` | | probe results ([§12](#12-active-discovery)) |
| `active-disabled`, `active-enabled`, `scan-started`, `scan-completed`, `identify-ran`, `described` | | operator actions, with the Unix user |

**Live.** `watch` streams events as they happen until Ctrl-C (`--interface`, `--type`):

```
$ sudo lan-sentinel watch
08:30:43  HOST_DESCRIBED         eth1   Filling line 2 PLC, cabinet K3  00:1b:1b:aa:bb:01
```

## 8. Why it believes what it shows

`hosts evidence` lists, per address and claim, every source with its first and last time, the observation counts, and each event with the evidence snapshot it was raised on. `*` marks the value each source holds now.

```
$ sudo lan-sentinel hosts evidence 192.168.110.60
Host 01a148fb-8e31-7042-a725-b783c8556851  00:40:8c:5e:10:21  on eth1

Addresses:
  192.168.110.60   2026-10-17 04:36:26 → open
      passive_arp      first 2026-10-17 04:36:26  last 2026-10-17 04:36:26
      passive_wsd      first 2026-10-17 04:36:27  last 2026-10-17 04:36:27
      passive_ssdp     first 2026-10-17 04:36:28  last 2026-10-17 04:36:28

Identification:
  wsd   (0.70)  3h ago
    *device_type   Camera                  (0.70)  {"onvif_types":"video_encoder","types":"NetworkVideoTransmitter,Device"}
    *model         P3245-LVE               (0.70)  {"onvif_hardware":"P3245-LVE"}
  oui   (0.70)  3h ago
    *manufacturer  Axis Communications AB  (0.70)  {"mac":"00:40:8c:5e:10:21","registry":"IEEE"}
  ssdp  (0.50)  3h ago
    *os            Linux                   (0.50)  {"server":"Linux/4.14, UPnP/1.0, Portable SDK for UPnP devices/1.6.22"}
  (* current: the value each source holds now)

Observations (raw and roll-ups):
  passive_arp      192.168.110.60        1  first 2026-10-17 04:36:26  last 2026-10-17 04:36:26
  passive_ssdp     192.168.110.60        1  first 2026-10-17 04:36:28  last 2026-10-17 04:36:28
  passive_wsd      192.168.110.60        1  first 2026-10-17 04:36:27  last 2026-10-17 04:36:27

Events:
  2026-10-17 04:36:26  HOST_DISCOVERED        192.168.110.60  (passive_arp)
      evidence {"interface":"eth1","ip":"192.168.110.60","mac":"00:40:8c:5e:10:21","source":"passive_arp","ts":"2026-10-17T04:36:26Z"}
  2026-10-17 04:36:27  VENDOR_IDENTIFIED      device_type=Camera  (passive_wsd)
      evidence {"interface":"eth1","ip":"192.168.110.60","mac":"00:40:8c:5e:10:21","source":"passive_wsd","ts":"2026-10-17T04:36:27Z"}
  …
```

The raw observations behind it (kept 7 days; `--rollups` shows the hourly roll-ups kept 90 days):

```
$ sudo lan-sentinel observations list --mac 00:1b:1b:aa:bb:01
TIME                 IFACE  SOURCE              MAC                IP              HOSTNAME     SERVICE  HOST
2026-10-17 04:26:26  eth1   passive_arp         00:1b:1b:aa:bb:01  192.168.110.50  -            -        01a148fb-8e30-7a37-9231-22a6336714c1
2026-10-17 04:26:27  eth1   passive_mdns        00:1b:1b:aa:bb:01  192.168.110.50  plc-a.local  -        01a148fb-8e30-7a37-9231-22a6336714c1
2026-10-17 05:26:26  eth1   passive_dhcp_lease  00:1b:1b:aa:bb:01  192.168.110.51  -            -        01a148fb-8e30-7a37-9231-22a6336714c1
2026-10-17 07:16:26  eth1   passive_arp         00:1b:1b:aa:bb:01  192.168.110.51  -            -        01a148fb-8e30-7a37-9231-22a6336714c1
2026-10-17 07:56:26  eth1   passive_dhcp_lease  00:1b:1b:aa:bb:01  192.168.110.52  -            -        01a148fb-8e30-7a37-9231-22a6336714c1
```

Identical observations are recorded once per two minutes, so a chatty device does not fill the database.

## 9. DHCP servers

Every DHCP server that answers on an interface is recorded by its identity (option 54), with the MAC and IP that sent the reply (a relay, if one forwarded it) and what it advertises:

```
$ sudo lan-sentinel dhcp servers
SERVER ID       RELAY  MAC                IP              IFACE  STATUS      ROUTER          DNS                          MASK           LAST SEEN
192.168.110.2   -      00:15:5d:00:00:02  192.168.110.2   eth1   allowed     192.168.110.1   192.168.110.2,192.168.110.4  255.255.255.0  33m ago
192.168.110.66  -      02:00:00:00:00:66  192.168.110.66  eth1   unexpected  192.168.110.66  -                            255.255.255.0  1h ago
```

`STATUS` is `allowed` or `unexpected` against the interface's `dhcp.servers` list, and `unchecked` when no list is set. Set the list once you know the site's servers, then `sudo lan-sentinel config reload`; from then on any other server raises `DHCP_SERVER_UNEXPECTED` (a warning in the journal). The list is not authentication: it flags a laptop or a misconfigured device running its own server, as above.

On a switched port the box sees DHCP broadcasts but not replies sent unicast to other clients, so an empty list proves nothing; a mirror port sees everything.

## 10. Describing hosts

Add a one-line note to a host (at most 200 characters), for the next person who looks:

```
$ sudo lan-sentinel hosts set 192.168.110.52 --description 'Filling line 2 PLC, cabinet K3'
Description of 00:1b:1b:aa:bb:01 on eth1: Filling line 2 PLC, cabinet K3

$ sudo lan-sentinel hosts list --description K3
MAC                IP              HOSTNAME     VENDOR      DEVICE  IFACE  STATE   LAST SEEN  DESCRIPTION
00:1b:1b:aa:bb:01  192.168.110.52  plc-a.local  Siemens AG  -       eth1   ACTIVE  2m ago     Filling line 2 PLC, cabinet K3
```

`hosts unset <host> --description` removes it. Each change is a `HOST_DESCRIBED` event with the Unix user who made it. The description belongs to the host (the MAC on that interface), so it stays with the device when its address changes.

## 11. The systemd journal

The daemon writes start-up and shutdown messages, warnings, and one journal entry per event. Observations are never logged, so the journal stays readable.

```
$ journalctl -u lan-sentinel --no-pager
Oct 17 08:34:30 plant-edge-01 systemd[1]: Starting lan-sentinel.service - LAN Sentinel...
Oct 17 08:34:30 plant-edge-01 lan-sentinel[103]: lan-sentinel starting
Oct 17 08:34:30 plant-edge-01 lan-sentinel[103]: database ready
Oct 17 08:34:30 plant-edge-01 lan-sentinel[103]: vendor table loaded
Oct 17 08:34:30 plant-edge-01 lan-sentinel[103]: system clock is not known to be synchronised; events are marked until it is
Oct 17 08:34:30 plant-edge-01 lan-sentinel[103]: api listening
Oct 17 08:34:30 plant-edge-01 lan-sentinel[103]: active discovery: arp every 5m, icmp every 10m, tcp 502 (modbus) every 5m, identify http every 1h on eth0 (172.31.240.0/24 exclude 172.31.240.1)
Oct 17 08:34:30 plant-edge-01 lan-sentinel[103]: lan-sentinel running
Oct 17 08:34:30 plant-edge-01 lan-sentinel[103]: SUBNET_CHANGED eth0 172.31.240.0/24
Oct 17 08:34:30 plant-edge-01 systemd[1]: Started lan-sentinel.service - LAN Sentinel.
Oct 17 08:34:30 plant-edge-01 lan-sentinel[103]: capture started
Oct 17 08:34:30 plant-edge-01 lan-sentinel[103]: HOST_DISCOVERED eth0 00:0e:8c:00:00:20 172.31.240.20
Oct 17 08:34:31 plant-edge-01 lan-sentinel[103]: HOST_DISCOVERED eth0 00:30:de:00:00:30 172.31.240.30
Oct 17 08:34:31 plant-edge-01 lan-sentinel[103]: HOST_DISCOVERED eth0 00:1b:1b:00:00:10 172.31.240.10
Oct 17 08:35:11 plant-edge-01 lan-sentinel[103]: SCAN_STARTED eth0 operator scan arp,icmp,tcp/502: 28 addresses to sweep, 3 known hosts
Oct 17 08:35:19 plant-edge-01 lan-sentinel[103]: SERVICE_OPENED eth0 00:1b:1b:00:00:10 tcp/502 172.31.240.10
Oct 17 08:35:19 plant-edge-01 lan-sentinel[103]: SCAN_COMPLETED eth0 operator scan done in 9s; arp 25 no_reply, 3 reply; icmp 3 reply; tcp/502 1 open, 2 refused
Oct 17 08:35:20 plant-edge-01 lan-sentinel[103]: IDENTIFY_RAN eth0 00:0e:8c:00:00:20 http ok 172.31.240.20
Oct 17 08:35:20 plant-edge-01 lan-sentinel[103]: SERVICE_OPENED eth0 00:0e:8c:00:00:20 tcp/80 172.31.240.20
Oct 17 08:35:20 plant-edge-01 lan-sentinel[103]: VENDOR_IDENTIFIED eth0 00:0e:8c:00:00:20 title=Line 2 HMI 172.31.240.20
Oct 17 08:35:21 plant-edge-01 lan-sentinel[103]: ACTIVE_DISABLED active discovery disabled by root: PLC firmware update on line 2
Oct 17 08:35:21 plant-edge-01 lan-sentinel[103]: ACTIVE_ENABLED active discovery enabled by root: firmware update done
Oct 17 08:35:21 plant-edge-01 lan-sentinel[103]: configuration reloaded; active discovery: arp every 15m, icmp every 10m, tcp 502 (modbus) every 5m, identify http every 1h on eth0 (172.31.240.0/24 exclude 172.31.240.1)
```

An event's message is `TYPE interface MAC value [IP]`. Useful forms:

| Command | Shows |
| --- | --- |
| `journalctl -u lan-sentinel -f` | follow as it happens |
| `journalctl -u lan-sentinel -b` | since the last boot |
| `journalctl -u lan-sentinel --since "2026-10-17 06:00" --until "2026-10-17 09:00"` | a time window |
| `journalctl -u lan-sentinel -p warning` | warnings and errors only |
| `journalctl -u lan-sentinel EVENT=duplicate_ip_detected` | one event type |
| `journalctl -u lan-sentinel MAC=00:1b:1b:aa:bb:01` | events of one MAC |
| `journalctl -u lan-sentinel IFACE=eth1 EVENT=host_discovered` | fields combine (AND) |
| `journalctl -u lan-sentinel -o cat` | messages only |
| `journalctl -u lan-sentinel -o json` | one JSON object per entry, for scripts |

Warnings and errors only, in the site capture: the rogue DHCP server and the duplicate IP.

```
$ journalctl -u lan-sentinel --no-pager -p warning -o cat
DHCP_SERVER_UNEXPECTED eth1 02:00:00:00:00:66 192.168.110.66
DUPLICATE_IP_DETECTED eth1 00:1b:1b:aa:bb:03 192.168.110.51
```

One MAC's story:

```
$ journalctl -u lan-sentinel --no-pager -o cat MAC=00:1b:1b:aa:bb:01
HOST_DISCOVERED eth1 00:1b:1b:aa:bb:01 192.168.110.50
HOSTNAME_ADDED eth1 00:1b:1b:aa:bb:01 mdns:plc-a.local 192.168.110.50
IP_CHANGED eth1 00:1b:1b:aa:bb:01 192.168.110.50 -> 192.168.110.51
IP_CHANGED eth1 00:1b:1b:aa:bb:01 192.168.110.51 -> 192.168.110.52
HOST_DESCRIBED eth1 00:1b:1b:aa:bb:01 Filling line 2 PLC, cabinet K3
```

Each event entry carries structured fields; `-o verbose` shows them all:

```
$ journalctl -u lan-sentinel --no-pager -o verbose EVENT=duplicate_ip_detected
Sat 2026-10-17 08:30:07.921301 UTC [s=df5efcf9fe9b4b528acf0518edf1133a;i=2fc;b=bb20022a9e8c44d284a7f411221f2373;m=33e4a48a;t=65e0516a372e3;x=53028910e72f9c9b]
    _BOOT_ID=bb20022a9e8c44d284a7f411221f2373
    _MACHINE_ID=db73e1dc4717484082a7fd9e8d45afac
    _HOSTNAME=plant-edge-01
    _RUNTIME_SCOPE=system
    PRIORITY=4
    _UID=0
    _GID=0
    _SYSTEMD_SLICE=system.slice
    _TRANSPORT=journal
    SYSLOG_IDENTIFIER=lan-sentinel
    _PID=110
    _COMM=lan-sentinel
    _EXE=/usr/local/bin/lan-sentinel
    _CMDLINE=/usr/local/bin/lan-sentinel daemon run --config /etc/lan-sentinel/config.yaml
    _CAP_EFFECTIVE=2000
    _SYSTEMD_CGROUP=/system.slice/lan-sentinel.service
    _SYSTEMD_UNIT=lan-sentinel.service
    _SYSTEMD_INVOCATION_ID=f54e978beb6a4440949331be63b04a5c
    IFACE=eth1
    CLOCK_SYNC=unknown
    SOURCE=passive_arp
    NEW_VALUE=192.168.110.51
    IP=192.168.110.51
    HOST_ID=01a148fb-8e31-742c-8721-67253adf5e0e
    MAC=00:1b:1b:aa:bb:03
    TS=2026-10-17 07:26:26 +0000 UTC
    MESSAGE=DUPLICATE_IP_DETECTED eth1 00:1b:1b:aa:bb:03 192.168.110.51
    RELATED_HOST_ID=01a148fb-8e30-7a37-9231-22a6336714c1
    EVENT=duplicate_ip_detected
    _SOURCE_REALTIME_TIMESTAMP=1792225807921301
```

| Field | Meaning |
| --- | --- |
| `EVENT` | the event type in lower case (`ip_changed`) |
| `IFACE`, `MAC`, `IP`, `HOST_ID` | the host the event is about |
| `OLD_VALUE`, `NEW_VALUE` | what changed (an address, `mdns:name`, `field=value`) |
| `RELATED_HOST_ID` | the other host of a duplicate IP or a MAC move |
| `SOURCE` | what caused it: an evidence source, `presence`, `expiry`, `iface_monitor` or `operator` |
| `TS` | when it happened. In a replay, or for evidence that arrived late, this differs from the journal's own timestamp |
| `CLOCK_SYNC` | `unsynced` or `unknown` when the clock was not known to be synchronised; absent once it is |
| `PRIORITY` | 4 warning (`DUPLICATE_IP_DETECTED`, `MAC_MOVED`, `ACTIVE_DISABLED`, `INTERFACE_DOWN`, `DATABASE_RECREATED`, `DHCP_SERVER_UNEXPECTED`, `DHCP_SERVER_MAC_CHANGED`), 5 notice (other changes), 6 info (scans, identification); errors are 3 |

For scripts, `-o json` gives one object per line; with `jq`:

```bash
journalctl -u lan-sentinel -o json EVENT=ip_changed | jq -r '[.TS, .MAC, .OLD_VALUE, .NEW_VALUE] | @tsv'
```

```
$ journalctl -u lan-sentinel --no-pager -o json EVENT=ip_changed
{"_GID":"0","_BOOT_ID":"bb20022a9e8c44d284a7f411221f2373","MESSAGE":"IP_CHANGED eth1 00:1b:1b:aa:bb:01 192.168.110.50 -> 192.168.110.51","CLOCK_SYNC":"unknown","_CAP_EFFECTIVE":"2000","_SYSTEMD_UNIT":"lan-sentinel.service","_TRANSPORT":"journal","TS":"2026-10-17 05:26:26 +0000 UTC","_COMM":"lan-sentinel","_SYSTEMD_CGROUP":"/system.slice/lan-sentinel.service","_SYSTEMD_SLICE":"system.slice","_SOURCE_REALTIME_TIMESTAMP":"1792225807921182","HOST_ID":"01a148fb-8e30-7a37-9231-22a6336714c1","__CURSOR":"s=df5efcf9fe9b4b528acf0518edf1133a;i=2f6;b=bb20022a9e8c44d284a7f411221f2373;m=33e4a3e4;t=65e0516a3723c;x=583dfc18d1b0ea5c","MAC":"00:1b:1b:aa:bb:01","SYSLOG_IDENTIFIER":"lan-sentinel","_SYSTEMD_INVOCATION_ID":"f54e978beb6a4440949331be63b04a5c","SOURCE":"passive_dhcp_lease","_UID":"0","_PID":"110","EVENT":"ip_changed","IFACE":"eth1","__MONOTONIC_TIMESTAMP":"870622180","NEW_VALUE":"192.168.110.51","PRIORITY":"5","_RUNTIME_SCOPE":"system","_EXE":"/usr/local/bin/lan-sentinel","_CMDLINE":"/usr/local/bin/lan-sentinel daemon run --config /etc/lan-sentinel/config.yaml","__REALTIME_TIMESTAMP":"1792225807921724","OLD_VALUE":"192.168.110.50","IP":"192.168.110.51","_MACHINE_ID":"db73e1dc4717484082a7fd9e8d45afac","_HOSTNAME":"plant-edge-01"}
…
```

The journal keeps what journald's size limits allow; the database keeps events for two years. For anything older than the journal, use `events list` and `hosts history`.

### Clock synchronisation

Boxes without a real-time clock boot with the wrong time until NTP has synchronised it. Events written meanwhile are marked: `*` in CLI output (*written before the system clock was synchronised: the time may be off*), `CLOCK_SYNC=unsynced` in the journal, `clock_sync` in JSON. A replay marks every event `?` (*unknown*), as in the site-capture examples. `daemon status` shows the current state on its `Clock:` line.

## 12. Active discovery

Passive capture finds devices that talk. Active discovery also finds the ones that only answer: many PLCs and I/O modules stay silent until polled. It is off by default, and it only ever probes networks you list.

**Before you enable it.** Review the site's devices with whoever runs them. List any fragile device under `exclude`. Start with the ARP sweep alone; add ICMP, TCP ports and UDP probes later.

```yaml
interfaces:
  - name: eth0
    passive: { enabled: true }
    active:
      enabled: true
      networks: [172.31.240.0/24]   # explicitly listed, /24 or narrower
      exclude: [172.31.240.1]       # never probed
active:
  arp:  { enabled: true, interval: 5m }
  icmp: { enabled: true, interval: 10m }
  tcp:
    enabled: true
    interval: 5m
    targets: [{ port: 502, name: modbus, timeout: 750ms }]   # timeout is required
```

`sudo lan-sentinel config reload` applies it; no restart is needed.

**What it sends, and the limits.**

| Probe | Sends | To |
| --- | --- | --- |
| ARP sweep | one ARP request per address | every address of the listed networks, less excludes |
| ICMP | one echo request | known hosts only |
| TCP | a plain connect, closed at once, no payload | known hosts only, on the configured ports |
| UDP | one NTP request, or one EtherNet/IP ListIdentity | known hosts only |

| Limit | Default |
| --- | --- |
| All probing together | 20 packets per second |
| ARP / ICMP / UDP | 10 / 5 / 5 packets per second |
| TCP | 5 connects per second, at most 4 at a time per interface and 1 per host |
| Any one device | at most one probe per second |
| Network size | /24 or narrower, unless `allow_wide_scan` is set |
| A device that does not answer | probed less often (back-off); never marked offline |

There is no SYN scanning, port sweeping, UDP port scanning or IPv6 sweeping.

**Preview, then scan on demand.** `scan plan` sends nothing; it shows the targets, the packets and how long a scan takes:

```
$ sudo lan-sentinel scan plan --interface eth0 --arp --tcp 502
Interface:  eth0    Networks: 172.31.240.0/24
Targets:    252 to sweep (excluded: 172.31.240.1), 3 known hosts
Probes:     arp; tcp/502
Rates:      arp 10 pps, tcp 5 connects/s (≤4 per interface, ≤1 per host); global cap 20 pps
Estimate:   252 ARP requests, 3 TCP connects (at most 3 packets each), at most ~273 packets
Duration:   estimated typical ~28 s, estimated no-response ~28 s
Assumes:    probes leave paced at the rates above, at most 20 packets/s in all (a TCP connect counts 3), and at least 1s apart per target; sending, connecting and answering take no time
            typical: known hosts answer at once; most swept addresses are empty, so the ARP sweep waits its 1s reply timeout once, after its last request
            no-response: nothing answers, so every phase waits out its reply timeout once (ARP 1s, tcp/502 750ms)
            ICMP, TCP and UDP counts use the hosts known now; hosts that first answer the sweep are probed too, which adds to a run
Verdict:    ALLOWED
```

`scan run` takes the same options and runs it within the same limits, recorded as `SCAN_STARTED` and `SCAN_COMPLETED` with your user name:

```
$ sudo lan-sentinel scan run --interface eth0 --network 172.31.240.0/27 --arp --icmp --tcp 502
Interface:  eth0    Networks: 172.31.240.0/27
Targets:    28 to sweep (excluded: 172.31.240.1), 3 known hosts
Probes:     arp; icmp; tcp/502
…
Verdict:    ALLOWED
Scanning (estimated typical duration ~6 s) ...
eth0: done in 9 s; 3 hosts answered ARP
  arp      25 no_reply, 3 reply
  icmp     3 reply
  tcp/502  1 OPEN, 2 REFUSED
```

`--network` must lie inside the interface's configured networks. Probe results per host and port:

```
$ sudo lan-sentinel services list
IP             MAC                IFACE  PORT     STATE    LAST CHECK
172.31.240.20  00:0e:8c:00:00:20  eth0   502/tcp  REFUSED  0s ago
172.31.240.10  00:1b:1b:00:00:10  eth0   502/tcp  OPEN     0s ago
172.31.240.30  00:30:de:00:00:30  eth0   502/tcp  REFUSED  0s ago
```

`REFUSED` means the device answered that nothing listens there; it still counts as the device being present. `TIMEOUT` and `UNREACHABLE` count for nothing.

### The kill switch

`active disable` stops every probe at once, on every interface, and stays in force across restarts until `active enable`. Use it before maintenance on sensitive equipment, or whenever probing is in doubt. The reason is required and recorded:

```
$ sudo lan-sentinel active disable --reason 'PLC firmware update on line 2'
Active discovery disabled (persists across restarts). Clear with: lan-sentinel active enable

$ sudo lan-sentinel scan plan --interface eth0
…
Verdict:    REFUSED
  - active discovery is disabled by the kill switch (PLC firmware update on line 2)
[exit 2]

$ sudo lan-sentinel daemon status
…
Active:     DISABLED (PLC firmware update on line 2)
…
         icmp       disabled    active discovery is disabled by the kill switch
         identify   disabled    active discovery is disabled by the kill switch
…
         tcp        disabled    active discovery is disabled by the kill switch

$ sudo lan-sentinel active enable --reason 'firmware update done'
Active discovery enabled.
```

Passive capture keeps running while the switch is set. Setting `LAN_SENTINEL_ACTIVE_DISABLED=1` in the unit's environment forces the switch on at start-up, whatever the database says; `active enable` then refuses until it is removed.

## 13. Identification probes

Identification probes ask a device about itself: they send a payload, unlike discovery. They are a separate opt-in per interface, only reach hosts already known, and run once per device (per MAC). The probes are `modbus` (FC 43/14 device identification), `http` (server and page title), `tls` (certificate), `snmp` (sysDescr, SNMPv2c with a community you configure), `ssh-banner`, `telnet` and `ftp`.

```yaml
interfaces:
  - name: eth0
    active:
      enabled: true
      networks: [172.31.240.0/24]
      identify: [{ name: http }, { name: modbus }]   # only these, on this interface
```

Every hour the daemon looks for hosts it has not tried. A host is eligible only when its address has exactly one holder and no conflict, it was seen within the last 30 minutes (`active.identify.host_max_age`), and it is not flagged as a proxy-ARP device; others are skipped and counted in `lan_sentinel_identify_suppressed_total`. `identify run` repeats a probe on demand (the same rules apply, apart from the once-per-device latch), and is recorded as `IDENTIFY_RAN`:

```
$ sudo lan-sentinel identify run 172.31.240.20 --probe http
identify http on 00:0e:8c:00:00:20: ok

$ sudo lan-sentinel hosts show 172.31.240.20
Host ID:     01a148ff-91b0-77ea-9027-fdbb679aa6a4
Interface:   eth0
MAC:         00:0e:8c:00:00:20  Siemens AG
State:       ACTIVE
First seen:  2026-10-17 08:34:30
Last seen:   2026-10-17 08:35:20

Addresses:
  172.31.240.20    2026-10-17 08:34:30 → open   sources: passive_arp, arp_scan, icmp_scan, kernel_neighbor, passive_ipv4, tcp_connect, identify_probe

Services:
  tcp/80   OPEN        0s ago
  tcp/502  REFUSED     1s ago

Identification:
  oui   (0.70)  50s ago
    manufacturer  Siemens AG
  http  (0.50)  0s ago
    title         Line 2 HMI
```

`--probe all` runs every probe the interface enables; `--probe http,tls` a list. TLS sends no server name unless asked (`--sni NAME`, or `{name: tls, sni: auto}` to send the host's DNS name). `snmp` needs a community on the interface entry (`{name: snmp, community: ...}`) or under `active.identify.probes.snmp`; there is no built-in default. Test each probe on one device of a type before enabling it for a site ([`TEST_PLAN.md`](TEST_PLAN.md) I1).

## 14. Reading the database without the daemon

When the daemon is stopped or will not start, `--offline` reads the database directly, read-only. Read commands work; commands that change something or need the daemon (`scan run`, `active …`, `hosts set`, `watch`, `daemon status`, `config reload`) refuse.

```
$ sudo lan-sentinel --offline hosts list
notice: /data/lan-sentinel/hosts.db has no WAL (daemon not running); reading it as it is. If the daemon starts meanwhile, re-run.
MAC                IP              HOSTNAME       VENDOR                  DEVICE  IFACE  STATE   LAST SEEN  DESCRIPTION
00:0e:8c:11:22:33  192.168.110.20  HMI-LINE3      Siemens AG              -       eth1   ACTIVE  3m ago     
…
```

To take the database to another machine, stop the daemon first (a clean stop folds the write-ahead log into the file), copy `/data/lan-sentinel/hosts.db`, and read it with `lan-sentinel --offline --db hosts.db ...` on any Linux machine. While the daemon runs, copy `hosts.db`, `hosts.db-wal` and `hosts.db-shm` together. `db info` shows the schema version, sizes and row counts; `db check` runs an integrity check.

## 15. Scripts, monitoring and metrics

Lists (`hosts list`, `hosts history`, `events list`, `observations list`, `services list`, `interfaces list`, `dhcp servers`) take `-o json`, `-o jsonl` or `-o csv`; single records (`hosts show`, `hosts find`, `daemon status`, `db info`) take `-o json`:

```
$ sudo lan-sentinel hosts list -o csv
MAC,IP,HOSTNAME,VENDOR,DEVICE,IFACE,STATE,LAST SEEN,DESCRIPTION
00:0e:8c:00:00:20,172.31.240.20,,Siemens AG,,eth0,ACTIVE,2026-10-17T08:39:26Z,
00:1b:1b:00:00:10,172.31.240.10,,Siemens AG,,eth0,ACTIVE,2026-10-17T08:39:26Z,
00:30:de:00:00:30,172.31.240.30,,WAGO Kontakttechnik GmbH,,eth0,ACTIVE,2026-10-17T08:39:26Z,
```

Times in JSON and CSV are RFC 3339 UTC. Exit codes: 0 success, 1 nothing found (`hosts find`, `hosts show`) or degraded (`daemon status`), 2 error or refused, 3 daemon not reachable, 64 usage error. `--quiet` prints nothing and leaves the exit code, for example in a check:

```bash
sudo lan-sentinel daemon status --quiet || echo "lan-sentinel needs attention"
sudo lan-sentinel hosts find 192.168.110.51 --quiet && echo "address in use"
```

**Prometheus.** With `api: { listen: 127.0.0.1:9734 }` the daemon serves `/metrics` on the loopback address (a restart applies it). Labels never contain MACs, IPs or names:

```
$ curl -s http://127.0.0.1:9734/metrics | grep -v '^#'
lan_sentinel_hosts{interface="eth0",presence="ACTIVE"} 3
lan_sentinel_hosts{interface="eth0",presence="RECENT"} 0
lan_sentinel_hosts{interface="eth0",presence="STALE"} 0
lan_sentinel_hosts{interface="eth0",presence="MISSING"} 0
lan_sentinel_dhcp_servers{interface="eth0",status="allowed"} 0
lan_sentinel_dhcp_servers{interface="eth0",status="unexpected"} 0
lan_sentinel_dhcp_servers{interface="eth0",status="unchecked"} 0
lan_sentinel_events_total{type="ACTIVE_DISABLED"} 1
…
lan_sentinel_observations_total{source="passive_arp"} 4
…
```

Worth alerting on: `lan_sentinel_events_total` for `DUPLICATE_IP_DETECTED`, `DHCP_SERVER_UNEXPECTED` and `MAC_MOVED` increasing, `lan_sentinel_capture_drops_total` increasing, and the database size. The full list is in [`API.md`](API.md#metrics). The local REST API on `/run/lan-sentinel/api.sock` is the integration point for other software on the box ([`API.md`](API.md)).

## 16. Troubleshooting

| Symptom | Check |
| --- | --- |
| `daemon status` exits 3, *is lan-sentinel running?* | `systemctl status lan-sentinel` and `journalctl -u lan-sentinel -b`. An invalid configuration stops the daemon at start-up and the journal names the key and line. `--offline` reads the database meanwhile |
| No hosts appear | The interface name in the config matches `ip link`; `capture` is `running` in `daemon status`; the port is not isolated. Quiet networks take a while: enable the ARP sweep, or wait for devices to talk |
| Every host goes `STALE` | Capture stopped or the link is down: `daemon status` (collector states) and `interfaces list` (state); look for `INTERFACE_DOWN` |
| A device is never seen | It may never broadcast. On a switched port only broadcast, multicast and the box's own traffic are visible: use a mirror port, or active discovery |
| No SSDP or WS-Discovery information | Switches with IGMP snooping keep multicast from ports that have not joined the group; the box never joins (it never transmits passively). A mirror port sees it ([`TEST_PLAN.md`](TEST_PLAN.md) B9) |
| `NEIGHBOR` is empty | The switch does not run LLDP or CDP on that port, or the box was moved recently (it shows while the advertisement's TTL holds) |
| DHCP server list empty | On a switched port, replies unicast to other clients are invisible. A mirror port, or a client renewing on the box's segment, shows them |
| Events marked `*` | The clock was not synchronised when they were written: check chrony (`chronyc tracking`) |
| `the daemon is busy, so the change is not confirmed` | The daemon was too backlogged to confirm an operator action within 8 seconds (exit 2, API status 503). The change may still be recorded: check `events list` before you repeat it |
| `scan plan` says `REFUSED` | Each reason is listed: kill switch, active discovery off on the interface, a network outside the configured ones, the /24 guard |
| `active discovery does not run in replay mode` | The configuration replays a capture; there is nothing to probe |
| `database schema version N is newer than this binary supports` | An older binary on a database a newer release migrated. Upgrade again, or restore the copy taken before the upgrade |
| `DATABASE_RECREATED` in the events | The database failed its start-up integrity check (power loss on a worn SD card, say). It was kept as `hosts.db.corrupt-<time>` beside the new one |
| Debian 11: `Unknown key name 'PrivateIPC'` | Expected: systemd 247 predates the setting, and the unit runs without it |

Logs for one start-up, with the daemon's own messages at debug level: set `logging: { level: debug }` and `sudo lan-sentinel config reload`, then set it back. Observations are never logged, even at debug level.

## 17. Upgrading and removing

Upgrade with the same commands as the install ([README](../README.md#install-the-latest-release)); copy the database first so you can roll back ([`deploy/README.md`](../deploy/README.md#upgrade-and-rollback), which also lists what changed between releases for operators).

To remove LAN Sentinel:

```bash
sudo systemctl disable --now lan-sentinel
sudo rm /etc/systemd/system/lan-sentinel.service /usr/local/bin/lan-sentinel
sudo systemctl daemon-reload
```

This keeps the configuration (`/etc/lan-sentinel`) and the history (`/data/lan-sentinel`); remove those directories too if they are no longer needed.
