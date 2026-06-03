# HomeSOC

HomeSOC is a Raspberry Pi home network monitoring lab I built for my own home network. I made it to practice Linux, networking, automation, Python scripting, and security operations in a more realistic way.

Instead of just running tools manually, I wanted a project that keeps track of devices on my LAN, notices when something new shows up, collects router logs, and gives me a simple workflow for reviewing alerts.

This is a learning and portfolio project. It is not meant to be an enterprise SOC product, and it only runs on my own network.

## What's working

- **Network discovery** — `arp-scan` runs every 15 minutes using a systemd timer. It finds devices on the LAN and records their IP, MAC address, and vendor.
- **Asset inventory** — devices are stored in SQLite and tracked by MAC address so they can still be recognized even if their IP changes.
- **New device review** — new or unapproved devices are flagged for review instead of being ignored.
- **Self-registration** — the Pi identifies itself so it does not keep alerting on its own MAC address.
- **Router log collection** — my Flint 2 router forwards syslog to the Pi over UDP. `rsyslog` writes the logs to a per-host log file, and `logrotate` handles retention.
- **DHCP detection rule** — a watcher checks the router DHCP logs every 5 minutes. If a device that is not approved in the inventory gets an IP address, it writes an alert ticket in Markdown.
- **Alert deduplication** — the same unknown device does not keep creating repeat tickets.
- **Daily summary tool** — a command-line report pulls from SQLite, the systemd journal, and router logs to show scan activity, current devices, stale devices, router activity, recent alerts, and Pi health.
- **Runbook** — RB-001 documents how I investigate an unknown device. I have used it to review real device detections on my home network.
- **Vulnerability review** — I wrote a baseline review of my home network with findings, severity, and remediation. One finding was SSH password authentication on the Pi, which I fixed by switching to SSH key-based login.

## Planned

- Flask dashboard for viewing devices and alerts
- More detection rules, such as SSH brute-force attempts or possible port scans
- More runbooks, such as host offline and brute-force response
- Backups for the database and important config files
- Real-time notifications for alerts

## How it works

The Raspberry Pi sits on my home network and runs two scheduled jobs:

1. **Discovery scan every 15 minutes**  
   This actively scans the LAN with `arp-scan`, finds what devices are online, saves the results in SQLite, and flags anything new.

2. **DHCPACK watcher every 5 minutes**  
   This passively reads the router logs that are forwarded to the Pi. When a device gets an IP address through DHCP and it is not approved in the inventory, HomeSOC creates an alert ticket.

The two jobs help cover different situations. The active scan tells me what is online right now, while the DHCP watcher can catch a device when it joins the network between scans.

When a new device is detected, I follow RB-001. I check the router admin page, look up the MAC vendor, compare the active scan with the router logs, decide whether the device is mine, and then update the inventory and documentation.

## Example output

Daily summary example:

```text
=== HomeSOC Daily Summary ===
Generated:        2026-06-01 17:20 UTC
"Online" = seen in last:    30 min

--- Scan Activity ---
  Scans in last 24h: 97
  Most recent scan:  2026-06-01 17:14 UTC
  Average duration:  3188 ms

--- Asset Inventory ---
  Total assets:        14
  Unreviewed:          0
  Seen in last 30 min: 7

--- Router Log Highlights ---
  DHCPACKs in current log:           32
  New Wi-Fi stations in current log: 27

--- Monitor Host Health ---
  Pi uptime: up 3 days, 20 hours
  Throttle state: throttled=0x0
=== End of Daily Summary ===
```

Example alert ticket when an unapproved device gets a DHCP lease. The MAC and IP are masked for privacy:

```text
---
status: open
severity: low
detected_at: 2026-06-01T12:00:00-04:00
detected_by: dhcpack_watcher
asset_ip: 192.168.8.xxx
asset_mac: xx:xx:xx:xx:xx:xx
runbook: docs/runbooks/RB-001-unknown-device.md
---

# Unknown device joined the network

A device joined the LAN and received an IP through DHCP. Its MAC address is not marked as approved in the asset inventory. Follow RB-001 to investigate.
```

The scheduled jobs run as systemd timers:

```text
$ systemctl list-timers | grep homesoc
homesoc-dhcpack.timer    homesoc-dhcpack.service
homesoc-discovery.timer  homesoc-discovery.service
```

## Hardware

- Raspberry Pi 3 Model B v1.2 (`pi-monitor`)
- GL.iNet Flint 2 router
- Home LAN: 192.168.8.0/24

## Software

- Raspberry Pi OS
- Python 3
- SQLite
- arp-scan
- nmap
- rsyslog
- logrotate
- systemd timers
- Git

## Project structure

| Path | Purpose |
| ---- | ------- |
| `scanners/discovery.py` | Network discovery scanner |
| `alerts/dhcpack_watcher.py` | DHCP-based detection rule |
| `scripts/daily-summary.py` | Daily status report |
| `db/schema.sql` | SQLite database schema |
| `collectors/` | rsyslog and logrotate configs |
| `systemd/` | Service and timer files |
| `docs/asset-register.md` | Device inventory |
| `docs/network-diagram.png` | Network diagram |
| `docs/runbooks/` | Investigation and response procedures |
| `docs/vulnerability-reviews/` | Security review writeups |
| `evidence/` | Alert tickets and project evidence |
| `dashboard/` | Planned Flask dashboard |

## Network

![Home network](docs/network-diagram.png)

## Scope

This project only runs on my own home network. I am not scanning or monitoring networks that I do not own or control.

## Why I built it

I wanted a project that was more useful than just saying I ran Nmap or followed a tutorial. HomeSOC gives me a way to practice Linux administration, networking, monitoring, scripting, detection logic, documentation, and basic security operations on a real network that I actually use.

The main goal is to build the project piece by piece and show a realistic security workflow: discover devices, track them over time, detect changes, investigate alerts, document what happened, and improve the setup as I go.
