# HomeSOC Splunk integration

HomeSOC runs natively on a Raspberry Pi. An Ubuntu Server VirtualBox VM runs Splunk Enterprise. The existing Flask dashboard, SQLite inventory, per-host syslog, Markdown alerts, and response runbooks remain in place.

## Systems and data flow

| System | Address | Role |
| --- | --- | --- |
| pi-monitor | 192.168.8.165 | HomeSOC, inventory, router syslog, local detectors, auth-log sender |
| homesoc-splunk | 192.168.8.239 | Ubuntu Server VM, Splunk Enterprise, HTTPS HEC |
| Windows management PC | 192.168.8.119 | SSH and Splunk web access |

The Pi reads new complete lines from `/var/log/auth.log` and sends JSON events to `https://192.168.8.239:8088/services/collector/event`. Splunk stores them in the `homesoc` index. A separate local SSH detector creates Markdown tickets in `evidence/alerts/`. Splunk alerts and HomeSOC cases are separate workflows; Splunk does not automatically create HomeSOC incidents.

The VM was allocated four vCPUs and approximately 8 GiB RAM. Splunk runs under the dedicated `splunk` account with `Splunkd.service` enabled at boot. HomeSOC does not use Docker.

## Sender and credentials

- Program: `siem/forward_auth.py`
- Service: `homesoc-auth-splunk.service`
- Timer: `homesoc-auth-splunk.timer`, approximately every two minutes
- Certificate trusted by the Pi: `~/.config/homesoc/splunk-hec.crt`
- Private token file: `~/.config/homesoc/splunk-hec.token`, mode 600
- Private checkpoint: `~/.local/state/homesoc-siem/auth-checkpoint.json`

The sender verifies HTTPS certificate trust and hostname/IP identity. The custom HEC certificate has SAN entries for `homesoc-splunk` and `192.168.8.239`. Its SHA-256 fingerprint was compared on the VM and Pi before use. The certificate expires October 9, 2027, at 19:58:56 UTC; renew it and update the Pi's trusted certificate before expiry. The private certificate key stays on the VM.

The sender starts at the end of the log on its first normal run. It saves its checkpoint after HEC accepts the submitted batches. Retries may duplicate an already accepted batch; events include a stable `event_id`, and searches use `dedup event_id`. HEC acceptance confirms receipt, not a guarantee of exactly-once indexing.

If the Windows host or VM is off, delivery fails and the checkpoint stays unchanged. The timer retries later. Recovery depends on retaining the unread logs; the sender has no independent persistent event spool. It handles retained uncompressed rename rotation, but missing rotated logs and truncation require manual review.

Never commit tokens, private keys, private checkpoints, session keys, or incident databases. Do not include token screenshots in documentation.

## VM firewall

Verified UFW status: active, deny incoming, allow outgoing, routed traffic disabled.

| Port / TCP | Allowed source | Purpose |
| --- | --- | --- |
| 22 | 192.168.8.119 | SSH management |
| 8000 | 192.168.8.119 | Splunk web |
| 8088 | 192.168.8.165 | HTTPS HEC |

No inbound rule was added for Splunk management port 8089. The firewall does not change HTTP into HTTPS: Splunk web currently uses HTTP on the private LAN. HEC forwarding uses verified HTTPS.

Confirm DHCP reservations for all three addresses before treating these source-specific firewall rules as stable. Pi-to-HEC delivery was verified after enabling UFW. Recheck a new Windows SSH connection and Splunk web access if those checks have not yet been recorded.

## Saved Splunk search

Saved alert: **HomeSOC — Repeated Invalid SSH Users**

```spl
index=homesoc source="/var/log/auth.log" earliest=-24h
| dedup event_id
| eval raw=mvindex(raw,0)
| rex field=raw "^(?<original_timestamp>\S+)"
| eval event_time=strptime(original_timestamp,"%Y-%m-%dT%H:%M:%S.%6N%:z")
| rex field=raw "sshd(?:-session)?\[\d+\]: Invalid user (?<username>\S+) from (?<src_ip>\S+) port (?<src_port>\d+)"
| where isnotnull(src_ip) AND event_time>=relative_time(now(),"-10m") AND event_time<=now()
| stats count AS invalid_user_attempts values(username) AS usernames BY host src_ip
| where invalid_user_attempts>=5
```

Settings verified in Splunk web:

- Private saved alert, enabled in the Search app.
- Cron: `*/2 * * * *`.
- Search range: last 24 hours through now; the SPL narrows source event timestamps to the last ten minutes.
- Trigger when result count is greater than zero; per-result action.
- Suppression: ten minutes, grouped by `host,src_ip`.
- Action: Add to Triggered Alerts, Medium severity.

Find executions under **Activity → Triggered Alerts**. The search counts invalid usernames only. It does not cover authentication failures for existing accounts.

The sender's Splunk `_time` represents forwarding time. This search extracts the timestamp from the original log instead. Events forwarded after more than ten minutes offline will not trigger this current-window rule, even though they may remain searchable. Historical correlation needs a separate search.

A private report named **HomeSOC — SSH Authentication Events** was also saved for manual investigation.

## Native detection and case handling

The local `homesoc-sshbrute.timer` runs approximately every five minutes. The watcher retains recent invalid-user attempts in its existing ignored checkpoint, so three attempts in one run plus two in another can meet the five-in-ten-minute threshold. Eight regression tests passed on the Pi, including cross-run counting, expiry, cursor migration, partial-line retry, and duplicate suppression.

An open source Markdown ticket suppresses additional tickets for that IP. Detected bursts are consumed from the recent-event buffer so resolving a source ticket does not replay the same burst. The local watcher does not recover unread entries from rotated files; its rotation handling remains a limitation.

For new devices, arp-scan updates SQLite and emits a discovery warning. The separate DHCPACK watcher generates unknown-device Markdown tickets from router syslog when the MAC is not marked known. Inventory presence alone does not imply a dashboard alert ticket.

The dashboard stores incident ownership, status, notes, resolution, and history separately from detector tickets. Opening the create-incident form does not save an incident; saving does. Resolving the dashboard case currently does not resolve the source Markdown ticket. Update both during closure. For an approved device, also mark its inventory record known to prevent future unknown-device tickets.

The Flask dashboard is LAN-accessible and does not currently provide authenticated user accounts. This setup has not been published as a public dashboard.

## Validation performed on October 9, 2026

1. HEC health returned `HEC is healthy`; a connection-test event was accepted and found in Splunk.
2. A second SSH connection produced real authentication events. The sender accepted them and the events were found in Splunk.
3. The sender timer was enabled and successfully sent events automatically.
4. Five controlled invalid-user attempts from the Windows PC triggered the Splunk search.
5. After resolving an older open source ticket, another five-attempt test produced a new local SSH ticket at 16:47 EDT. The corresponding test was also observed in Splunk.
6. The controlled test was recorded as authorized activity, and the incident and source ticket were resolved.
7. The cross-run watcher patch passed eight tests and was committed on the Pi.
8. After UFW was enabled, HEC accepted two events from the Pi.
9. The VM's DHCPACK ticket was found, confirming that its unknown-device detection had occurred. Its parser matched the router log, and the VM was subsequently approved in inventory.

The controlled SSH events are real lab activity, not fabricated sample data. A detection of this deliberately generated behavior is a true positive with an authorized/benign disposition, not evidence of an actual intrusion.

## Useful checks

On the Pi:

```bash
systemctl list-timers homesoc-auth-splunk.timer homesoc-sshbrute.timer homesoc-dhcpack.timer --no-pager
sudo journalctl -u homesoc-auth-splunk.service -n 20 --no-pager
sudo journalctl -u homesoc-sshbrute.service -n 20 --no-pager
python3 -m unittest discover -s siem/tests -v
python3 -m unittest discover -s alerts/tests -v
```

On the VM:

```bash
systemctl is-enabled Splunkd.service
sudo systemctl status Splunkd.service --no-pager
sudo ufw status verbose
```

## Remaining work

- Confirm DHCP reservations and record Windows SSH/web checks after UFW enablement.
- Plan certificate renewal and verify Ubuntu/Splunk update procedures.
- Review the trial license: Splunk displayed a warning that this scheduled search will not run after the Enterprise trial expires. The native Pi detector remains separate from Splunk scheduling.
- Add valid-account failed-authentication detection with separate validation.
- Consider forwarding router logs and inventory events; the current sender forwards auth.log only.
- Consider authenticated dashboard access and coordinated case/source-ticket closure.
- Test a VM outage and recovery deliberately, including retained-log limits.
