# Service health page

Open **Service Health** in the dashboard or `/health`. Refresh status reads the current systemd properties of five fixed timer/service pairs on the Pi:

| Job | Warning after no successful completion |
| --- | --- |
| Discovery | 45 minutes |
| DHCP detector | 15 minutes |
| SSH detector | 15 minutes |
| Splunk authentication sender | 10 minutes |
| Verified backup | 30 hours |

These are warning thresholds, not schedule changes. Backup still runs daily around 03:15 in the Pi's local timezone. Timestamps on this page are converted to UTC. Next trigger can be unavailable while a timer is inactive or its service is running.

## Reading the status

- **Healthy:** the timer is active and enabled persistently, and systemd records a recent successful service completion with exit code zero.
- **Running:** the service is currently starting, running, or stopping. An unusually long run is flagged for attention.
- **Failed:** systemd reports a failed timer/service or a non-successful last result.
- **Overdue / Needs attention:** timer inactivity, startup configuration, missing/unloadable units, old completions, or clock inconsistencies need inspection.
- **Waiting for first run:** no service run is recorded during the initial boot grace period.
- **Unknown:** readable status or a confirmed successful completion is unavailable. The page does not invent healthy values or substitute sample data.

Inactive oneshot services are normal after success. A sender accepting zero events or detector producing zero tickets can be successful: process completion is what this page checks. No journal text or secrets are displayed. Inspect on the Pi expands fixed `systemctl status` and `journalctl` commands for each job.

The backend runs one `systemctl show` command for fixed units and selected properties, without a shell or sudo, with a four-second timeout. No URL parameter chooses a unit. Page refresh does not start, stop, enable, or restart anything and does not modify SQLite, evidence, or checkpoints. Partial status and unavailable systemd are reported without crashing the page. There are no new dependencies or systemd units.

Systemd properties are not a durable run history and can reset after reboot or unit unloading. Thresholds assume the currently documented schedules; update them if schedules change. Healthy is process-level evidence, not proof of complete collection, correct detection, a reachable Splunk VM right now, valid Splunk licensing, or an off-Pi backup copy. Successful backup verification does not prove a complete machine rebuild. This page creates no health tickets or external notifications.

Tests use synthetic properties and temporary dashboard data. A live Pi/browser check is still required after installation. The health page follows the dashboard login gate and is accessed through its SSH tunnel. It adds no service-control permission. See [dashboard login](dashboard-login.md).

Systemd reference: https://manpages.debian.org/bookworm/systemd/systemctl.1.en.html
