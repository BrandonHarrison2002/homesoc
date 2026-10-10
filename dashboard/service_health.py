"""Read fixed HomeSOC systemd properties; never start, stop, or edit units."""
from datetime import datetime, timezone
import os
import re
import subprocess
import time

# Warning thresholds allow normal interval and runtime variation.
JOBS = (
    ("Discovery", "homesoc-discovery", "Every 15 minutes", 45 * 60),
    ("DHCP detector", "homesoc-dhcpack", "Every 5 minutes", 15 * 60),
    ("SSH detector", "homesoc-sshbrute", "Every 5 minutes", 15 * 60),
    ("Splunk sender", "homesoc-auth-splunk", "About every 2 minutes", 10 * 60),
    ("Verified backup", "homesoc-backup", "Daily around 03:15 (Pi local time)", 30 * 60 * 60),
)
UNITS = tuple(base + suffix for _, base, _, _ in JOBS for suffix in (".timer", ".service"))
PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "Result",
              "ExecMainStatus", "ExecMainStartTimestamp", "ExecMainExitTimestamp",
              "LastTriggerUSec", "NextElapseUSecRealtime", "NextElapseUSecMonotonic")


def parse_properties(output):
    units = {}
    for block in output.strip().split("\n\n"):
        values = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if values.get("Id") in UNITS:
            units[values["Id"]] = values
    return units


def read_units():
    command = ["systemctl", "--no-pager", "--timestamp=unix", "show", "--all",
               "--property=" + ",".join(PROPERTIES), *UNITS]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=4,
                                env={**os.environ, "LC_ALL": "C", "TZ": "UTC", "SYSTEMD_COLORS": "0"})
    except (OSError, subprocess.TimeoutExpired):
        return {}, "Systemd status is unavailable. Check access to the local system manager."
    # A missing unit can produce nonzero exit while other units still have properties.
    units = parse_properties(result.stdout)
    if not units:
        return {}, "Systemd returned no readable HomeSOC unit properties."
    return units, ("Some unit information could not be read." if result.returncode else "")


def timestamp(value):
    if not value or value in ("n/a", "0"):
        return None
    try:
        if value.startswith("@"):
            return datetime.fromtimestamp(float(value[1:]), timezone.utc)
        # Also accept UTC pretty output if a systemctl version keeps that format.
        match = re.fullmatch(r"\w{3} (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?) UTC", value)
        if match:
            return datetime.fromisoformat(match[1]).replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    return None


def monotonic_seconds(value):
    if not value or value in ("0", "infinity", "n/a"):
        return None
    if value.isdigit():
        return int(value) / 1_000_000
    scales = {"w": 604800, "d": 86400, "h": 3600, "min": 60,
              "s": 1, "ms": .001, "us": .000001, "µs": .000001}
    parts = re.findall(r"(\d+(?:\.\d+)?)(min|ms|us|µs|w|d|h|s)", value)
    if not parts or re.sub(r"\d+(?:\.\d+)?(?:min|ms|us|µs|w|d|h|s)", "", value).strip():
        return None
    return sum(float(amount) * scales[unit] for amount, unit in parts)


def formatted(value):
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if value else "Not available"


def assess(job, units, now, uptime):
    label, base, schedule, threshold = job
    timer = units.get(base + ".timer", {})
    service = units.get(base + ".service", {})
    start = timestamp(service.get("ExecMainStartTimestamp"))
    end = timestamp(service.get("ExecMainExitTimestamp"))
    trigger = timestamp(timer.get("LastTriggerUSec"))
    next_run = timestamp(timer.get("NextElapseUSecRealtime"))
    if next_run is None:
        mono = monotonic_seconds(timer.get("NextElapseUSecMonotonic"))
        if mono is not None and mono >= uptime:
            from datetime import timedelta
            next_run = now + timedelta(seconds=mono - uptime)
    row = dict(label=label, base=base, schedule=schedule,
               timer_state=timer.get("ActiveState", "unknown"),
               enabled=timer.get("UnitFileState", "unknown"),
               service_state=service.get("ActiveState", "unknown"),
               result=service.get("Result") or "Not recorded",
               exit_code=service.get("ExecMainStatus", "Not recorded"),
               last_start=formatted(start), last_finish=formatted(end),
               last_trigger=formatted(trigger), next_run=formatted(next_run),
               threshold_minutes=threshold // 60, issues=[])
    issues = row["issues"]
    if not timer or not service:
        row.update(status="Unknown", tone="unknown")
        issues.append("Status could not be read for one or both units.")
        return row
    if timer.get("LoadState") != "loaded" or service.get("LoadState") != "loaded":
        row.update(status="Needs attention", tone="warning")
        issues.append("A unit is missing, masked, or could not be loaded.")
        return row
    timer_active = timer.get("ActiveState") == "active"
    running = service.get("ActiveState") in ("activating", "active", "deactivating", "reloading")
    failed = (timer.get("ActiveState") == "failed" or service.get("ActiveState") == "failed"
              or (not running and service.get("Result") not in (None, "", "success")))
    if not timer_active:
        issues.append("Timer is not active; automatic runs are not scheduled normally.")
    if timer.get("UnitFileState") not in ("enabled", "enabled-runtime"):
        issues.append("Timer is not enabled for startup.")
    elif timer.get("UnitFileState") == "enabled-runtime":
        issues.append("Timer is enabled for this boot only.")
    if failed:
        issues.append("Systemd reports a failed job or timer. Inspect its journal.")
        row.update(status="Failed", tone="failure")
    elif running:
        row.update(status="Running" if not issues else "Needs attention", tone="running" if not issues else "warning")
        if start and (now - start).total_seconds() > threshold:
            issues.append("This run has lasted longer than the warning threshold.")
            row.update(status="Needs attention", tone="warning")
    elif start is None:
        issues.append("No service run is recorded in the current systemd state.")
        row.update(status="Waiting for first run" if uptime < threshold and not issues[:-1] else "Needs attention",
                   tone="pending" if uptime < threshold and not issues[:-1] else "warning")
    elif end is None or service.get("Result") != "success" or service.get("ExecMainStatus") != "0":
        issues.append("A successful completed run could not be confirmed.")
        row.update(status="Unknown" if not issues[:-1] else "Needs attention", tone="unknown" if not issues[:-1] else "warning")
    elif (now - end).total_seconds() < -60:
        issues.append("Last finish is in the future; check the Pi clock.")
        row.update(status="Needs attention", tone="warning")
    elif (now - end).total_seconds() > threshold:
        issues.append("No recent successful completion within the warning threshold.")
        row.update(status="Overdue", tone="warning")
    elif issues:
        row.update(status="Needs attention", tone="warning")
    else:
        row.update(status="Healthy", tone="healthy")
    return row


def snapshot():
    units, error = read_units()
    now = datetime.now(timezone.utc)
    uptime = time.monotonic()
    rows = [assess(job, units, now, uptime) for job in JOBS]
    return dict(rows=rows, checked_at=formatted(now), error=error,
                healthy=sum(row["tone"] == "healthy" for row in rows),
                attention=sum(row["tone"] in ("warning", "failure") for row in rows),
                unknown=sum(row["tone"] == "unknown" for row in rows))
