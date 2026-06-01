#!/usr/bin/env python3
"""
HomeSOC daily summary — one-screen operational status report.

Aggregates data from three sources:
  - SQLite (db/homesoc.db) for assets + scans
  - Systemd journal for new-asset alerts emitted by discovery.py
  - Flint 2 syslog at /var/log/remote/GL-MT6000.log for DHCP/Wi-Fi events

Run from anywhere:
    python3 scripts/daily-summary.py

Reading the Flint log requires being in the 'adm' group (one-time setup:
    sudo usermod -a -G adm brandon
    (log out and back in)
"""

import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Paths are computed relative to this script so it works regardless of cwd.
DB_PATH = Path(__file__).resolve().parent.parent / "db" / "homesoc.db"
FLINT_LOG = Path("/var/log/remote/GL-MT6000.log")

# Tunable windows
LOOKBACK_HOURS = 24
ONLINE_WINDOW_MIN = 30


def get_time() -> str:
    """Current UTC time as 'YYYY-MM-DD HH:MM:SS' (matches DB schema convention)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# Functions
def scan_activity(conn):
    """How many scans ran, when was the most recent, what's the average duration."""
    print("--- Scan Activity ---")
    cur = conn.execute(
        """
        SELECT COUNT(*), MAX(started_at), AVG(duration_ms)
        FROM scans
        WHERE started_at > datetime('now', ?)
        """,
        (f"-{LOOKBACK_HOURS} hours",),
    )
    count, most_recent, avg_ms = cur.fetchone()

    print(f"  Scans in last {LOOKBACK_HOURS}h: {count}")
    print(f"  Most recent scan:    {most_recent or 'none'} UTC")
    if avg_ms is not None:
        print(f"  Average duration:    {avg_ms:.0f} ms")
    else:
        print(f"  Average duration:    -")
    print()


def asset_inventory(conn):
    """Headline counts: total, unreviewed, currently online."""
    print("--- Asset Inventory ---")
    total = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    unreviewed = conn.execute(
        "SELECT COUNT(*) FROM assets WHERE is_known = 0"
    ).fetchone()[0]
    online = conn.execute(
        "SELECT COUNT(*) FROM assets WHERE last_seen > datetime('now', ?)",
        (f"-{ONLINE_WINDOW_MIN} minutes",),
    ).fetchone()[0]

    print(f"  Total assets:           {total}")
    print(f"  Unreviewed (is_known=0):{unreviewed:>3}")
    print(f"  Seen in last {ONLINE_WINDOW_MIN} min:  {online}")
    print()


def recently_seen(conn):
    """Devices observed within the online window, newest first."""
    print(f"--- Currently Online (last {ONLINE_WINDOW_MIN} min) ---")
    cur = conn.execute(
        """
        SELECT ip, mac, COALESCE(hostname, ''), COALESCE(owner, '-'), last_seen
        FROM assets
        WHERE last_seen > datetime('now', ?)
        ORDER BY last_seen DESC
        """,
        (f"-{ONLINE_WINDOW_MIN} minutes",),
    )
    rows = cur.fetchall()
    if not rows:
        print("  (no devices seen recently)")
    else:
        for ip, mac, hostname, owner, last_seen in rows:
            print(f"  {ip:<15} {mac:<18} {hostname:<25} {owner:<10} {last_seen} UTC")
    print()


def stale_devices(conn):
    """Devices not seen within the 24h lookback window, oldest first."""
    print(f"--- Not Seen in {LOOKBACK_HOURS}h ---")
    cur = conn.execute(
        """
        SELECT ip, mac, COALESCE(hostname, ''), COALESCE(owner, '-'), last_seen
        FROM assets
        WHERE last_seen < datetime('now', ?)
        ORDER BY last_seen ASC
        """,
        (f"-{LOOKBACK_HOURS} hours",),
    )
    rows = cur.fetchall()
    if not rows:
        print(f"  (all known devices seen in last {LOOKBACK_HOURS}h)")
    else:
        for ip, mac, hostname, owner, last_seen in rows:
            print(
                f"  {ip:<15} {mac:<18} {hostname:<25} {owner:<10} last seen {last_seen} UTC"
            )
    print()


def flint_highlights():
    """Count DHCPACKs and new Wi-Fi station events in the current Flint log.

    Note: only counts the current (un-rotated) log file. Older events that
    have been logrotated out are not counted. Good enough for v1.
    """
    print(f"--- Router Log Highlights ---")
    if not FLINT_LOG.exists():
        print(f"  (Flint log not found at {FLINT_LOG})")
        print()
        return

    try:
        dhcpacks = 0
        new_stations = 0
        with FLINT_LOG.open() as f:
            for line in f:
                if "DHCPACK" in line:
                    dhcpacks += 1
                elif "New Sta:" in line:
                    new_stations += 1
        print(f"  DHCPACKs in current log:           {dhcpacks}")
        print(f"  New Wi-Fi stations in current log: {new_stations}")
    except PermissionError:
        print(f"  (Permission denied reading {FLINT_LOG})")
        print(f"  Fix: sudo usermod -a -G adm brandon, then log out and back in")
    print()


def recent_alerts():
    """Find any NEW-asset banner lines emitted by discovery.py in the last 24h."""
    print(f"--- New-Asset Alerts (last {LOOKBACK_HOURS}h) ---")
    try:
        result = subprocess.run(
            [
                "journalctl",
                "-u",
                "homesoc-discovery.service",
                "--since",
                f"{LOOKBACK_HOURS} hours ago",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        matching = [
            line
            for line in result.stdout.splitlines()
            if "NEW asset(s) detected" in line
        ]
        if not matching:
            print("  (no new-asset alerts)")
        else:
            for line in matching:
                print(f"  {line}")
    except FileNotFoundError:
        print("  (journalctl not available)")
    except subprocess.CalledProcessError as e:
        print(f"  (journalctl error: {e})")
    print()

def host_health():
    """Show this Pi's own uptime and recent throttle status."""
    print("--- Monitor Host Health ---")
    try:
        result = subprocess.run(
            ["uptime", "-p"], capture_output=True, text=True, check=True
        )
        print(f"  Pi uptime: {result.stdout.strip()}")
    except subprocess.CalledProcessError:
        print(f"  Pi uptime: (uptime command failed)")

    # vcgencmd reports thermal/voltage history since boot
    try:
        result = subprocess.run(
            ["vcgencmd", "get_throttled"], capture_output=True, text=True, check=True
        )
        # Output is like "throttled=0x0" (healthy) or non-zero (had issues)
        print(f"  Throttle state: {result.stdout.strip()}")
    except (FileNotFoundError, subprocess.CalledProcessError):
        # vcgencmd is Pi-specific; harmless to skip on other systems
        pass
    print()


# Main
def main() -> int:
    print("=== HomeSOC Daily Summary ===")
    print(f"Generated:        {get_time()} UTC")
    print(f"Lookback window:  {LOOKBACK_HOURS}h")
    print(f"\"Online\" = seen in last:    {ONLINE_WINDOW_MIN} min")
    print()

    if not DB_PATH.exists():
        print(f"ERROR: database not found at {DB_PATH}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(DB_PATH)
    try:
        scan_activity(conn)
        asset_inventory(conn)
        recently_seen(conn)
        stale_devices(conn)
        flint_highlights()
        recent_alerts()
        host_health()
    finally:
        conn.close()

    print("=== End of Daily Summary ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())

