#!/usr/bin/env python3
"""
HomeSOC — Network discovery scanner.

Runs `arp-scan` against the local subnet, parses results, and writes
asset + scan + sighting records to the HomeSOC SQLite database.

Flags any MAC address never seen before so the operator can review it.

Usage:
    sudo python3 scanners/discovery.py
    sudo python3 scanners/discovery.py --interface eth0 --db db/homesoc.db

Requires:
    arp-scan installed and runnable with sudo.
    SQLite database initialized from db/schema.sql.
"""

import argparse
import os
import re
import sqlite3
import subprocess
import sys
import time
import socket
from datetime import datetime, timezone
from pathlib import Path

# Constants
SELF_MAC = "b8:27:eb:f0:9d:06"
SELF_OWNER = "HomeSOC Raspberry Pi"
SELF_VENDOR = "Raspberry Pi Foundation"
SELF_DEVICE_TYPE = "server"

# regular expression module for parsing arp-scan output.
ROW_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<mac>[0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+"
    r"(?P<vendor>.+?)\s*$",
    re.IGNORECASE,
)


# Tools
def get_time() -> str:
    """Return current UTC time as ISO-8601 string (matches schema convention)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def get_self_device() -> dict:
    """
    Return a device dict for this Pi, matching the shape from parse_arp_scan:{"ip": ..., "mac": ..., "vendor": ...}
    """
    return {
        "ip": get_local_ip(),
        "mac": SELF_MAC,
        "vendor": SELF_VENDOR,
    }


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def run_arp_scan(interface: str) -> tuple[str, int]:
    """Run arp-scan and return (stdout, duration_ms)."""
    cmd = [
        "arp-scan",
        "--interface",
        interface,
        "--localnet",
    ]  # arpscan command
    start = time.monotonic()
    result = subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    duration_ms = int((time.monotonic() - start) * 1000)
    return result.stdout, duration_ms  # Captures Output, Duration


def parse_arp_scan(output: str) -> list[dict]:
    """
    Turn arp-scan output into a list of devices.
    Each device has an IP, MAC, and vendor.
    """
    devices = []
    seen_macs: set[str] = set()
    for line in output.splitlines():
        match = ROW_RE.match(line.strip())
        if not match:  # Skip lines that are not device rows
            continue
        mac = match.group("mac").lower()
        if mac in seen_macs:  # Skip duplicate devices from the same scan
            continue
        seen_macs.add(mac)
        devices.append(
            {
                "ip": match.group("ip"),
                "mac": mac,
                "vendor": match.group("vendor").strip(),
            }
        )
    return devices


# Database
def save_device(conn: sqlite3.Connection, device: dict, now: str) -> tuple[int, bool]:
    """
    Insert a new asset or update an existing one (by MAC).
    Returns (asset_id, is_new_asset).
    """
    cur = conn.execute(
        "SELECT id, first_seen FROM assets WHERE mac = ?", (device["mac"],)
    )
    row = cur.fetchone()

    if row is None:
        is_self = device["mac"] == SELF_MAC  # Auto-approve the Pi
        cur = conn.execute(
            """
            INSERT INTO assets (mac, ip, vendor, owner, device_type,
                                is_known, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device["mac"],
                device["ip"],
                device["vendor"],
                SELF_OWNER if is_self else None,
                SELF_DEVICE_TYPE if is_self else None,
                1 if is_self else 0,
                now,
                now,
            ),
        )
        return cur.lastrowid, True

    asset_id = row[0]  # Device already exists, so update the latest info.
    conn.execute(
        """
        UPDATE assets
           SET ip = ?, vendor = ?, last_seen = ?
         WHERE id = ?
        """,
        (device["ip"], device["vendor"], now, asset_id),
    )
    return asset_id, False


def save_scan(
    conn: sqlite3.Connection,
    started: str,
    finished: str,
    duration_ms: int,
    host_count: int,
) -> int:
    """Save one scan run to the database."""
    cur = conn.execute(
        """
        INSERT INTO scans (started_at, finished_at, duration_ms,
                           host_count, scan_type, source)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (started, finished, duration_ms, host_count, "arp-scan", "discovery.py"),
    )
    return cur.lastrowid


def save_seen_device(
    conn: sqlite3.Connection, scan_id: int, asset_id: int, ip: str, seen_at: str
) -> None:
    """Save that a device was seen during a scan."""
    conn.execute(
        """
        INSERT INTO sightings (scan_id, asset_id, ip, seen_at)
        VALUES (?, ?, ?, ?)
        """,
        (scan_id, asset_id, ip, seen_at),
    )


# Main
def main() -> int:
    parser = argparse.ArgumentParser(description="HomeSOC discovery scanner")
    parser.add_argument(
        "--interface",
        default="eth0",
        help="Network interface to scan from (default: eth0)",
    )
    parser.add_argument(
        "--db",
        default="db/homesoc.db",
        help="Path to SQLite database (default: db/homesoc.db)",
    )
    args = parser.parse_args()

    # arp-scan needs sudo to work correctly
    if os.geteuid() != 0:
        print(
            "ERROR: this script must be run with sudo (arp-scan needs raw sockets).",
            file=sys.stderr,
        )
        return 2

    db_path = Path(args.db)
    if not db_path.exists():
        print(
            f"ERROR: database not found at {db_path}. "
            f"Initialize it with: sqlite3 {db_path} < db/schema.sql",
            file=sys.stderr,
        )
        return 2

    started_at = get_time()
    print(f"[{started_at}] Starting discovery scan on {args.interface}...")

    try:
        output, duration_ms = run_arp_scan(args.interface)
    except subprocess.CalledProcessError as e:
        print(
            f"ERROR: arp-scan failed (exit {e.returncode}): {e.stderr}", file=sys.stderr
        )
        return 1
    except subprocess.TimeoutExpired:
        print("ERROR: arp-scan timed out after 60s.", file=sys.stderr)
        return 1

    devices = parse_arp_scan(output)
    devices.insert(0, get_self_device()) # adds pi to the list of devices 
    finished_at = get_time()

    conn = sqlite3.connect(db_path)
    try:
        with conn:
            scan_id = save_scan(
                conn, started_at, finished_at, duration_ms, len(devices)
            )
            new_assets: list[dict] = []
            for device in devices:
                asset_id, is_new = save_device(conn, device, finished_at)
                save_seen_device(conn, scan_id, asset_id, device["ip"], finished_at)
                if is_new and device["mac"] != SELF_MAC:
                    new_assets.append(device)
    finally:
        conn.close()

    # ---- Human-readable summary ----
    print(
        f"[{finished_at}] Scan complete in {duration_ms} ms. "
        f"{len(devices)} device(s) responded."
    )
    print(f"  Scan ID: {scan_id}")
    for d in devices:
        marker = " (self)" if d["mac"] == SELF_MAC else ""
        print(f"  {d['ip']:<15}  {d['mac']}  {d['vendor']}{marker}")

    if new_assets:
        print("")
        print(f"!! {len(new_assets)} NEW asset(s) detected (review required):")
        for d in new_assets:
            print(f"   - {d['mac']}  {d['ip']}  {d['vendor']}")
        print("")
        print(
            "   To approve: UPDATE assets SET is_known=1, owner='...', "
            "device_type='...' WHERE mac='...';"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())

