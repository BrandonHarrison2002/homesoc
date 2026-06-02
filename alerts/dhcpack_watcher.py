#!/usr/bin/env python3
"""
HomeSOC DHCPACK watcher

Usage:
    python3 alerts/dhcpack_watcher.py
    python3 alerts/dhcpack_watcher.py --test
"""

import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# Paths and constants
PROJECT_ROOT = Path(__file__).resolve().parent.parent

DB_PATH = PROJECT_ROOT / "db" / "homesoc.db"
ALERTS_DIR = PROJECT_ROOT / "evidence" / "alerts"
STATE_FILE = PROJECT_ROOT / "alerts" / ".watcher_state.json"
FLINT_LOG = Path("/var/log/remote/GL-MT6000.log")
RUNBOOK_PATH = "docs/runbooks/RB-001-unknown-device.md"

DHCPACK_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})\s+"
    r"\S+\s+"
    r"dnsmasq-dhcp\[\d+\]:\s+"
    r"DHCPACK\(\S+\)\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<mac>[0-9a-f]{2}(?::[0-9a-f]{2}){5})"
    r"(?:\s+\S+)?\s*$",
    re.IGNORECASE,
)


# Syslog parser
def parse_dhcpack(line: str) -> dict | None:
    """Parse one syslog line."""
    match = DHCPACK_RE.match(line)

    if not match:
        return None

    return {
        "timestamp": match.group("timestamp"),
        "ip": match.group("ip"),
        "mac": match.group("mac").lower(),
    }


# Database lookup
def is_unknown_mac(mac: str, conn: sqlite3.Connection) -> bool:
    """
    A MAC is considered unknown if:
      - it is not in the assets table, or
      - it exists but is not marked with is_known=1
    """
    cur = conn.execute(
        "SELECT is_known FROM assets WHERE mac = ?",
        (mac.lower(),),
    )

    row = cur.fetchone()

    if row is None:
        return True

    return row[0] != 1


# Alert ticket helpers
def filename_safe_timestamp(iso_ts: str) -> str:
    """Convert an ISO timestamp into something safe for a filename."""
    return iso_ts.replace(":", "-")


def existing_open_ticket(mac: str, alerts_dir: Path) -> Path | None:
    mac_compact = mac.lower().replace(":", "")
    pattern = f"*__dhcpack__{mac_compact}.md"

    for existing in alerts_dir.glob(pattern):
        try:
            content = existing.read_text()
        except OSError:
            continue

        # The ticket status should be in the YAML frontmatter at the top.
        head = "\n".join(content.splitlines()[:10])

        if "status: open" in head:
            return existing

    return None


# Alert ticket writer
def write_ticket(event: dict, alerts_dir: Path) -> Path | None:
    alerts_dir.mkdir(parents=True, exist_ok=True)

    existing = existing_open_ticket(event["mac"], alerts_dir)

    if existing is not None:
        return None

    mac_compact = event["mac"].replace(":", "")
    filename = (
        f"{filename_safe_timestamp(event['timestamp'])}" f"__dhcpack__{mac_compact}.md"
    )

    ticket_path = alerts_dir / filename

    content = f"""---
status: open
severity: low
detected_at: {event['timestamp']}
detected_by: dhcpack_watcher
asset_ip: {event['ip']}
asset_mac: {event['mac']}
runbook: {RUNBOOK_PATH}
---

# Unknown device joined the network

HomeSOC detected a device that joined the LAN and received an IP address
through DHCP.

The MAC address for this device is not currently marked as known in the
assets database with `is_known=1`.

## Evidence

- Detected at: {event['timestamp']} from the Flint router syslog
- IP assigned: {event['ip']}
- MAC address: {event['mac']}
- Detection source: DHCPACK event in `/var/log/remote/GL-MT6000.log`

## What this means

This does not automatically mean the device is malicious. It could be a new
phone, laptop, smart home device, guest device, or something that has not been
added to the HomeSOC asset inventory yet.

The goal is to make sure every device on the network is identified and approved.

## Runbook

Follow this runbook to investigate the device:

`{RUNBOOK_PATH}`

## Resolution

After the device has been reviewed, update the frontmatter status from:

`status: open`

to:

`status: resolved`

Then add notes below explaining what the device was and what action was taken.
"""

    ticket_path.write_text(content)
    return ticket_path


# State file handling
def load_state(state_path: Path) -> dict:
    """Load the watcher state file."""
    default_state = {
        "last_byte_offset": 0,
        "last_inode": None,
        "last_run": None,
    }

    if not state_path.exists():
        return default_state

    try:
        return json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError):
        print(
            f"WARNING: state file at {state_path} is corrupt; starting fresh.",
            file=sys.stderr,
        )
        return default_state


def save_state(state_path: Path, offset: int, inode: int) -> None:
    """
    Save the current log offset, inode, and run time.

    This uses an atomic write. It writes to a temporary file first, then replaces
    the real state file. That way, a crash should not leave behind a half-written
    state file.
    """
    state_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "last_byte_offset": offset,
        "last_inode": inode,
        "last_run": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    tmp = state_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    tmp.replace(state_path)


# Main log processing
def process_log(
    log_path: Path,
    state: dict,
    conn: sqlite3.Connection,
    alerts_dir: Path,
) -> tuple[int, int | None, int]:
    """Read new log content and create tickets for unknown devices.

    Returns:
      - new byte offset
      - current log inode
      - number of new tickets written
    """
    if not log_path.exists():
        print(f"WARNING: log file {log_path} does not exist yet.", file=sys.stderr)
        return state.get("last_byte_offset", 0), state.get("last_inode"), 0

    stat = log_path.stat()
    current_inode = stat.st_ino
    current_size = stat.st_size

    last_inode = state.get("last_inode")
    last_offset = state.get("last_byte_offset", 0)

    # If the inode changed, the log was probably rotated.
    # In that case, start reading from the beginning of the new file.
    if last_inode is None or last_inode != current_inode:
        start_offset = 0
    elif last_offset > current_size:
        # Same inode, but the file is smaller than before.
        # This should not normally happen, but starting over is safer.
        start_offset = 0
    else:
        start_offset = last_offset

    ticket_count = 0

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(start_offset)

        for line in f:
            event = parse_dhcpack(line)

            if event is None:
                continue

            if not is_unknown_mac(event["mac"], conn):
                continue

            written = write_ticket(event, alerts_dir)

            if written is not None:
                ticket_count += 1
                print(
                    f"ALERT: {event['timestamp']}  "
                    f"{event['mac']}  "
                    f"{event['ip']}  -> {written.name}"
                )

        new_offset = f.tell()

    return new_offset, current_inode, ticket_count


def run_watcher() -> int:

    if not DB_PATH.exists():
        print(f"ERROR: database not found at {DB_PATH}", file=sys.stderr)
        return 2

    state = load_state(STATE_FILE)

    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    print(f"[{started_at}] DHCPACK watcher: reading {FLINT_LOG}")
    print(
        f"  starting offset: {state.get('last_byte_offset', 0)} "
        f"(last_inode: {state.get('last_inode')})"
    )

    conn = sqlite3.connect(DB_PATH)

    try:
        new_offset, new_inode, ticket_count = process_log(
            FLINT_LOG,
            state,
            conn,
            ALERTS_DIR,
        )
    finally:
        conn.close()

    save_state(STATE_FILE, new_offset, new_inode)

    finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    print(
        f"[{finished_at}] Done. "
        f"New offset: {new_offset}. "
        f"Tickets written: {ticket_count}"
    )

    return 0


# Self-test mode
def run_tests() -> int:
    """
    Run quick self-tests for the parser, database check, and ticket writer.

    This is not a full test suite, but it is useful for checking that the main
    parts of the watcher still work after making changes.
    """
    test_lines = [
        "2026-06-01T07:12:13-04:00 GL-MT6000 dnsmasq-dhcp[14306]: DHCPACK(br-lan) 192.168.8.175 5c:e7:53:bb:ca:e4",
        "2026-06-01T07:12:13-04:00 GL-MT6000 dnsmasq-dhcp[14306]: DHCPACK(br-lan) 192.168.8.119 bc:fc:e7:75:e4:bb HACKER-MAN-2",
        "2026-06-01T07:12:13-04:00 GL-MT6000 dnsmasq-dhcp[14306]: DHCPOFFER(br-lan) 192.168.8.175 5c:e7:53:bb:ca:e4",
        "2026-06-01T07:12:13-04:00 GL-MT6000 dnsmasq-dhcp[14306]: DHCPREQUEST(br-lan) 192.168.8.175 5c:e7:53:bb:ca:e4",
        "2026-06-01T07:13:33-04:00 GL-MT6000 kernel: [312288.226451] 7986@C13L2,MacTableInsertEntry() 1577: New Sta:5c:e7:53:b6:9e:a4",
        "this is not a syslog line",
        "",
    ]

    print(f"{'RESULT':6}  LINE")
    print("-" * 80)

    for line in test_lines:
        result = parse_dhcpack(line)
        status = "MATCH" if result else "skip"
        display = line[:70] + "..." if len(line) > 70 else line

        print(f"{status:6}  {display}")

        if result:
            print(f"        -> {result}")

    print()
    print("=== Database check ===")

    if not DB_PATH.exists():
        print(f"  ERROR: database not found at {DB_PATH}")
    else:
        conn = sqlite3.connect(DB_PATH)

        try:
            test_macs = [
                ("b8:27:eb:f0:9d:06", "Pi should already be known"),
                ("94:83:c4:ca:93:ca", "Flint router should already be known"),
                ("aa:bb:cc:dd:ee:ff", "Fake MAC should be unknown"),
                ("5C:E7:53:BB:CA:E4", "Uppercase MAC test should still work"),
            ]

            for mac, desc in test_macs:
                result = is_unknown_mac(mac, conn)
                print(f"  {mac:20}  unknown={result}  ({desc})")

        finally:
            conn.close()

    print()
    print("=== Ticket writer ===")

    fake_event = {
        "timestamp": "2026-06-01T12:00:00-04:00",
        "ip": "192.168.8.250",
        "mac": "aa:bb:cc:dd:ee:ff",
    }

    result1 = write_ticket(fake_event, ALERTS_DIR)

    if result1:
        print(f"  First call:  wrote {result1.name}")
    else:
        print("  First call:  deduplicated, but it should have created a ticket")

    result2 = write_ticket(fake_event, ALERTS_DIR)

    if result2:
        print(f"  Second call: wrote {result2.name}, but it should have deduped")
    else:
        print("  Second call: deduplicated as expected")

    if result1:
        result1.unlink()
        print(f"  Cleaned up test ticket: {result1.name}")

    return 0


# Entry point
def main() -> int:
    parser = argparse.ArgumentParser(description="HomeSOC DHCPACK watcher")

    parser.add_argument(
        "--test",
        action="store_true",
        help="run self-tests instead of processing the log",
    )

    args = parser.parse_args()

    if args.test:
        return run_tests()

    return run_watcher()


if __name__ == "__main__":
    sys.exit(main())
