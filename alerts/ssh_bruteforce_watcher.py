#!/usr/bin/env python3
"""
HomeSOC SSH brute-force watcher.

This script watches /var/log/auth.log for repeated failed SSH login attempts
from the same source IP. If one IP hits the threshold within the time window,
the script writes an alert ticket in evidence/alerts/.

My Pi uses key-only SSH, so password authentication should already be disabled.
That means a normal SSH brute-force attempt should not actually succeed, but it
is still worth alerting on because it can show scanning, bad configuration, or
a device on the network acting weird.

This rule looks for lines like:

    Invalid user admin from 192.168.8.50 port 51000

It only counts the actual "Invalid user" line, not the follow-up preauth line,
so each login attempt is counted once.

Usage:

    python3 alerts/ssh_bruteforce_watcher.py
    python3 alerts/ssh_bruteforce_watcher.py --test
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path



# Settings
PROJECT_ROOT = Path(__file__).resolve().parent.parent

ALERTS_DIR = PROJECT_ROOT / "evidence" / "alerts"
STATE_FILE = PROJECT_ROOT / "alerts" / ".ssh_watcher_state.json"
AUTH_LOG = Path("/var/log/auth.log")

RUNBOOK_PATH = "docs/runbooks/RB-003-ssh-bruteforce.md"

# Alert when one source IP has this many failed SSH attempts inside the window.
FAILURE_THRESHOLD = 5
WINDOW_MINUTES = 10


# Match auth.log lines like:
#
# 2026-06-03T19:30:01.000000-04:00 pi-monitor sshd-session[1300]:
# Invalid user admin from 192.168.8.50 port 51000
#
# This supports both sshd and sshd-session.
INVALID_USER_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})\s+"
    r"\S+\s+"
    r"sshd(?:-session)?\[\d+\]:\s+"
    r"Invalid user\s+(?P<username>\S+)\s+"
    r"from\s+(?P<source_ip>\S+)\s+port"
)



# Log parsing
def parse_ssh_failure(line: str) -> dict | None:
    """
    Parse one auth.log line.

    Returns a dictionary if the line is an SSH invalid-user attempt.
    Returns None for anything else.

    This ignores:
    - successful logins
    - preauth connection closed lines
    - unrelated auth.log entries
    """
    match = INVALID_USER_RE.match(line)

    if not match:
        return None

    return {
        "timestamp": match.group("timestamp"),
        "username": match.group("username"),
        "source_ip": match.group("source_ip"),
    }


def parse_ts(iso_ts: str) -> datetime | None:
    """
    Convert the auth.log timestamp into a datetime object.

    Example input:
        2026-06-03T19:29:58.621247-04:00
    """
    try:
        return datetime.fromisoformat(iso_ts)
    except ValueError:
        return None



# Detection logic
def find_bruteforce_sources(events: list[dict]) -> list[dict]:
    """
    Find source IPs that crossed the brute-force threshold.

    This is different from a simple one-event alert. This rule has to correlate
    multiple SSH failures from the same IP and check whether they happened close
    enough together.

    Returns one summary per source IP that triggered.
    """
    by_ip: dict[str, list[dict]] = defaultdict(list)

    for event in events:
        timestamp = parse_ts(event["timestamp"])

        if timestamp is None:
            continue

        by_ip[event["source_ip"]].append({
            "ts": timestamp,
            "username": event["username"],
        })

    window = timedelta(minutes=WINDOW_MINUTES)
    hits = []

    for source_ip, attempts in by_ip.items():
        attempts.sort(key=lambda attempt: attempt["ts"])

        triggered = False

        for index, start_attempt in enumerate(attempts):
            window_start = start_attempt["ts"]
            window_end = window_start + window

            attempts_in_window = [
                attempt
                for attempt in attempts[index:]
                if attempt["ts"] <= window_end
            ]

            if len(attempts_in_window) >= FAILURE_THRESHOLD:
                triggered = True
                break

        if triggered:
            usernames = sorted({attempt["username"] for attempt in attempts})

            hits.append({
                "source_ip": source_ip,
                "count": len(attempts),
                "first": attempts[0]["ts"].isoformat(),
                "last": attempts[-1]["ts"].isoformat(),
                "usernames": usernames,
            })

    return hits



# Alert ticket writing
def make_ip_filename_safe(ip: str) -> str:
    """
    Make an IP address safe to use in a filename.
    """
    return ip.replace(":", "-").replace(".", "-")


def find_existing_open_ticket(source_ip: str, alerts_dir: Path) -> Path | None:
    """
    Check if there is already an open SSH brute-force ticket for this IP.

    This prevents the watcher from creating duplicate tickets every time it
    runs while the same issue is still open.
    """
    ip_safe = make_ip_filename_safe(source_ip)

    for existing_ticket in alerts_dir.glob(f"*__sshbrute__{ip_safe}.md"):
        try:
            first_lines = "\n".join(existing_ticket.read_text().splitlines()[:10])
        except OSError:
            continue

        if "status: open" in first_lines:
            return existing_ticket

    return None


def write_ticket(hit: dict, alerts_dir: Path) -> Path | None:
    """
    Write an SSH brute-force alert ticket.

    Returns the ticket path if a new ticket was written.
    Returns None if an open ticket already exists for that source IP.
    """
    alerts_dir.mkdir(parents=True, exist_ok=True)

    existing_ticket = find_existing_open_ticket(hit["source_ip"], alerts_dir)

    if existing_ticket is not None:
        return None

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    source_ip_safe = make_ip_filename_safe(hit["source_ip"])

    filename = f"{now}__sshbrute__{source_ip_safe}.md"
    ticket_path = alerts_dir / filename

    usernames = ", ".join(hit["usernames"][:10])

    content = f"""---
status: open
severity: medium
detected_at: {hit["last"]}
detected_by: ssh_bruteforce_watcher
source_ip: {hit["source_ip"]}
failure_count: {hit["count"]}
runbook: {RUNBOOK_PATH}
---

# Possible SSH brute-force attempt

Multiple failed SSH login attempts came from one source IP within a short
time window.

On this Pi, SSH is key-only, so these invalid-user attempts should not have
been able to log in. Still, this could show scanning, a misconfigured device,
or a device on the network acting suspicious.

## Evidence

- Source IP: {hit["source_ip"]}
- Failed attempts: {hit["count"]}
- First seen: {hit["first"]}
- Last seen: {hit["last"]}
- Usernames tried: {usernames}
- Detection source: `/var/log/auth.log`
- Matched pattern: `Invalid user ... from ...`
- Threshold: {FAILURE_THRESHOLD} failures within {WINDOW_MINUTES} minutes

## What this means

Repeated invalid-user attempts from one IP usually means an automated scan or
brute-force attempt.

Because this Pi uses key-only SSH, the attempts should not have succeeded, but
I still need to confirm the source IP and decide whether to block it.

## Runbook

Follow `{RUNBOOK_PATH}` to investigate and respond.

## Resolution

When reviewed, change `status: open` to `status: resolved` in the frontmatter
and add notes below.

### Notes

- Source checked:
- Known device?:
- SSH password auth confirmed disabled?:
- Action taken:
"""

    ticket_path.write_text(content)
    return ticket_path



# State file
def load_state(state_path: Path) -> dict:
    """
    Load the watcher state file.

    The state file tracks the last byte offset read from auth.log. This lets
    the script only process new log lines each time it runs.
    """
    if not state_path.exists():
        return {
            "last_byte_offset": 0,
            "last_inode": None,
            "last_run": None,
        }

    try:
        return json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError):
        print(
            f"WARNING: state file {state_path} is corrupt; starting fresh.",
            file=sys.stderr,
        )

        return {
            "last_byte_offset": 0,
            "last_inode": None,
            "last_run": None,
        }


def save_state(state_path: Path, offset: int, inode: int) -> None:
    """
    Save the current auth.log position so the next run continues from there.
    """
    state_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "last_byte_offset": offset,
        "last_inode": inode,
        "last_run": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    temp_path = state_path.with_suffix(".json.tmp")
    temp_path.write_text(json.dumps(payload, indent=2))
    temp_path.replace(state_path)



# Main processing
def process_log(log_path: Path, state: dict, alerts_dir: Path) -> tuple[int, int | None, int]:
    """
    Read new auth.log lines, detect brute-force sources, and write tickets.

    Returns:
        new_offset, new_inode, ticket_count
    """
    if not log_path.exists():
        print(f"WARNING: {log_path} was not found.", file=sys.stderr)

        return (
            state.get("last_byte_offset", 0),
            state.get("last_inode"),
            0,
        )

    current_stat = log_path.stat()
    current_inode = current_stat.st_ino
    current_size = current_stat.st_size

    last_inode = state.get("last_inode")
    last_offset = state.get("last_byte_offset", 0)

    if last_inode is None or last_inode != current_inode:
        # First run or log rotation.
        start_offset = 0
    elif last_offset > current_size:
        # Log file shrank unexpectedly.
        start_offset = 0
    else:
        start_offset = last_offset

    events = []

    with log_path.open("r", encoding="utf-8", errors="replace") as auth_log:
        auth_log.seek(start_offset)

        for line in auth_log:
            event = parse_ssh_failure(line)

            if event is not None:
                events.append(event)

        new_offset = auth_log.tell()

    hits = find_bruteforce_sources(events)

    ticket_count = 0

    for hit in hits:
        ticket_path = write_ticket(hit, alerts_dir)

        if ticket_path is not None:
            ticket_count += 1

            print(
                f"ALERT: SSH brute-force from {hit['source_ip']} "
                f"({hit['count']} attempts) -> {ticket_path.name}"
            )

    return new_offset, current_inode, ticket_count


def run_watcher() -> int:
    """
    Run the watcher normally.
    """
    state = load_state(STATE_FILE)

    started = datetime.now(timezone.utc).isoformat(timespec="seconds")

    print(f"[{started}] SSH brute-force watcher")
    print(f"Reading: {AUTH_LOG}")
    print(
        f"Starting offset: {state.get('last_byte_offset', 0)} "
        f"(last inode: {state.get('last_inode')})"
    )

    new_offset, new_inode, ticket_count = process_log(
        AUTH_LOG,
        state,
        ALERTS_DIR,
    )

    save_state(STATE_FILE, new_offset, new_inode)

    finished = datetime.now(timezone.utc).isoformat(timespec="seconds")

    print(
        f"[{finished}] Done. "
        f"New offset: {new_offset}. "
        f"Tickets written: {ticket_count}."
    )

    return 0



# Self-test
def run_tests() -> int:
    """
    Run basic parser and threshold tests.
    """
    test_lines = [
        "2026-06-03T19:29:58.621247-04:00 pi-monitor sshd-session[1295]: Invalid user fakeattacker from ::1 port 39308",
        "2026-06-03T19:30:01.000000-04:00 pi-monitor sshd-session[1300]: Invalid user admin from 192.168.8.50 port 51000",
        "2026-06-03T19:30:02.000000-04:00 pi-monitor sshd[1301]: Invalid user root from 192.168.8.50 port 51002",
        "2026-06-03T19:29:58.633699-04:00 pi-monitor sshd-session[1295]: Connection closed by invalid user fakeattacker ::1 port 39308 [preauth]",
        "2026-06-03T18:51:02.428351-04:00 pi-monitor sshd-session[1163]: Accepted publickey for brandon from 192.168.8.119 port 57948 ssh2",
        "this is not a log line",
        "",
    ]

    print(f"{'RESULT':6}  LINE")
    print("-" * 80)

    parsed_events = []

    for line in test_lines:
        result = parse_ssh_failure(line)
        status = "MATCH" if result else "skip"

        display = line[:68] + "..." if len(line) > 68 else line

        print(f"{status:6}  {display}")

        if result:
            print(f"        -> {result}")
            parsed_events.append(result)

    print()
    print("=== Threshold logic ===")

    base_time = datetime(
        2026,
        6,
        3,
        19,
        0,
        0,
        tzinfo=timezone(timedelta(hours=-4)),
    )

    burst = []

    for index in range(5):
        timestamp = (base_time + timedelta(seconds=index * 10)).isoformat()

        burst.append({
            "timestamp": timestamp,
            "username": "fakeattacker",
            "source_ip": "192.168.8.99",
        })

    burst.append({
        "timestamp": base_time.isoformat(),
        "username": "x",
        "source_ip": "192.168.8.10",
    })

    hits = find_bruteforce_sources(burst)

    for hit in hits:
        print(
            f"  TRIGGERED: {hit['source_ip']} "
            f"count={hit['count']} "
            f"users={hit['usernames']}"
        )

    if not hits:
        print("  No sources crossed the threshold.")

    print("  Expected: one trigger for 192.168.8.99, none for 192.168.8.10")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="HomeSOC SSH brute-force watcher"
    )

    parser.add_argument(
        "--test",
        action="store_true",
        help="run self-tests",
    )

    args = parser.parse_args()

    if args.test:
        return run_tests()

    return run_watcher()


if __name__ == "__main__":
    sys.exit(main())

