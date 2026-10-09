#!/usr/bin/env python3
"""HomeSOC dashboard — device inventory, alerts, summary."""

import sqlite3
from pathlib import Path

from flask import Flask, abort, render_template, request

app = Flask(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "db" / "homesoc.db"
ALERTS_DIR = PROJECT_ROOT / "evidence" / "alerts"
LOGS_DIR = Path("/var/log/remote")
AUTH_LOG = Path("/var/log/auth.log")
LOG_TAIL_BYTES = 65536
LOG_TAIL_LINES = 200

# anything last seen within this window is considered "online"
ONLINE_WINDOW_MIN = 30

# data access
def get_devices():
    """Return all assets with a computed online/offline status."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            """
            SELECT
                ip,
                mac,
                COALESCE(hostname, '')      AS hostname,
                COALESCE(owner, '-')        AS owner,
                COALESCE(device_type, '-')  AS device_type,
                is_known,
                last_seen,
                CASE
                    WHEN last_seen > datetime('now', ?)
                    THEN 'online'
                    ELSE 'offline'
                END AS status
            FROM assets
            ORDER BY ip
            """,
            (f"-{ONLINE_WINDOW_MIN} minutes",),
        ).fetchall()
    finally:
        conn.close()


def parse_frontmatter(text: str) -> dict:
    """Pull key: value pairs out of a --- fenced YAML header."""
    fields = {}
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return fields
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" in line:
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    return fields


def get_alerts():
    """
    Read alert tickets from evidence/alerts/, newest first.
    Returns parsed frontmatter + filename for each .md file found.
    """
    alerts = []
    if not ALERTS_DIR.exists():
        return alerts
    for ticket in sorted(ALERTS_DIR.glob("*.md"), reverse=True):
        try:
            meta = parse_frontmatter(ticket.read_text())
        except OSError:
            continue
        meta["filename"] = ticket.name
        alerts.append(meta)
    return alerts


def get_summary():
    """Lightweight operational snapshot pulled live from SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        scan = conn.execute(
            """
            SELECT COUNT(*) AS cnt, MAX(started_at) AS latest, AVG(duration_ms) AS avg_ms
            FROM scans
            WHERE started_at > datetime('now', '-24 hours')
            """
        ).fetchone()

        total = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        unreviewed = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE is_known = 0"
        ).fetchone()[0]
        online = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE last_seen > datetime('now', ?)",
            (f"-{ONLINE_WINDOW_MIN} minutes",),
        ).fetchone()[0]

        stale = conn.execute(
            """
            SELECT ip, mac, COALESCE(hostname, '') AS hostname, last_seen
            FROM assets
            WHERE last_seen < datetime('now', '-24 hours')
            ORDER BY last_seen ASC
            """
        ).fetchall()

        return {
            "scan_count": scan["cnt"],
            "scan_latest": scan["latest"] or "none",
            "scan_avg_ms": round(scan["avg_ms"]) if scan["avg_ms"] else None,
            "total": total,
            "unreviewed": unreviewed,
            "online": online,
            "stale": stale,
        }
    finally:
        conn.close()

def filter_devices(devices, query, status, review):
    """Narrow the displayed rows without changing the inventory database."""
    matches = []
    search = query.casefold()
    fields = ("ip", "mac", "hostname", "owner", "device_type")
    for device in devices:
        if status != "all" and device["status"] != status:
            continue
        if review == "unreviewed" and device["is_known"] != 0:
            continue
        if review == "known" and device["is_known"] == 0:
            continue
        if search and not any(search in str(device[field] or "").casefold() for field in fields):
            continue
        matches.append(device)
    return matches


def get_host_detail(mac):
    """Look up a stable MAC identity and its latest 20 discovery sightings."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        device = conn.execute(
            """
            SELECT *,
                CASE WHEN last_seen > datetime('now', ?)
                     THEN 'online' ELSE 'offline' END AS status
            FROM assets
            WHERE mac = ? COLLATE NOCASE
            """,
            (f"-{ONLINE_WINDOW_MIN} minutes", mac),
        ).fetchone()
        if device is None:
            return None, []
        sightings = conn.execute(
            """
            SELECT s.seen_at, s.ip, s.scan_id, scans.scan_type
            FROM sightings AS s
            LEFT JOIN scans ON scans.id = s.scan_id
            WHERE s.asset_id = ?
            ORDER BY s.seen_at DESC, s.scan_id DESC
            LIMIT 20
            """,
            (device["id"],),
        ).fetchall()
        return device, sightings
    finally:
        conn.close()


def get_host_alerts(device):
    """Find ticket candidates; an IP-only match needs DHCP history verification."""
    matches = []
    for alert in get_alerts():
        if alert.get("asset_mac", "").casefold() == device["mac"].casefold():
            matches.append(dict(alert, match_basis="MAC match"))
        elif device["ip"] and device["ip"] in (alert.get("asset_ip"), alert.get("source_ip")):
            matches.append(dict(alert, match_basis="Current IP match; verify DHCP history"))
    return matches[:50]


def get_log_sources():
    """Only offer configured local log files, never paths supplied by a visitor."""
    sources = {}
    try:
        for path in sorted(LOGS_DIR.glob("*.log")):
            if path.is_file() and not path.is_symlink():
                sources[f"Remote: {path.name}"] = path
        if AUTH_LOG.is_file() and not AUTH_LOG.is_symlink():
            sources["Pi: auth.log"] = AUTH_LOG
    except OSError:
        pass
    return sources


def read_log_tail(path):
    """Read at most 64 KiB and return the latest 200 complete lines, newest first."""
    with path.open("rb") as log:
        log.seek(0, 2)
        start = max(0, log.tell() - LOG_TAIL_BYTES)
        log.seek(start)
        block = log.read(LOG_TAIL_BYTES)
    if start:
        # The first line might start before the bounded window; discard its fragment.
        block = block.partition(b"\n")[2]
    if not block.endswith(b"\n"):
        # Ignore an unfinished line until the writer completes it.
        block = block.rpartition(b"\n")[0]
    lines = block.decode("utf-8", errors="replace").splitlines()
    return list(reversed(lines[-LOG_TAIL_LINES:]))


# routes
@app.route("/")
def home():
    all_devices = get_devices()
    query = request.args.get("q", "").strip()
    status = request.args.get("status", "all")
    review = request.args.get("review", "all")
    if status not in ("all", "online", "offline"):
        status = "all"
    if review not in ("all", "known", "unreviewed"):
        review = "all"
    devices = filter_devices(all_devices, query, status, review)
    return render_template(
        "devices.html",
        devices=devices,
        total=len(all_devices),
        online=sum(1 for d in all_devices if d["status"] == "online"),
        unreviewed=sum(1 for d in all_devices if d["is_known"] == 0),
        query=query,
        status_filter=status,
        review_filter=review,
        window=ONLINE_WINDOW_MIN,
        active="devices",
    )


@app.route("/devices/<mac>")
def host_detail(mac):
    device, sightings = get_host_detail(mac)
    if device is None:
        abort(404)
    return render_template(
        "host.html",
        device=device,
        sightings=sightings,
        related_alerts=get_host_alerts(device),
        window=ONLINE_WINDOW_MIN,
        active="devices",
    )


@app.route("/alerts")
def alerts():
    all_alerts = get_alerts()
    open_count = sum(1 for a in all_alerts if a.get("status") == "open")
    return render_template(
        "alerts.html",
        alerts=all_alerts,
        total=len(all_alerts),
        open_count=open_count,
        active="alerts",
    )


@app.route("/logs")
def logs():
    sources = get_log_sources()
    selected = request.args.get("source", next(iter(sources), ""))
    query = request.args.get("q", "").strip()
    lines = []
    error = ""
    if selected in sources:
        try:
            lines = read_log_tail(sources[selected])
        except OSError:
            error = "This log cannot be read. Check the dashboard service user's file permissions."
    elif selected:
        error = "Unknown log source. Choose one of the available files."
    tail_count = len(lines)
    if query:
        lines = [line for line in lines if query.casefold() in line.casefold()]
    return render_template(
        "logs.html", sources=sources, selected=selected, query=query,
        lines=lines, tail_count=tail_count, error=error,
        line_limit=LOG_TAIL_LINES, active="logs",
    )


@app.route("/summary")
def summary():
    return render_template("summary.html", s=get_summary(), window=ONLINE_WINDOW_MIN, active="summary")


if __name__ == "__main__":
    import os
    # Debug mode only when explicitly requested (never under systemd).
    debug = os.environ.get("HOMESOC_DEBUG") == "1"
    app.run(host="0.0.0.0", port=8080, debug=debug)
