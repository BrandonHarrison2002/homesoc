#!/usr/bin/env python3
"""HomeSOC dashboard — device inventory, alerts, summary."""

import sqlite3
from pathlib import Path

from flask import Flask, render_template

app = Flask(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "db" / "homesoc.db"
ALERTS_DIR = PROJECT_ROOT / "evidence" / "alerts"

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

# routes
@app.route("/")
def home():
    devices = get_devices()
    return render_template(
        "devices.html",
        devices=devices,
        total=len(devices),
        online=sum(1 for d in devices if d["status"] == "online"),
        unreviewed=sum(1 for d in devices if d["is_known"] == 0),
        window=ONLINE_WINDOW_MIN,
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
    )


@app.route("/summary")
def summary():
    return render_template("summary.html", s=get_summary(), window=ONLINE_WINDOW_MIN)


if __name__ == "__main__":
    import os
    # Debug mode only when explicitly requested (never under systemd).
    debug = os.environ.get("HOMESOC_DEBUG") == "1"
    app.run(host="0.0.0.0", port=8080, debug=debug)
