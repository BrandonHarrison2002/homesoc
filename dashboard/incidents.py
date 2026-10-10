"""Incident storage only. This module never opens inventory or detector tickets."""
import os
import secrets
import sqlite3
from pathlib import Path

STATE_DIR = Path(os.environ.get('HOMESOC_INCIDENT_STATE_DIR',
    str(Path(__file__).resolve().parent.parent / 'dashboard-state')))
STATUSES = ('Open', 'Investigating', 'Contained', 'Resolved')
PRIORITIES = ('low', 'medium', 'high')


def prepare_state():
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE_DIR.chmod(0o700)


def get_session_key():
    """Keep Flask's session-signing key private and stable across restarts."""
    prepare_state()
    path = STATE_DIR / 'session.key'
    try:
        with path.open('x') as key:
            path.chmod(0o600)
            key.write(secrets.token_hex(32))
    except FileExistsError:
        pass
    return path.read_text()


def connect():
    prepare_state()
    conn = sqlite3.connect(STATE_DIR / 'incidents.db', timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_filename TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                owner TEXT NOT NULL DEFAULT '',
                resolution TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS incident_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL REFERENCES incidents(id),
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS incident_notes_case ON incident_notes(incident_id);
        ''')
        conn.execute('PRAGMA foreign_keys = ON')
        return conn
    except Exception:
        conn.close()
        raise


def list_incidents():
    conn = connect()
    try:
        return conn.execute('SELECT * FROM incidents ORDER BY id DESC').fetchall()
    finally:
        conn.close()


def get_incident(incident_id):
    conn = connect()
    try:
        incident = conn.execute('SELECT * FROM incidents WHERE id=?', (incident_id,)).fetchone()
        notes = conn.execute('SELECT * FROM incident_notes WHERE incident_id=? ORDER BY id',
                             (incident_id,)).fetchall()
        return incident, notes
    finally:
        conn.close()


def get_or_create_incident(filename, title, priority, status='Open', owner='', resolution='', note=''):
    validate_incident_values(status, priority, owner, resolution, note)
    conn = connect()
    try:
        inserted = conn.execute(
            'INSERT OR IGNORE INTO incidents(alert_filename,title,priority,status,owner,resolution) VALUES(?,?,?,?,?,?)',
            (filename, title, priority, status, owner, resolution))
        incident = conn.execute('SELECT id FROM incidents WHERE alert_filename=?', (filename,)).fetchone()
        if inserted.rowcount == 1 and note:
            conn.execute('INSERT INTO incident_notes(incident_id,body) VALUES(?,?)', (incident['id'], note))
        conn.commit()
        return incident['id']
    finally:
        conn.close()


def validate_incident_values(status, priority, owner, resolution, note):
    if status not in STATUSES or priority not in PRIORITIES:
        raise ValueError('Choose an available status and priority.')
    if len(owner) > 80 or len(resolution) > 4000 or len(note) > 4000:
        raise ValueError('Owner is limited to 80 characters; notes and resolution to 4,000.')
    if status == 'Resolved' and len(resolution.strip()) < 10:
        raise ValueError('Record a resolution of at least 10 characters before resolving.')


def update_incident(incident_id, status, priority, owner, resolution, note):
    """Validate first, then commit the case and timeline changes together."""
    validate_incident_values(status, priority, owner, resolution, note)
    conn = connect()
    try:
        old = conn.execute('SELECT * FROM incidents WHERE id=?', (incident_id,)).fetchone()
        if old is None:
            raise LookupError('Incident not found')
        changes = []
        for field, value in [('status', status), ('priority', priority), ('owner', owner), ('resolution', resolution)]:
            if old[field] != value:
                if field == 'resolution':
                    changes.append('Resolution updated')
                else:
                    changes.append(f"{field}: {old[field] or 'unassigned'} -> {value or 'unassigned'}")
        if changes or note:
            conn.execute("UPDATE incidents SET status=?,priority=?,owner=?,resolution=?,updated_at=datetime('now') WHERE id=?",
                         (status, priority, owner, resolution, incident_id))
            if changes:
                conn.execute('INSERT INTO incident_notes(incident_id,body) VALUES(?,?)',
                             (incident_id, '; '.join(changes)))
            if note:
                conn.execute('INSERT INTO incident_notes(incident_id,body) VALUES(?,?)', (incident_id, note))
            conn.commit()
    finally:
        conn.close()


def add_incident_note(incident_id, body):
    """Append audit text without overwriting incident fields from another edit."""
    if not body.strip() or len(body) > 4000:
        raise ValueError('A timeline note must contain 1 to 4,000 characters.')
    conn = connect()
    try:
        conn.execute('INSERT INTO incident_notes(incident_id,body) VALUES(?,?)', (incident_id, body))
        conn.execute("UPDATE incidents SET updated_at=datetime('now') WHERE id=?", (incident_id,))
        conn.commit()
    finally:
        conn.close()
