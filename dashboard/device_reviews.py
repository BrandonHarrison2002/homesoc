"""Archive stale inventory entries for display without approving or deleting them."""
from datetime import datetime, timezone
try:
    from . import incidents as incident_store
except ImportError:
    import incidents as incident_store

STALE_DAYS = 30


def connect():
    conn = incident_store.connect()
    conn.execute('''CREATE TABLE IF NOT EXISTS device_archives (
        mac TEXT PRIMARY KEY,
        last_seen_at_archive TEXT NOT NULL,
        reason TEXT NOT NULL,
        is_archived INTEGER NOT NULL DEFAULT 1,
        archived_at TEXT NOT NULL DEFAULT (datetime('now'))
    )''')
    conn.commit()
    return conn


def records():
    conn = connect()
    try:
        return {row['mac']: dict(row) for row in conn.execute('SELECT * FROM device_archives')}
    finally:
        conn.close()


def age_days(last_seen, now=None):
    try:
        seen = datetime.fromisoformat(last_seen)
        if seen.tzinfo is None: seen = seen.replace(tzinfo=timezone.utc)
        now = now or datetime.now(timezone.utc)
        return max(0, (now - seen).days)
    except (ValueError, TypeError):
        return None


def annotate(device, archives):
    result = dict(device)
    record = archives.get(device['mac'].lower())
    # A changed discovery timestamp brings the device back into active review.
    result['archived'] = bool(record and record['is_archived'] and record['last_seen_at_archive'] == device['last_seen'])
    result['archive_record'] = record
    result['age_days'] = age_days(device['last_seen'])
    return result


def archive(device, reason):
    reason = reason.strip()
    if len(reason) < 10 or len(reason) > 1000:
        raise ValueError('Record an archive reason of 10 to 1,000 characters.')
    age = age_days(device['last_seen'])
    if device['status'] == 'online' or age is None or age < STALE_DAYS:
        raise ValueError('Archive is available only for devices not seen for at least 30 days.')
    conn = connect()
    try:
        conn.execute('''INSERT INTO device_archives(mac,last_seen_at_archive,reason)
            VALUES(?,?,?) ON CONFLICT(mac) DO UPDATE SET
            last_seen_at_archive=excluded.last_seen_at_archive,
            reason=excluded.reason, is_archived=1, archived_at=datetime('now')''',
            (device['mac'].lower(), device['last_seen'], reason))
        conn.commit()
    finally:
        conn.close()


def restore(mac):
    conn = connect()
    try:
        conn.execute('UPDATE device_archives SET is_archived=0 WHERE mac=?', (mac.lower(),))
        conn.commit()
    finally:
        conn.close()
