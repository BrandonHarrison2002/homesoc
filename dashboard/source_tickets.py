"""Explicit source-ticket closure; inventory and detector cursors stay untouched."""
import fcntl
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

MAX_TICKET_BYTES = 131072


def resolve_source(alerts_dir: Path, filename: str, incident_id: int, resolution: str) -> bool:
    """Return True on closure, False if already resolved. Reject unsafe tickets."""
    if (Path(filename).name != filename or not filename.endswith('.md')
            or '\x00' in filename or alerts_dir.is_symlink()):
        raise ValueError('Source ticket path is not an available local alert.')
    if len(resolution.strip()) < 10 or len(resolution) > 4000:
        raise ValueError('Save a resolution of 10 to 4,000 characters first.')
    # Serialize dashboard closure requests; detector reads see an atomic replacement.
    lock_fd = os.open(alerts_dir / '.source-close.lock',
                      os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        ticket = alerts_dir / filename
        fd = os.open(ticket, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError('Source must be a regular Markdown file with no hard links.')
            if before.st_uid != os.geteuid():
                raise ValueError('Source ticket must be owned by the dashboard service user.')
            data = stream.read(MAX_TICKET_BYTES + 1)
        if len(data) > MAX_TICKET_BYTES:
            raise ValueError('Source ticket is too large to close from the dashboard.')
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError as error:
            raise ValueError('Source ticket must contain valid UTF-8 text.') from error
        lines = text.splitlines(keepends=True)
        if not lines or lines[0].strip() != '---':
            raise ValueError('Source ticket has no complete metadata header.')
        end = next((i for i in range(1, len(lines)) if lines[i].strip() == '---'), None)
        if end is None:
            raise ValueError('Source ticket has no complete metadata header.')
        status_lines = [i for i in range(1, end)
                        if lines[i].partition(':')[0].strip() == 'status']
        if len(status_lines) != 1:
            raise ValueError('Source ticket must have exactly one status field.')
        index = status_lines[0]
        status_value = lines[index].partition(':')[2].strip()
        if status_value == 'resolved':
            return False
        if status_value != 'open':
            raise ValueError('Only an open source alert can be resolved here.')
        newline = '\r\n' if lines[index].endswith('\r\n') else '\n'
        lines[index] = 'status: resolved' + newline
        closed_at = datetime.now(timezone.utc).isoformat(timespec='seconds')
        note = (f'\n\n## Dashboard resolution — INC-{incident_id:04d}\n\n'
                f'Resolved at: {closed_at}\n\n{resolution.strip()}\n')
        updated = ''.join(lines) + note
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=alerts_dir, prefix='.source-close-',
                                             suffix='.tmp', delete=False) as stream:
                temporary = Path(stream.name)
                os.fchmod(stream.fileno(), stat.S_IMODE(before.st_mode) & 0o777)
                stream.write(updated.encode('utf-8'))
                stream.flush()
                os.fsync(stream.fileno())
            current = ticket.lstat()
            identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
            if identity(current) != identity(before):
                raise ValueError('Source ticket changed during closure. Reload and retry.')
            os.replace(temporary, ticket)
            temporary = None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return True
    finally:
        os.close(lock_fd)
