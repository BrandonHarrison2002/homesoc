"""Single-user credentials and login throttle for the private dashboard."""
import argparse
from collections import deque
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import threading
import time
from werkzeug.security import check_password_hash, generate_password_hash
try:
    from . import incidents as incident_store
except ImportError:
    import incidents as incident_store

SESSION_SECONDS = 8 * 60 * 60
HASH_METHOD = 'pbkdf2:sha256:600000'


class AuthConfigError(ValueError):
    pass


def credentials_path():
    return incident_store.STATE_DIR / 'auth.json'


def read_credentials():
    try:
        fd = os.open(credentials_path(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'r', encoding='utf-8') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 4096:
                raise AuthConfigError('Credential file must be private, regular, and owned by the dashboard user.')
            values = json.load(handle)
        if not isinstance(values, dict) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', values.get('username', '')):
            raise AuthConfigError('Invalid credential configuration.')
        if not re.fullmatch(r'[a-f0-9]{64}', values.get('version', '')):
            raise AuthConfigError('Invalid credential configuration.')
        if not re.fullmatch(r'pbkdf2:sha256:600000\$[A-Za-z0-9]{16}\$[a-f0-9]{64}', values.get('password_hash', '')):
            raise AuthConfigError('Invalid credential configuration.')
        return values
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError) as error:
        raise AuthConfigError('Dashboard login is not configured or its credential file cannot be read.') from error


def set_password(username, password):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', username):
        raise ValueError('Username must be 1 to 64 letters, digits, dots, underscores, or hyphens.')
    if len(password) < 12 or len(password) > 128:
        raise ValueError('Choose a password between 12 and 128 characters.')
    incident_store.prepare_state()
    path = credentials_path()
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError('Refusing to replace a credential file with unsafe ownership or links.')
    values = dict(username=username, password_hash=generate_password_hash(password, method=HASH_METHOD, salt_length=16), version=secrets.token_hex(32))
    fd, name = tempfile.mkstemp(prefix='.auth-', dir=incident_store.STATE_DIR)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(values, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)
    return values


def verify(values, username, password):
    if len(username) > 64 or not 1 <= len(password) <= 128:
        return False
    correct_password = check_password_hash(values['password_hash'], password)
    return secrets.compare_digest(username.encode(), values['username'].encode()) and correct_password


def valid_session(data, values, now=None):
    now = time.time() if now is None else now
    issued = data.get('auth_issued_at')
    return (isinstance(issued, (int, float)) and 0 <= now-issued < SESSION_SECONDS
            and data.get('auth_user') == values['username'] and data.get('auth_version') == values['version'])


class LoginThrottle:
    """Single-user, process-local throttle shared across source IPs and cookies."""
    def __init__(self):
        self.failures = deque(maxlen=5)
        self.lock = threading.Lock()

    def blocked(self):
        with self.lock:
            now = time.monotonic()
            while self.failures and now - self.failures[0] >= 600:
                self.failures.popleft()
            return len(self.failures) >= 5

    def failed(self):
        with self.lock:
            self.failures.append(time.monotonic())


def main():
    parser = argparse.ArgumentParser(description='Set/reset the private HomeSOC dashboard password without printing it.')
    parser.add_argument('command', choices=['set-password'])
    parser.add_argument('--username', required=True)
    args = parser.parse_args()
    password = getpass.getpass('New dashboard password (12–128 characters): ')
    confirmation = getpass.getpass('Confirm password: ')
    if password != confirmation:
        parser.error('Passwords do not match; nothing saved.')
    try:
        set_password(args.username, password)
    except ValueError as error:
        parser.error(str(error))
    print('Dashboard credentials saved privately. Previous login sessions are invalidated.')


if __name__ == '__main__':
    main()
