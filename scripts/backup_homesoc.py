#!/usr/bin/env python3
"""Private HomeSOC data backups and a temporary restore check; stdlib only."""
import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import stat
import tarfile
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARCHIVE_RE = re.compile(r'^homesoc-\d{8}T\d{12}Z\.tar\.gz$')
DB_TABLES = {'db/homesoc.db': ('assets', 'scans', 'sightings'),
             'dashboard-state/incidents.db': ('incidents', 'incident_notes')}
SOURCE_DIRS = ('alerts', 'collectors', 'dashboard', 'docs', 'scanners', 'scripts', 'siem', 'systemd')
SUFFIXES = {'.py', '.html', '.css', '.js', '.md', '.sql', '.service', '.timer', '.conf', '.txt', '.png'}
EXCLUDED_DIRS = {'.git', '.venv', 'venv', '__pycache__', 'node_modules'}
MAX_RESTORE_BYTES = 1024 * 1024 * 1024


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(65536), b''):
            result.update(block)
    return result.hexdigest()


def counts(path, tables):
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError(f'SQLite integrity check failed: {path.name}')
        if db.execute('PRAGMA foreign_key_check').fetchone() is not None:
            raise ValueError(f'SQLite foreign-key check failed: {path.name}')
        return {table: db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                for table in tables}  # table names are fixed by DB_TABLES


def snapshot_database(source, target):
    if source.is_symlink() or source.parent.is_symlink() or not source.is_file():
        raise ValueError(f'Required database missing or symlinked: {source}')
    target.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + 120
    def progress(status, remaining, total):
        if time.monotonic() > deadline:
            raise TimeoutError('SQLite backup exceeded two minutes; retry later.')
    with closing(sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        with closing(sqlite3.connect(target)) as backup:
            db.backup(backup, pages=256, progress=progress, sleep=0.1)
    target.chmod(0o600)


def copy_regular(source, target):
    """Copy a stable regular file; never follow a source symlink."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as src:
        before = os.fstat(src.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f'Not a regular file: {source}')
        with target.open('wb') as dst:
            shutil.copyfileobj(src, dst)
        after = os.fstat(src.fileno())
        current = source.lstat()
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
        if identity(before) != identity(after) or identity(before) != identity(current):
            raise ValueError(f'File changed during backup; retry: {source}')
    target.chmod(0o600)


def collect_sources(root):
    result = []
    for name in ('README.md', 'requirements.txt', '.gitignore', 'db/schema.sql',
                 'collectors/logrotate.d/homesoc-remote'):
        path = root / name
        if path.is_file(): result.append(path)
    for folder in (*SOURCE_DIRS, 'evidence/alerts'):
        directory = root / folder
        if not directory.exists(): continue
        if directory.is_symlink(): raise ValueError(f'Symlinked source directory: {folder}')
        for path in directory.rglob('*'):
            relative = path.relative_to(root)
            if any(part in EXCLUDED_DIRS for part in relative.parts): continue
            if path.suffix not in SUFFIXES: continue
            if folder == 'evidence/alerts' and path.suffix != '.md': continue
            if any((root.joinpath(*relative.parts[:i])).is_symlink()
                   for i in range(1, len(relative.parts) + 1)):
                raise ValueError(f'Symlinked source: {relative}')
            if path.is_file(): result.append(path)
    return sorted(set(result))


def verify_archive(archive):
    """Restore into disposable storage, verify hashes and database readability."""
    with tempfile.TemporaryDirectory(prefix='homesoc-restore-check-') as directory:
        root = Path(directory)
        with tarfile.open(archive, 'r:gz') as bundle:
            members = bundle.getmembers()
            if len(members) > 10000 or sum(m.size for m in members) > MAX_RESTORE_BYTES:
                raise ValueError('Archive exceeds restore-check limits.')
            seen = set()
            for member in members:
                name = member.name
                parts = Path(name).parts
                if (not member.isfile() or Path(name).is_absolute() or '..' in parts
                        or name in seen or not parts):
                    raise ValueError('Archive contains an unsafe or duplicate member.')
                target = root / name
                if not target.resolve().is_relative_to(root):
                    raise ValueError('Archive path escapes temporary restore directory.')
                seen.add(name)
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(member) as source, target.open('wb') as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o600)
        manifest = json.loads((root / 'manifest.json').read_text())
        files = manifest['files']
        if set(files) != seen - {'manifest.json'}:
            raise ValueError('Archive contents do not match the manifest.')
        for name, expected in files.items():
            if digest(root / name) != expected:
                raise ValueError(f'Backup hash mismatch: {name}')
        checked = {}
        for name, tables in DB_TABLES.items():
            checked[name] = counts(root / name, tables)
            if checked[name] != manifest['database_rows'][name]:
                raise ValueError(f'Restored row counts differ: {name}')
        return checked


def prune_backups(destination, keep):
    archives = sorted((p for p in destination.iterdir()
                       if ARCHIVE_RE.fullmatch(p.name) and not p.is_symlink()
                       and p.is_file() and p.stat().st_uid == os.geteuid()), reverse=True)
    for path in archives[keep:]: path.unlink()


def create_backup(root, destination, keep=7):
    if keep < 1: raise ValueError('Keep must be at least one.')
    destination = destination.expanduser().absolute()
    if destination.is_symlink() or destination.resolve().is_relative_to(root.resolve()):
        raise ValueError('Backup directory must be outside the project and not a symlink.')
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.stat().st_uid != os.geteuid():
        raise ValueError('Backup directory must belong to the running user.')
    destination.chmod(0o700)
    lock_fd = os.open(destination / '.backup.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with tempfile.TemporaryDirectory(prefix='.stage-', dir=destination) as directory:
            stage = Path(directory)
            row_counts = {}
            for name, tables in DB_TABLES.items():
                snapshot_database(root / name, stage / name)
                row_counts[name] = counts(stage / name, tables)
            for path in collect_sources(root):
                copy_regular(path, stage / path.relative_to(root))
            files = {str(p.relative_to(stage)): digest(p) for p in sorted(stage.rglob('*')) if p.is_file()}
            manifest = {'version': 1, 'created_at': datetime.now(timezone.utc).isoformat(),
                        'host': socket.gethostname(), 'files': files, 'database_rows': row_counts}
            (stage / 'manifest.json').write_text(json.dumps(manifest, indent=2))
            stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
            archive = destination / f'homesoc-{stamp}.tar.gz'
            partial = destination / (archive.name + '.partial')
            try:
                with tarfile.open(partial, 'w:gz') as bundle:
                    for path in sorted(stage.rglob('*')):
                        if path.is_file(): bundle.add(path, arcname=str(path.relative_to(stage)), recursive=False)
                partial.chmod(0o600)
                verify_archive(partial)
                with partial.open('rb') as saved: os.fsync(saved.fileno())
                os.replace(partial, archive)
                directory_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(directory_fd)
                finally: os.close(directory_fd)
            finally:
                partial.unlink(missing_ok=True)
        # Delete old archives only after the new backup passes a restore check.
        prune_backups(destination, keep)
        return archive, row_counts
    finally:
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=Path.home() / 'homesoc-backups')
    parser.add_argument('--keep', type=int, default=7)
    parser.add_argument('--verify', type=Path, help='verify an archive via a temporary restore')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.verify:
            rows = verify_archive(args.verify)
            print('Temporary restore verified:', json.dumps(rows, sort_keys=True))
        else:
            archive, rows = create_backup(PROJECT_ROOT, args.output_dir, args.keep)
            print('Verified backup:', archive)
            print('Snapshot rows:', json.dumps(rows, sort_keys=True))
    except (OSError, ValueError, sqlite3.Error, tarfile.TarError, KeyError) as error:
        print('Backup failed:', error)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
