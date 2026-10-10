"""Backup/restore tests use temporary projects, never live HomeSOC data."""
import importlib.util
import io
import json
import os
import sqlite3
import stat
import tarfile
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('homesoc_backup', Path(__file__).resolve().parents[1] / 'backup_homesoc.py')
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.root = self.parent / 'project'
        self.root.mkdir()
        self.output = self.parent / 'backups'
        for name, tables in backup.DB_TABLES.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with closing(sqlite3.connect(path)) as db:
                for table in tables:
                    db.execute(f'CREATE TABLE {table} (id INTEGER PRIMARY KEY, value TEXT)')
                    db.execute(f'INSERT INTO {table}(value) VALUES(?)', ('sample fixture',))
                db.commit()
        self.alerts = self.root / 'evidence/alerts'
        self.alerts.mkdir(parents=True)
        (self.alerts / 'sample.md').write_text('# Synthetic evidence\n')
        (self.root / 'README.md').write_text('# Synthetic HomeSOC\n')
        (self.root / 'dashboard-state/session.key').write_text('synthetic-secret')
        (self.root / 'alerts').mkdir()
        (self.root / 'alerts/.watcher_state.json').write_text('{"last_byte_offset":123}')

    def test_round_trip_rows_evidence_and_private_permissions(self):
        original = (self.root / 'db/homesoc.db').read_bytes()
        archive, rows = backup.create_backup(self.root, self.output)
        self.assertEqual(backup.verify_archive(archive), rows)
        self.assertEqual(rows['db/homesoc.db']['assets'], 1)
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        with tarfile.open(archive) as bundle:
            names = bundle.getnames()
            self.assertIn('evidence/alerts/sample.md', names)
            self.assertNotIn('dashboard-state/session.key', names)
            self.assertNotIn('alerts/.watcher_state.json', names)
        self.assertEqual((self.root / 'db/homesoc.db').read_bytes(), original)

    def test_wal_database_snapshot_includes_committed_rows(self):
        with closing(sqlite3.connect(self.root / 'db/homesoc.db')) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('INSERT INTO assets(value) VALUES(?)', ('committed WAL sample',))
            db.commit()
            archive, rows = backup.create_backup(self.root, self.output)
            self.assertEqual(rows['db/homesoc.db']['assets'], 2)
            self.assertEqual(backup.verify_archive(archive)['db/homesoc.db']['assets'], 2)

    def test_retention_does_not_delete_unrelated_files(self):
        self.output.mkdir()
        unrelated = self.output / 'personal.tar.gz'
        unrelated.write_text('keep me')
        for _ in range(3): backup.create_backup(self.root, self.output, keep=2)
        archives = [p for p in self.output.iterdir() if backup.ARCHIVE_RE.fullmatch(p.name)]
        self.assertEqual(len(archives), 2)
        self.assertTrue(unrelated.exists())

    def test_failed_new_backup_preserves_existing_archive(self):
        old, _ = backup.create_backup(self.root, self.output)
        with patch.object(backup, 'verify_archive', side_effect=ValueError('synthetic failed restore')):
            with self.assertRaises(ValueError): backup.create_backup(self.root, self.output, keep=1)
        self.assertTrue(old.exists())
        self.assertEqual(list(self.output.glob('*.partial')), [])
        self.assertEqual(list(self.output.glob('.stage-*')), [])

    def test_missing_database_and_symlink_are_rejected(self):
        (self.root / 'dashboard-state/incidents.db').unlink()
        with self.assertRaises(ValueError): backup.create_backup(self.root, self.output)
        (self.root / 'dashboard-state/incidents.db').symlink_to(self.root / 'db/homesoc.db')
        with self.assertRaises(ValueError): backup.create_backup(self.root, self.output)

    def test_backup_inside_repo_is_rejected(self):
        with self.assertRaises(ValueError): backup.create_backup(self.root, self.root / 'backup')

    def test_unsafe_archive_paths_and_links_rejected(self):
        for kind in ('path', 'link'):
            archive = self.parent / f'{kind}.tar.gz'
            with tarfile.open(archive, 'w:gz') as bundle:
                member = tarfile.TarInfo('../escape' if kind == 'path' else 'link')
                if kind == 'link':
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/etc/passwd'
                    bundle.addfile(member)
                else:
                    member.size = 1
                    bundle.addfile(member, io.BytesIO(b'x'))
            with self.assertRaises(ValueError): backup.verify_archive(archive)
        self.assertFalse((self.parent / 'escape').exists())

    def test_hash_tamper_detected(self):
        good, _ = backup.create_backup(self.root, self.output)
        bad = self.parent / 'tampered.tar.gz'
        with tarfile.open(good) as source, tarfile.open(bad, 'w:gz') as dest:
            for member in source.getmembers():
                data = source.extractfile(member).read()
                if member.name == 'README.md': data = b'tampered synthetic content'
                member.size = len(data)
                dest.addfile(member, io.BytesIO(data))
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            backup.verify_archive(bad)


if __name__ == '__main__':
    unittest.main()
