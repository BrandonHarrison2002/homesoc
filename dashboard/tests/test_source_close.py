"""Source closure checks using synthetic tickets and temporary databases only."""
import os
import stat
import unittest
from unittest.mock import patch
import test_incidents as fixtures
from dashboard import source_tickets


class SourceCloseTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.IncidentTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.IncidentTests.tearDownClass.__func__)
    setUp = fixtures.IncidentTests.setUp
    tearDown = fixtures.IncidentTests.tearDown
    create = fixtures.IncidentTests.create
    save = fixtures.IncidentTests.save

    def close_source(self, **data):
        return self.client.post('/incidents/1/resolve-source',
                                data={'csrf_token': self.token, **data})

    def resolved_case(self):
        self.create()
        self.save(status='Resolved', resolution='Authorized synthetic lab activity; no containment needed.')

    def test_saved_resolution_closure_and_no_duplicate_refresh(self):
        original = self.ticket.read_text()
        inventory = self.module.DB_PATH.read_bytes()
        self.ticket.chmod(0o640)
        self.resolved_case()
        page = self.client.get('/incidents/1').data
        self.assertIn(b'Resolve source alert</button>', page)
        # Submitted edits on the other form must not override the saved resolution.
        response = self.close_source(resolution='Unsubmitted override')
        self.assertEqual(response.status_code, 302)
        text = self.ticket.read_text()
        self.assertIn('status: resolved', text)
        self.assertIn(original.split('---', 2)[2], text)
        self.assertIn('Authorized synthetic lab activity', text)
        self.assertNotIn('Unsubmitted override', text)
        self.assertIn('INC-0001', text)
        self.assertEqual(stat.S_IMODE(self.ticket.stat().st_mode), 0o640)
        notes = self.store.get_incident(1)[1]
        self.assertIn('Source alert resolved', notes[-1]['body'])
        self.assertEqual(self.close_source().status_code, 302)
        self.assertEqual(len(self.store.get_incident(1)[1]), len(notes))
        self.assertEqual(self.ticket.read_text(), text)
        self.assertIn(b'Source alert is resolved.', self.client.get('/incidents/1').data)
        self.assertEqual(self.module.DB_PATH.read_bytes(), inventory)

    def test_no_get_or_unresolved_case_mutation(self):
        self.create()
        original = self.ticket.read_bytes()
        self.assertEqual(self.client.get('/incidents/1/resolve-source').status_code, 405)
        self.assertEqual(self.close_source().status_code, 400)
        self.assertEqual(self.ticket.read_bytes(), original)
        self.assertNotIn(b'Resolve source alert</button>', self.client.get('/incidents/1').data)
        self.resolved_case()
        self.assertEqual(self.ticket.read_bytes(), original)

    def test_missing_and_wrong_csrf_rejected(self):
        self.resolved_case()
        original = self.ticket.read_bytes()
        for data in ({}, {'csrf_token': 'wrong'}):
            self.assertEqual(self.client.post('/incidents/1/resolve-source', data=data).status_code, 403)
        other = self.module.app.test_client()
        self.assertEqual(other.post('/incidents/1/resolve-source', data={'csrf_token': self.token}).status_code, 403)
        self.assertEqual(self.ticket.read_bytes(), original)

    def test_missing_case_and_source(self):
        self.assertEqual(self.client.post('/incidents/99/resolve-source', data={'csrf_token': self.token}).status_code, 404)
        self.resolved_case()
        self.ticket.unlink()
        self.assertEqual(self.close_source().status_code, 409)
        self.assertEqual(self.store.get_incident(1)[0]['status'], 'Resolved')

    def test_symlink_and_traversal_rejected(self):
        self.resolved_case()
        outside = self.root / 'outside.md'
        outside.write_text(self.ticket.read_text())
        before = outside.read_bytes()
        self.ticket.unlink()
        self.ticket.symlink_to(outside)
        self.assertEqual(self.close_source().status_code, 409)
        self.assertEqual(outside.read_bytes(), before)
        for filename in ('../outside.md', str(outside), 'sample.md\x00'):
            with self.assertRaises(ValueError):
                source_tickets.resolve_source(self.module.ALERTS_DIR, filename, 1, 'Valid sample resolution')

    def test_malformed_status_large_ticket_and_invalid_utf8_rejected(self):
        self.resolved_case()
        fixtures = [b'no header', b'---\nstatus: open\n',
                    b'---\nstatus: open\nstatus: resolved\n---\n',
                    b'---\nstatus: investigating\n---\n', b'\xff',
                    b'x' * (source_tickets.MAX_TICKET_BYTES + 1)]
        for data in fixtures:
            with self.subTest(data=data[:40]):
                self.ticket.write_bytes(data)
                self.assertEqual(self.close_source().status_code, 400)
                self.assertEqual(self.ticket.read_bytes(), data)

    def test_atomic_replace_failure_leaves_original_and_no_audit(self):
        self.resolved_case()
        original = self.ticket.read_bytes()
        count = len(self.store.get_incident(1)[1])
        with patch.object(source_tickets.os, 'replace', side_effect=PermissionError):
            self.assertEqual(self.close_source().status_code, 409)
        self.assertEqual(self.ticket.read_bytes(), original)
        self.assertEqual(len(self.store.get_incident(1)[1]), count)
        self.assertEqual(list(self.module.ALERTS_DIR.glob('.source-close-*.tmp')), [])

    def test_short_saved_resolution_rejected(self):
        self.resolved_case()
        before = self.ticket.read_bytes()
        with self.assertRaises(ValueError):
            source_tickets.resolve_source(self.module.ALERTS_DIR, 'sample.md', 1, 'short')
        self.assertEqual(self.ticket.read_bytes(), before)

    def test_resolution_text_escaped_in_page(self):
        self.create()
        self.save(status='Resolved', resolution='Synthetic <script>alert(1)</script> evidence.')
        self.close_source()
        response = self.client.get('/alerts/sample.md').data
        self.assertNotIn(b'<script>alert(1)</script>', response)
        self.assertIn(b'&lt;script&gt;', response)

    def test_crlf_and_hardlinks(self):
        self.resolved_case()
        self.ticket.write_bytes(b'---\r\nstatus: open\r\nseverity: low\r\n---\r\n# Sample\r\n')
        self.assertEqual(self.close_source().status_code, 302)
        self.assertIn(b'status: resolved\r\n', self.ticket.read_bytes())
        self.ticket.write_text('---\nstatus: open\n---\n')
        os.link(self.ticket, self.root / 'hardlink.md')
        self.assertEqual(self.close_source().status_code, 400)
        self.assertIn('status: open', self.ticket.read_text())


if __name__ == '__main__':
    unittest.main()
