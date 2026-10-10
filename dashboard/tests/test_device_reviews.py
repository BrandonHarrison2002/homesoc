"""Stale-device filtering/archive tests never change live inventory."""
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from contextlib import closing
import test_incidents as fixtures
from dashboard import device_reviews


class DeviceReviewTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.IncidentTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.IncidentTests.tearDownClass.__func__)
    tearDown = fixtures.IncidentTests.tearDown

    def setUp(self):
        fixtures.IncidentTests.setUp(self)
        self.mac = 'aa:bb:cc:dd:ee:01'
        self.recent_mac = 'aa:bb:cc:dd:ee:02'
        self.old = (datetime.now(timezone.utc) - timedelta(days=100)).strftime('%Y-%m-%d %H:%M:%S')
        self.recent = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        with closing(sqlite3.connect(self.module.DB_PATH)) as db:
            for mac, ip, seen in ((self.mac, '192.0.2.101', self.old), (self.recent_mac, '192.0.2.102', self.recent)):
                db.execute('INSERT INTO assets(mac,ip,is_known,first_seen,last_seen) VALUES(?,?,0,?,?)', (mac, ip, seen, seen))
            db.commit()

    def post(self, mac=None, **data):
        return self.client.post(f'/devices/{mac or self.mac}/archive', data={'csrf_token': self.token, 'reason': 'Historical unidentified fixture, retained for review.', **data})

    def test_archive_preserves_inventory_and_detector_approval(self):
        before = self.module.DB_PATH.read_bytes()
        ticket = self.ticket.read_bytes()
        self.assertEqual(self.post().status_code, 302)
        self.assertEqual(self.module.DB_PATH.read_bytes(), before)
        self.assertEqual(self.ticket.read_bytes(), ticket)
        device, _ = self.module.get_host_detail(self.mac)
        self.assertEqual(device['is_known'], 0)
        self.assertTrue(device_reviews.annotate(device, device_reviews.records())['archived'])
        self.assertIn(b'Return to active review', self.client.get(f'/devices/{self.mac}').data)

    def test_default_view_hides_archived_and_filters_show_it(self):
        self.post()
        active = self.client.get('/').data
        self.assertNotIn(b'192.0.2.101', active)
        self.assertIn(b'192.0.2.102', active)
        self.assertIn(b'192.0.2.101', self.client.get('/?visibility=archived').data)
        self.assertNotIn(b'192.0.2.102', self.client.get('/?visibility=archived').data)
        self.assertIn(b'192.0.2.101', self.client.get('/?visibility=all').data)
        self.assertIn(b'UNREVIEWED', active)
        self.assertNotIn(b'>NEW</span>', active)

    def test_age_search_and_review_filters_combine(self):
        old = self.client.get('/?age=stale90&review=unreviewed').data
        self.assertIn(b'192.0.2.101', old)
        self.assertNotIn(b'192.0.2.102', old)
        recent = self.client.get('/?age=recent7').data
        self.assertNotIn(b'192.0.2.101', recent)
        self.assertIn(b'192.0.2.102', recent)
        self.assertNotIn(b'192.0.2.101', self.client.get('/?age=stale30&q=nomatch').data)
        self.assertEqual(self.client.get('/?age=bogus&visibility=bogus').status_code, 200)

    def test_recent_and_unknown_age_devices_cannot_be_archived(self):
        self.assertEqual(self.post(self.recent_mac).status_code, 400)
        with closing(sqlite3.connect(self.module.DB_PATH)) as db:
            db.execute('UPDATE assets SET last_seen=? WHERE mac=?', ('not a timestamp', self.mac))
            db.commit()
        self.assertEqual(self.post().status_code, 400)

    def test_reason_validation(self):
        for reason in ('short', 'x' * 1001):
            self.assertEqual(self.post(reason=reason).status_code, 400)
        self.assertEqual(device_reviews.records(), {})

    def test_get_and_csrf_cannot_archive(self):
        self.assertEqual(self.client.get(f'/devices/{self.mac}/archive').status_code, 405)
        self.assertEqual(self.post(csrf_token='wrong').status_code, 403)
        other = self.module.app.test_client()
        self.assertEqual(other.post(f'/devices/{self.mac}/archive', data={'csrf_token': self.token}).status_code, 403)
        self.assertEqual(device_reviews.records(), {})

    def test_restore_retains_reason_and_unknown_state(self):
        self.post()
        self.assertEqual(self.post(action='restore').status_code, 302)
        device, _ = self.module.get_host_detail(self.mac)
        annotated = device_reviews.annotate(device, device_reviews.records())
        self.assertFalse(annotated['archived'])
        self.assertEqual(device['is_known'], 0)
        self.assertIn('Historical unidentified', annotated['archive_record']['reason'])
        self.assertIn(b'192.0.2.101', self.client.get('/').data)

    def test_new_sighting_reactivates_without_trusting(self):
        self.post()
        with closing(sqlite3.connect(self.module.DB_PATH)) as db:
            db.execute('UPDATE assets SET last_seen=? WHERE mac=?', (self.recent, self.mac))
            db.commit()
        self.assertIn(b'192.0.2.101', self.client.get('/').data)
        self.assertIn(b'discovery has since seen this device again', self.client.get(f'/devices/{self.mac}').data)
        device, _ = self.module.get_host_detail(self.mac)
        self.assertEqual(device['is_known'], 0)

    def test_missing_device_and_invalid_action(self):
        self.assertEqual(self.post('aa:bb:cc:dd:ee:ff').status_code, 404)
        self.assertEqual(self.post(action='delete').status_code, 400)

    def test_archive_reason_is_escaped(self):
        self.post(reason='Synthetic <script>alert(1)</script> archive reason')
        page = self.client.get(f'/devices/{self.mac}').data
        self.assertNotIn(b'<script>alert(1)</script>', page)
        self.assertIn(b'&lt;script&gt;', page)

    def test_utc_age_parsing(self):
        now = datetime(2026, 10, 10, 20, tzinfo=timezone.utc)
        self.assertEqual(device_reviews.age_days('2026-09-10 20:00:00', now), 30)
        self.assertEqual(device_reviews.age_days('2026-09-10T16:00:00-04:00', now), 30)
        self.assertIsNone(device_reviews.age_days('unknown', now))


if __name__ == '__main__': unittest.main()
