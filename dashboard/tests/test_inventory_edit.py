"""Inventory edits use synthetic data and explicit saved approval."""
import sqlite3
import unittest
from contextlib import closing
from unittest.mock import patch
import test_device_reviews as fixtures


class InventoryEditTests(unittest.TestCase):
    setUpClass = fixtures.DeviceReviewTests.__dict__["setUpClass"]
    tearDownClass = fixtures.DeviceReviewTests.__dict__["tearDownClass"]
    setUp = fixtures.DeviceReviewTests.setUp
    tearDown = fixtures.DeviceReviewTests.tearDown

    def post(self, mac=None, **values):
        data = {"csrf_token": self.token, "owner": "Brandon", "device_type": "phone",
                "notes": "Matched phone Wi-Fi MAC", "review": "known", "confirm_identity": "yes"}
        data.update(values)
        return self.client.post(f"/devices/{mac or self.mac}/inventory", data=data)

    def row(self):
        with closing(sqlite3.connect(self.module.DB_PATH)) as db:
            db.row_factory = sqlite3.Row
            return dict(db.execute("SELECT * FROM assets WHERE mac=?", (self.mac,)).fetchone())

    def test_save_approves_only_selected_metadata_preserving_evidence(self):
        before = self.row()
        ticket = self.ticket.read_bytes()
        self.assertEqual(self.post().status_code, 302)
        after = self.row()
        self.assertEqual(after["is_known"], 1)
        self.assertEqual(after["owner"], "Brandon")
        self.assertEqual(after["device_type"], "phone")
        self.assertEqual(after["notes"], "Matched phone Wi-Fi MAC")
        for key in ("mac", "ip", "hostname", "vendor", "first_seen", "last_seen"):
            self.assertEqual(before[key], after[key])
        self.assertEqual(self.ticket.read_bytes(), ticket)
        page = self.client.get(f"/devices/{self.mac}?inventory_saved=1").data
        self.assertIn(b"Inventory saved.", page)
        self.assertIn(b"Known</td>", page)

    def test_get_and_cancel_do_not_save(self):
        before = self.row()
        page = self.client.get(f"/devices/{self.mac}")
        self.assertIn(b"Cancel edits", page.data)
        self.assertEqual(self.client.get(f"/devices/{self.mac}/inventory").status_code, 405)
        self.assertEqual(before, self.row())

    def test_approval_requires_identity_and_owner_type(self):
        for changes in ({"confirm_identity": ""}, {"owner": ""}, {"device_type": ""}):
            self.assertEqual(self.post(**changes).status_code, 400)
            self.assertEqual(self.row()["is_known"], 0)

    def test_validation_keeps_submitted_fields_and_database(self):
        before = self.row()
        for changes in ({"review": "invalid"}, {"owner": "x"*101}, {"device_type": "x"*101}, {"notes": "x"*4001}, {"notes": "bad\x00text"}):
            self.assertEqual(self.post(**changes).status_code, 400)
            self.assertEqual(before, self.row())
        self.assertIn(b"New owner", self.post(owner="New owner", confirm_identity="").data)

    def test_csrf_and_missing_host(self):
        before = self.row()
        for token in ("", "wrong"):
            self.assertEqual(self.post(csrf_token=token).status_code, 403)
        other = self.module.app.test_client()
        self.assertEqual(other.post(f"/devices/{self.mac}/inventory", data={"csrf_token": self.token}).status_code, 403)
        self.assertEqual(self.post("aa:bb:cc:dd:ee:ff").status_code, 404)
        self.assertEqual(before, self.row())

    def test_unreviewed_can_save_notes_without_approving(self):
        self.assertEqual(self.post(review="unreviewed", owner="", device_type="", confirm_identity="").status_code, 302)
        self.assertEqual(self.row()["is_known"], 0)
        self.assertIsNone(self.row()["owner"])
        self.assertEqual(self.row()["notes"], "Matched phone Wi-Fi MAC")
        self.post()
        self.assertEqual(self.post(review="unreviewed", confirm_identity="").status_code, 302)
        self.assertEqual(self.row()["is_known"], 0)

    def test_markup_is_escaped_and_sql_text_is_data(self):
        value = "<script>alert(1)</script> ' ; DROP TABLE assets; --"
        self.assertEqual(self.post(owner=value, notes=value).status_code, 302)
        self.assertEqual(self.row()["owner"], value)
        page = self.client.get(f"/devices/{self.mac}").data
        self.assertNotIn(b"<script>alert(1)</script>", page)
        self.assertIn(b"&lt;script&gt;", page)

    def test_database_failure_leaves_inventory_unchanged(self):
        before = self.row()
        original = sqlite3.connect
        def fail_write(path, *args, **kwargs):
            if kwargs.get("uri") and "mode=rw" in str(path):
                raise sqlite3.OperationalError("database is locked")
            return original(path, *args, **kwargs)
        with patch.object(self.module.sqlite3, "connect", side_effect=fail_write):
            self.assertEqual(self.post().status_code, 503)
        self.assertEqual(before, self.row())

if __name__ == "__main__": unittest.main()
