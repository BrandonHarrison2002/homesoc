"""Synthetic integration checks; no live inventory, tickets or networks are used."""
import importlib
from contextlib import closing
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

class IncidentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.import_temp = tempfile.TemporaryDirectory()
        cls.original_state_env = os.environ.get('HOMESOC_INCIDENT_STATE_DIR')
        os.environ['HOMESOC_INCIDENT_STATE_DIR'] = cls.import_temp.name
        cls.module = importlib.import_module('dashboard.app')
        cls.store = cls.module.incident_store
        cls.original_paths = (cls.module.DB_PATH, cls.module.ALERTS_DIR, cls.store.STATE_DIR)
    @classmethod
    def tearDownClass(cls):
        cls.module.DB_PATH, cls.module.ALERTS_DIR, cls.store.STATE_DIR = cls.original_paths
        if cls.original_state_env is None:
            os.environ.pop('HOMESOC_INCIDENT_STATE_DIR', None)
        else:
            os.environ['HOMESOC_INCIDENT_STATE_DIR'] = cls.original_state_env
        cls.import_temp.cleanup()
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store.STATE_DIR = self.root/'state'
        self.module.app.secret_key = self.store.get_session_key()
        self.module.ALERTS_DIR = self.root/'alerts';self.module.ALERTS_DIR.mkdir()
        self.module.DB_PATH = self.root/'inventory.db'
        with closing(sqlite3.connect(self.module.DB_PATH)) as db:
            db.executescript((self.module.PROJECT_ROOT/'db/schema.sql').read_text())
        self.ticket = self.module.ALERTS_DIR/'sample.md'
        self.ticket.write_text('---\nstatus: open\nseverity: medium\ndetected_by: sample-test\n---\n# Synthetic alert\nSample evidence only.')
        self.client = self.module.app.test_client()
        self.module.app.config['TESTING'] = True
        credentials = dict(username='fixture', password_hash='pbkdf2:sha256:600000$ABCDEFGHIJKLMNOP$' + 'a'*64, version='a'*64)
        (self.store.STATE_DIR / 'auth.json').write_text(__import__('json').dumps(credentials))
        (self.store.STATE_DIR / 'auth.json').chmod(0o600)
        self.module.login_throttle = self.module.dashboard_auth.LoginThrottle()
        with self.client.session_transaction() as session:
            session.update(auth_user='fixture', auth_version=credentials['version'], auth_issued_at=time.time())
            session.permanent = True
        self.client.get('/alerts/sample.md')
        with self.client.session_transaction() as session:
            self.token = session['csrf_token']
    def tearDown(self):
        self.temp.cleanup()
    def create(self):
        return self.client.post('/incidents/from-alert/sample.md',data={'csrf_token':self.token})
    def save(self, **changes):
        data=dict(csrf_token=self.token,status='Investigating',priority='medium',owner='Brandon',resolution='',note='')
        data.update(changes)
        return self.client.post('/incidents/1/update',data=data)
    def test_creation_duplicate_link_and_persistence(self):
        response=self.create()
        self.assertEqual(response.status_code,302)
        self.assertEqual(response.location,'/incidents/1')
        self.assertEqual(self.create().location,'/incidents/1')
        self.assertEqual(len(self.store.list_incidents()),1)
        self.assertIn(b'INC-0001',self.client.get('/incidents').data)
        self.assertIn(b'Source status: open',self.client.get('/incidents/1').data)
        self.assertEqual(self.store.get_incident(1)[0]['title'],'Synthetic alert')
        self.assertEqual(self.store.get_session_key(),self.module.app.secret_key)
    def test_workflow_notes_resolution_and_read_only_sources(self):
        before_ticket=self.ticket.read_bytes();before_db=self.module.DB_PATH.read_bytes()
        self.create()
        self.assertEqual(self.save(note='Reviewed sample evidence').status_code,302)
        self.assertEqual(self.save(status='Resolved').status_code,400)
        self.assertEqual(self.store.get_incident(1)[0]['status'],'Investigating')
        self.assertEqual(self.save(status='Resolved',resolution='Confirmed authorized sample activity').status_code,302)
        incident,notes=self.store.get_incident(1)
        self.assertEqual(incident['status'],'Resolved')
        self.assertEqual(incident['owner'],'Brandon')
        self.assertEqual(len(notes),3)
        self.assertEqual(self.ticket.read_bytes(),before_ticket)
        self.assertEqual(self.module.DB_PATH.read_bytes(),before_db)
        self.assertNotIn(b'INC-0001',self.client.get('/incidents?status=Open').data)
    def test_csrf_session_isolation_missing_cases_and_invalid_input(self):
        self.assertEqual(self.client.post('/incidents/from-alert/sample.md').status_code,403)
        self.assertEqual(self.client.post('/incidents/from-alert/sample.md',data={'csrf_token':'invalid-令牌'}).status_code,403)
        other=self.module.app.test_client()
        self.assertEqual(other.post('/incidents/from-alert/sample.md',data={'csrf_token':self.token}).status_code,403)
        self.assertEqual(self.client.get('/incidents/999').status_code,404)
        self.assertEqual(self.client.post('/incidents/from-alert/missing.md',data={'csrf_token':self.token}).status_code,404)
        self.assertEqual(self.client.get('/incidents/from-alert/sample.md').status_code,200)
        self.assertEqual(len(self.store.list_incidents()),0)
        self.create()
        for data in [dict(status='Bogus'),dict(priority='Bogus'),dict(owner='x'*81),dict(note='x'*4001)]:
            self.assertEqual(self.save(**data).status_code,400)
        self.assertEqual(self.store.get_incident(1)[0]['status'],'Open')
    def test_new_form_cancel_invalid_save_and_initial_values(self):
        page=self.client.get('/incidents/from-alert/sample.md')
        self.assertEqual(page.status_code,200)
        self.assertIn(b'Unsaved form',page.data)
        self.assertEqual(len(self.store.list_incidents()),0)
        self.client.get('/alerts/sample.md')
        self.assertEqual(len(self.store.list_incidents()),0)
        data=dict(csrf_token=self.token,status='Resolved',priority='low',owner='Brandon',resolution='',note='Reviewed synthetic evidence')
        self.assertEqual(self.client.post('/incidents/from-alert/sample.md',data=data).status_code,400)
        self.assertEqual(len(self.store.list_incidents()),0)
        data['resolution']='Confirmed benign activity from my own login attempts'
        saved=self.client.post('/incidents/from-alert/sample.md',data=data)
        self.assertEqual(saved.status_code,302)
        incident,notes=self.store.get_incident(1)
        self.assertEqual(incident['status'],'Resolved')
        self.assertEqual(incident['owner'],'Brandon')
        self.assertEqual(len(notes),1)
        self.assertEqual(self.client.get('/incidents/from-alert/sample.md').location,'/incidents/1')
        data['owner']='Should not overwrite'
        self.client.post('/incidents/from-alert/sample.md',data=data)
        self.assertEqual(self.store.get_incident(1)[0]['owner'],'Brandon')
    def test_safe_text_deleted_source_and_no_duplicate_on_refresh(self):
        self.create()
        self.save(note='<script>sample()</script>')
        html=self.client.get('/incidents/1').get_data(as_text=True)
        self.assertNotIn('<script>sample()</script>',html)
        self.assertIn('&lt;script&gt;',html)
        self.ticket.unlink()
        self.assertIn(b'no longer available',self.client.get('/incidents/1').data)
        self.client.get('/incidents/1');self.client.get('/incidents/1')
        self.assertEqual(len(self.store.get_incident(1)[1]),2)

if __name__=='__main__':unittest.main()
