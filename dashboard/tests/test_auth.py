"""Login checks use private temporary credentials and synthetic inventory."""
from pathlib import Path
import json
import os
import time
import unittest
from unittest.mock import patch
from werkzeug.security import check_password_hash, generate_password_hash
import test_incidents as fixtures
from dashboard import auth

PASSWORD = 'Synthetic-test-password-2026'


class AuthTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.IncidentTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.IncidentTests.tearDownClass.__func__)
    tearDown = fixtures.IncidentTests.tearDown

    def setUp(self):
        fixtures.IncidentTests.setUp(self)
        if not hasattr(type(self), 'password_hash'):
            type(self).password_hash = generate_password_hash(PASSWORD, method=auth.HASH_METHOD, salt_length=16)
        self.values = dict(username='brandon', password_hash=self.password_hash, version='b'*64)
        auth.credentials_path().write_text(json.dumps(self.values))
        auth.credentials_path().chmod(0o600)
        self.client = self.module.app.test_client()
        self.client.get('/login')
        with self.client.session_transaction() as session:
            self.token = session['csrf_token']

    def login(self, **changes):
        data=dict(username='brandon',password=PASSWORD,csrf_token=self.token,next='/devices')
        data.update(changes)
        return self.client.post('/login',data=data)

    def test_all_private_reads_and_mutations_require_login(self):
        before=self.module.DB_PATH.read_bytes(), self.ticket.read_bytes()
        for path in ('/', '/devices', '/alerts', '/logs', '/incidents', '/summary', '/health', '/alerts/sample.md', '/devices/aa:bb:cc:dd:ee:01'):
            response=self.client.get(path)
            self.assertEqual(response.status_code,302,path)
            self.assertIn('/login?',response.location)
        for path in ('/incidents/from-alert/sample.md','/incidents/1/update','/incidents/1/resolve-source','/devices/aa:bb:cc:dd:ee:01/inventory','/devices/aa:bb:cc:dd:ee:01/archive'):
            self.assertEqual(self.client.post(path,data={'csrf_token':self.token}).status_code,403,path)
        self.assertEqual(before,(self.module.DB_PATH.read_bytes(),self.ticket.read_bytes()))

    def test_success_rotates_csrf_and_session_with_cookie_flags(self):
        with self.client.session_transaction() as session:
            session['unsaved_legacy_value']='old'
        response=self.login()
        self.assertEqual(response.status_code,302)
        self.assertEqual(response.location,'/devices')
        cookie=response.headers['Set-Cookie']
        self.assertIn('HttpOnly',cookie)
        self.assertIn('SameSite=Strict',cookie)
        self.assertIn('homesoc_session=',cookie)
        self.assertIn('Expires=',cookie)
        with self.client.session_transaction() as session:
            self.assertNotEqual(self.token,session['csrf_token'])
            self.assertNotIn('unsaved_legacy_value',session)
            self.assertEqual(session['auth_user'],'brandon')
        self.assertEqual(self.client.get('/alerts').status_code,200)

    def test_wrong_username_and_password_same_error(self):
        for changes in ({'password':'wrong'}, {'username':'someoneelse'}, {'password':'x'*129}):
            response=self.login(**changes)
            self.assertEqual(response.status_code,401)
            self.assertIn(b'Invalid username or password',response.data)
            self.assertNotIn(PASSWORD.encode(),response.data)

    def test_login_csrf_and_throttle(self):
        self.assertEqual(self.login(csrf_token='').status_code,403)
        self.assertEqual(self.login(csrf_token='invalid').status_code,403)
        with patch.object(auth,'verify',return_value=False):
            for _ in range(5): self.assertEqual(self.login(password='wrong').status_code,401)
        self.assertEqual(self.login().status_code,429)
        other=self.module.app.test_client();other.get('/login')
        with other.session_transaction() as session: other_token=session['csrf_token']
        self.assertEqual(other.post('/login',data={'csrf_token':other_token,'username':'brandon','password':PASSWORD}).status_code,429)

    def test_throttle_expires_and_remains_bounded(self):
        throttle=auth.LoginThrottle()
        with patch.object(auth.time,'monotonic',return_value=100):
            for _ in range(20):throttle.failed()
            self.assertTrue(throttle.blocked())
            self.assertEqual(len(throttle.failures),5)
        with patch.object(auth.time,'monotonic',return_value=701):self.assertFalse(throttle.blocked())

    def test_logout_post_and_csrf(self):
        self.login()
        with self.client.session_transaction() as session: token=session['csrf_token']
        self.assertEqual(self.client.get('/logout').status_code,405)
        self.assertEqual(self.client.post('/logout',data={'csrf_token':'wrong'}).status_code,403)
        self.assertEqual(self.client.get('/alerts').status_code,200)
        self.assertEqual(self.client.post('/logout',data={'csrf_token':token}).status_code,302)
        self.assertEqual(self.client.get('/alerts').status_code,302)

    def test_absolute_session_expiry_and_reset_invalidation(self):
        self.login()
        with self.client.session_transaction() as session:session['auth_issued_at']=time.time()-auth.SESSION_SECONDS-1
        self.assertEqual(self.client.get('/alerts').status_code,302)
        with self.client.session_transaction() as session:
            session.update(auth_user='brandon',auth_version=self.values['version'],auth_issued_at=time.time())
        self.assertEqual(self.client.get('/alerts').status_code,200)
        self.values['version']='c'*64
        auth.credentials_path().write_text(json.dumps(self.values))
        self.assertEqual(self.client.get('/alerts').status_code,302)

    def test_session_not_refreshed_and_legacy_cookie_not_authorized(self):
        self.login()
        with self.client.session_transaction() as session: issued=session['auth_issued_at']
        self.client.get('/alerts')
        with self.client.session_transaction() as session:self.assertEqual(issued,session['auth_issued_at'])
        other=self.module.app.test_client()
        with other.session_transaction() as session:session['csrf_token']='legacy'
        self.assertEqual(other.get('/alerts').status_code,302)
        self.assertEqual(self.module.app.config['SESSION_REFRESH_EACH_REQUEST'],False)

    def test_no_external_redirects(self):
        for target in ('https://example.com/', '//example.com/', '/\\example.com', '/\nexample.com'):
            self.client.get('/login')
            with self.client.session_transaction() as session:self.token=session['csrf_token']
            self.assertEqual(self.login(next=target).location,'/')
            with self.client.session_transaction() as session:session.clear()

    def test_missing_invalid_and_public_credentials_fail_closed(self):
        path=auth.credentials_path()
        for value in ('missing', 'invalid', 'public'):
            path.unlink(missing_ok=True)
            if value=='invalid':path.write_text('{bad json');path.chmod(0o600)
            if value=='public':path.write_text(json.dumps(self.values));path.chmod(0o644)
            self.assertEqual(self.client.get('/alerts').status_code,503)
            self.assertEqual(self.client.post('/incidents/from-alert/sample.md',data={'csrf_token':self.token}).status_code,503)

    def test_symlink_hardlink_and_nonregular_credentials_rejected(self):
        path=auth.credentials_path();path.unlink()
        target=self.root/'target.json';target.write_text(json.dumps(self.values));target.chmod(0o600)
        path.symlink_to(target)
        with self.assertRaises(auth.AuthConfigError):auth.read_credentials()
        with self.assertRaises(ValueError):auth.set_password('brandon',PASSWORD)
        path.unlink();os.link(target,path)
        with self.assertRaises(auth.AuthConfigError):auth.read_credentials()
        path.unlink();path.mkdir()
        with self.assertRaises(auth.AuthConfigError):auth.read_credentials()

    def test_set_password_private_hash_and_new_version(self):
        previous=self.values['version']
        values=auth.set_password('brandon',PASSWORD)
        self.assertNotEqual(values['version'],previous)
        self.assertTrue(check_password_hash(values['password_hash'],PASSWORD))
        self.assertEqual(auth.read_credentials(),values)
        self.assertEqual(auth.credentials_path().stat().st_mode & 0o777,0o600)
        self.assertNotIn(PASSWORD,auth.credentials_path().read_text())
        for username,password in (('bad user',PASSWORD),('brandon','short'),('brandon','x'*129)):
            with self.assertRaises(ValueError):auth.set_password(username,password)

    def test_private_pages_no_cache_and_login_does_not_show_nav(self):
        response=self.client.get('/login')
        self.assertEqual(response.headers['Cache-Control'],'no-store')
        self.assertEqual(response.headers['X-Frame-Options'],'DENY')
        self.assertNotIn(b'>Recent Logs</a>',response.data)
        self.login()
        page=self.client.get('/alerts')
        self.assertIn(b'Log out',page.data)
        self.assertEqual(page.headers['Cache-Control'],'no-store')

if __name__=='__main__':unittest.main()
