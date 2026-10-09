import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('sender', Path(__file__).parents[1] / 'forward_auth.py')
sender = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sender)


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'auth.log'
        self.path.write_bytes(b'existing\n')

    def test_default_starts_at_end(self):
        events, state = sender.read_events(self.path, None)
        self.assertEqual(events, [])
        with self.path.open('ab') as f:
            f.write(b'new\nunfinished')
        events, state = sender.read_events(self.path, state)
        self.assertEqual([e['event']['raw'] for e in events], ['new'])
        with self.path.open('ab') as f:
            f.write(b'\n')
        events, _ = sender.read_events(self.path, state)
        self.assertEqual(events[0]['event']['raw'], 'unfinished')

    def test_retry_identity_and_from_start(self):
        events, state = sender.read_events(self.path, None, True)
        retry, _ = sender.read_events(self.path, None, True)
        self.assertEqual(events[0]['event']['event_id'], retry[0]['event']['event_id'])
        self.assertFalse(events[0]['event']['sample_data'])
        self.assertEqual(sender.read_events(self.path, state)[0], [])

    def test_rotation_finishes_old_then_new(self):
        _, state = sender.read_events(self.path, None)
        with self.path.open('ab') as f:
            f.write(b'old remainder\n')
        self.path.rename(str(self.path) + '.1')
        self.path.write_bytes(b'new log\n')
        events, state = sender.read_events(self.path, state)
        self.assertEqual(events[0]['event']['raw'], 'old remainder')
        events, _ = sender.read_events(self.path, state)
        self.assertEqual(events[0]['event']['raw'], 'new log')

    def test_missing_rotation_and_truncation_fail(self):
        _, state = sender.read_events(self.path, None)
        self.path.write_bytes(b'')
        with self.assertRaises(ValueError):
            sender.read_events(self.path, state)
        self.path.rename(str(self.path) + '.2')
        self.path.write_bytes(b'new\n')
        with self.assertRaises(FileNotFoundError):
            sender.read_events(self.path, state)

    def test_reject_symlink(self):
        link = self.path.with_name('link')
        link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            sender.read_events(link, None)

    def test_reject_insecure_endpoint(self):
        with self.assertRaises(ValueError):
            sender.send([{}], 'http://example.com/services/collector/event', 'token', None)

    def test_failed_send_does_not_save_checkpoint(self):
        config = Path(self.temp.name) / '.config/homesoc'
        config.mkdir(parents=True)
        token = config / 'splunk-hec.token'
        token.write_text('test-token')
        token.chmod(0o600)
        original_read = sender.read_events
        with patch.object(Path, 'home', return_value=Path(self.temp.name)), \
             patch.object(sender, 'read_events', side_effect=lambda p, s, f: original_read(self.path, s, f)), \
             patch.object(sender, 'send', side_effect=OSError('offline')), \
             patch('sys.argv', ['sender', '--from-start']):
            with self.assertRaises(OSError):
                sender.main()
        self.assertFalse((Path(self.temp.name) / '.local/state/homesoc-siem/auth-checkpoint.json').exists())

    def test_atomic_checkpoint(self):
        state_path = self.path.with_name('checkpoint.json')
        sender.save_checkpoint(state_path, {'offset': 42})
        self.assertEqual(json.loads(state_path.read_text()), {'offset': 42})


if __name__ == '__main__':
    unittest.main()
