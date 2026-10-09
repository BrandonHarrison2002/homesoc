"""Regression tests using temporary logs and state, never the live auth log."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from alerts import ssh_bruteforce_watcher as watcher


class WindowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / 'auth.log'
        self.log.touch()
        self.state_file = self.root / 'state.json'
        self.alerts = self.root / 'alerts'
        self.now = datetime(2026, 10, 9, 20, 0, tzinfo=timezone.utc)

    def append(self, count, at, ip='192.168.8.119', newline=True):
        with self.log.open('a') as stream:
            for i in range(count):
                ts = (at + timedelta(seconds=i)).isoformat(timespec='microseconds')
                stream.write(f'{ts} pi-monitor sshd-session[123]: Invalid user test from {ip} port 12345' + ('\n' if newline else ''))

    def run_once(self, at):
        state = watcher.load_state(self.state_file)
        offset, inode, count = watcher.process_log(self.log, state, self.alerts, now=at)
        watcher.save_state(self.state_file, offset, inode, state.get('recent_events', []))
        return count

    def test_three_then_two_across_runs(self):
        self.append(3, self.now)
        self.assertEqual(self.run_once(self.now + timedelta(minutes=1)), 0)
        self.assertEqual(len(watcher.load_state(self.state_file)['recent_events']), 3)
        self.append(2, self.now + timedelta(minutes=5))
        self.assertEqual(self.run_once(self.now + timedelta(minutes=6)), 1)
        ticket = next(self.alerts.glob('*.md')).read_text()
        self.assertIn('failure_count: 5', ticket)

    def test_expired_attempts_do_not_count(self):
        self.append(3, self.now)
        self.run_once(self.now + timedelta(minutes=1))
        self.append(2, self.now + timedelta(minutes=12))
        self.assertEqual(self.run_once(self.now + timedelta(minutes=13)), 0)
        self.assertEqual(len(watcher.load_state(self.state_file)['recent_events']), 2)

    def test_separate_ips_do_not_combine(self):
        self.append(3, self.now)
        self.append(2, self.now, ip='192.168.8.120')
        self.assertEqual(self.run_once(self.now + timedelta(minutes=1)), 0)

    def test_closing_ticket_does_not_replay_burst(self):
        self.append(5, self.now)
        self.assertEqual(self.run_once(self.now + timedelta(minutes=1)), 1)
        ticket = next(self.alerts.glob('*.md'))
        ticket.write_text(ticket.read_text().replace('status: open', 'status: resolved'))
        self.assertEqual(self.run_once(self.now + timedelta(minutes=2)), 0)
        self.assertEqual(watcher.load_state(self.state_file)['recent_events'], [])

    def test_open_ticket_suppresses_and_consumes_new_burst(self):
        self.append(5, self.now)
        self.assertEqual(self.run_once(self.now + timedelta(minutes=1)), 1)
        self.append(5, self.now + timedelta(minutes=2))
        self.assertEqual(self.run_once(self.now + timedelta(minutes=3)), 0)
        self.assertEqual(len(list(self.alerts.glob('*.md'))), 1)
        self.assertEqual(watcher.load_state(self.state_file)['recent_events'], [])

    def test_existing_state_preserves_cursor(self):
        self.append(5, self.now)
        watcher.save_state(self.state_file, self.log.stat().st_size, self.log.stat().st_ino)
        import json
        state = json.loads(self.state_file.read_text())
        del state['recent_events']
        self.state_file.write_text(json.dumps(state))
        self.assertEqual(self.run_once(self.now + timedelta(minutes=1)), 0)
        self.append(2, self.now + timedelta(minutes=2))
        self.assertEqual(self.run_once(self.now + timedelta(minutes=3)), 0)

    def test_partial_line_is_retried(self):
        self.append(1, self.now, newline=False)
        self.run_once(self.now + timedelta(minutes=1))
        self.assertEqual(watcher.load_state(self.state_file)['last_byte_offset'], 0)
        with self.log.open('a') as stream:
            stream.write('\n')
        self.run_once(self.now + timedelta(minutes=2))
        self.assertEqual(len(watcher.load_state(self.state_file)['recent_events']), 1)

    def test_old_log_history_does_not_alert(self):
        self.append(5, self.now - timedelta(days=1))
        self.assertEqual(self.run_once(self.now), 0)


if __name__ == '__main__':
    unittest.main()
