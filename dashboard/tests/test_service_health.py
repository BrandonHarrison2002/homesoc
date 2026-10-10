"""Synthetic systemd properties; tests never change real services."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch
import subprocess
import unittest
import test_incidents as fixtures
from dashboard import service_health as health

NOW = datetime(2026, 10, 10, 20, tzinfo=timezone.utc)


def stamp(dt):
    return '@' + str(dt.timestamp())


def units_for(job=health.JOBS[0]):
    base = job[1]
    return {base+'.timer': {'Id': base+'.timer', 'LoadState': 'loaded', 'ActiveState': 'active',
                            'SubState': 'waiting', 'UnitFileState': 'enabled',
                            'LastTriggerUSec': stamp(NOW-timedelta(minutes=2)),
                            'NextElapseUSecRealtime': stamp(NOW+timedelta(minutes=13))},
            base+'.service': {'Id': base+'.service', 'LoadState': 'loaded', 'ActiveState': 'inactive',
                              'SubState': 'dead', 'Result': 'success', 'ExecMainStatus': '0',
                              'ExecMainStartTimestamp': stamp(NOW-timedelta(minutes=2)),
                              'ExecMainExitTimestamp': stamp(NOW-timedelta(minutes=1))}}


def output_for(units):
    return '\n\n'.join('\n'.join(f'{key}={value}' for key, value in props.items()) for props in units.values())


class HealthRulesTests(unittest.TestCase):
    def assess(self, units, job=health.JOBS[0], uptime=200000):
        return health.assess(job, units, NOW, uptime)

    def test_successful_inactive_oneshot_is_healthy(self):
        row = self.assess(units_for())
        self.assertEqual(row['status'], 'Healthy')
        self.assertEqual(row['service_state'], 'inactive')
        self.assertEqual(row['last_finish'], '2026-10-10 19:59:00 UTC')

    def test_failed_result_and_exit_are_reported(self):
        units=units_for(); units['homesoc-discovery.service'].update(Result='exit-code',ExecMainStatus='1',ActiveState='failed')
        row=self.assess(units)
        self.assertEqual(row['tone'], 'failure')
        self.assertEqual(row['exit_code'], '1')

    def test_timer_inactive_disabled_and_runtime_enabled(self):
        for changes in ({'ActiveState': 'inactive'}, {'UnitFileState': 'disabled'}, {'UnitFileState': 'enabled-runtime'}):
            units=units_for(); units['homesoc-discovery.timer'].update(changes)
            self.assertEqual(self.assess(units)['tone'], 'warning')

    def test_overdue_and_daily_backup_thresholds(self):
        units=units_for(); units['homesoc-discovery.service']['ExecMainExitTimestamp']=stamp(NOW-timedelta(minutes=46))
        self.assertEqual(self.assess(units)['status'], 'Overdue')
        job=health.JOBS[-1];units=units_for(job)
        units[job[1]+'.service']['ExecMainExitTimestamp']=stamp(NOW-timedelta(hours=25))
        self.assertEqual(self.assess(units,job)['status'], 'Healthy')
        units[job[1]+'.service']['ExecMainExitTimestamp']=stamp(NOW-timedelta(hours=31))
        self.assertEqual(self.assess(units,job)['status'], 'Overdue')

    def test_running_and_long_running(self):
        units=units_for();units['homesoc-discovery.service']['ActiveState']='activating'
        self.assertEqual(self.assess(units)['status'], 'Running')
        units['homesoc-discovery.service']['ExecMainStartTimestamp']=stamp(NOW-timedelta(hours=1))
        self.assertEqual(self.assess(units)['tone'], 'warning')

    def test_no_run_default_success_is_not_healthy(self):
        units=units_for();units['homesoc-discovery.service'].update(ExecMainStartTimestamp='',ExecMainExitTimestamp='')
        self.assertEqual(self.assess(units,uptime=30)['status'], 'Waiting for first run')
        self.assertEqual(self.assess(units)['tone'], 'warning')

    def test_missing_masked_and_incomplete_properties(self):
        self.assertEqual(self.assess({})['tone'], 'unknown')
        units=units_for();units['homesoc-discovery.service']['LoadState']='not-found'
        self.assertEqual(self.assess(units)['tone'], 'warning')
        units=units_for();units['homesoc-discovery.service']['ExecMainExitTimestamp']=''
        self.assertEqual(self.assess(units)['tone'], 'unknown')

    def test_future_clock_warns(self):
        units=units_for();units['homesoc-discovery.service']['ExecMainExitTimestamp']=stamp(NOW+timedelta(hours=1))
        self.assertEqual(self.assess(units)['tone'], 'warning')

    def test_monotonic_next_trigger_and_parsing(self):
        self.assertEqual(health.monotonic_seconds('2h 1min 500ms'), 7260.5)
        self.assertEqual(health.monotonic_seconds('210000000'),210)
        self.assertIsNone(health.monotonic_seconds('infinity'))
        self.assertIsNone(health.monotonic_seconds('garbage'))
        units=units_for();units['homesoc-discovery.timer'].update(NextElapseUSecRealtime='',NextElapseUSecMonotonic='210000000')
        self.assertEqual(self.assess(units,uptime=200)['next_run'],'2026-10-10 20:00:10 UTC')

    def test_timestamp_and_fixed_allowlist_parsing(self):
        self.assertEqual(health.timestamp('Sat 2026-10-10 20:00:00 UTC'),NOW)
        self.assertIsNone(health.timestamp('n/a'))
        self.assertIsNone(health.timestamp('@nan'))
        self.assertIsNone(health.timestamp('invalid'))
        units=units_for();output=output_for(units)+'\n\nId=unrelated.service\nResult=success'
        self.assertEqual(health.parse_properties(output),units)

    def test_reader_uses_only_show_fixed_units_and_timeout(self):
        with patch.object(health.subprocess,'run',return_value=SimpleNamespace(stdout=output_for(units_for()),returncode=0)) as run:
            units,error=health.read_units()
        self.assertFalse(error)
        command=run.call_args.args[0]
        self.assertIn('show',command)
        self.assertEqual(tuple(command[-10:]),health.UNITS)
        self.assertEqual(run.call_args.kwargs['timeout'],4)
        self.assertNotIn('shell',run.call_args.kwargs)
        self.assertEqual(len(units),2)

    def test_reader_errors_partial_results_and_no_properties(self):
        for error in (FileNotFoundError(),subprocess.TimeoutExpired('systemctl',4)):
            with patch.object(health.subprocess,'run',side_effect=error):
                units,message=health.read_units()
            self.assertEqual(units,{})
            self.assertTrue(message)
        with patch.object(health.subprocess,'run',return_value=SimpleNamespace(stdout=output_for(units_for()),returncode=1)):
            units,message=health.read_units()
        self.assertEqual(len(units),2)
        self.assertTrue(message)
        with patch.object(health.subprocess,'run',return_value=SimpleNamespace(stdout='no systemd',returncode=0)):
            self.assertEqual(health.read_units()[0],{})


class HealthPageTests(unittest.TestCase):
    setUpClass=classmethod(fixtures.IncidentTests.setUpClass.__func__)
    tearDownClass=classmethod(fixtures.IncidentTests.tearDownClass.__func__)
    setUp=fixtures.IncidentTests.setUp
    tearDown=fixtures.IncidentTests.tearDown

    def test_page_refresh_has_all_jobs_without_mutation(self):
        units={}
        for job in health.JOBS:units.update(units_for(job))
        before=(self.module.DB_PATH.read_bytes(),self.ticket.read_bytes())
        with patch.object(health,'read_units',return_value=(units,'')):
            response=self.client.get('/health?unit=arbitrary.service')
        self.assertEqual(response.status_code,200)
        for label,_,_,_ in health.JOBS:self.assertIn(label.encode(),response.data)
        self.assertIn(b'Refresh status',response.data)
        self.assertEqual(before,(self.module.DB_PATH.read_bytes(),self.ticket.read_bytes()))
        self.assertEqual(self.client.post('/health').status_code,405)

    def test_unavailable_does_not_substitute_sample_health(self):
        with patch.object(health,'read_units',return_value=({},'Unavailable')):
            response=self.client.get('/health')
        self.assertEqual(response.status_code,200)
        self.assertIn(b'Unknown',response.data)
        self.assertIn(b'Unavailable',response.data)
        self.assertIn(b'No sample data is substituted',response.data)

    def test_systemd_text_is_escaped(self):
        units=units_for();units['homesoc-discovery.service']['Result']='<script>alert(1)</script>'
        with patch.object(health,'read_units',return_value=(units,'')):
            page=self.client.get('/health').data
        self.assertNotIn(b'<script>alert(1)</script>',page)
        self.assertIn(b'&lt;script&gt;',page)

if __name__=='__main__':unittest.main()
