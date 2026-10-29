"""Application tests collected by pytest and runnable with unittest offline."""
from dataclasses import replace
from contextlib import closing
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from atlas.cli import main
from atlas.core.application import Application
from atlas.core.config import Config, LoggingConfig, MonitorConfig, StorageConfig, load_config
from atlas.core.diagnostics import diagnose, netlink_check, tcp_socket_check
from atlas.core.errors import ConfigurationError, ResourceLimitError, StorageError
from atlas.core.logging import configure, event
from atlas.core.resources import ResourceMonitor, enforce
from atlas.storage.reader import database_status, reader
from atlas.storage.sqlite import Store

ROOT = Path(__file__).resolve().parents[1]


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'atlas.yaml'
    def tearDown(self):
        self.temp.cleanup()
    def config(self, text):
        self.path.write_text(text)
        return load_config(self.path)
    def test_defaults_and_relative_paths(self):
        c = self.config('storage:\n  path: data/atlas.sqlite3\nmonitor:\n  interval_seconds: 0.5\n')
        self.assertEqual(c.storage.path, self.path.parent / 'data/atlas.sqlite3')
        self.assertEqual(c.monitor.max_rss_mb, 256)
    def test_unknown_duplicate_and_unsafe_yaml(self):
        for text in ('unexpected: 1', 'storage: {}\nstorage: {}',
                     'storage: &s {}\nbridge: *s', '!!python/object:os.system {}', 'storage: [1]', '[]',
                     'storage:\n  path: data\n  path: other', 'storage: {report_limit: true}',
                     'monitor: {interval_seconds: .nan}', 'monitor: {interval_seconds: true}',
                     'monitor: {interval_seconds: 0}', 'monitor: {max_rss_mb: 2048}',
                     'logging: {level: TRACE}', 'storage: {path: 123}', 'bridge: {unknown: true}',
                     'storage: {report_limit: 50000}', '[[[[[[[[[[[0]]]]]]]]]]]'):
            with self.subTest(text=text), self.assertRaises(ConfigurationError):
                self.config(text)
    def test_large_config_rejected(self):
        with self.assertRaises(ConfigurationError):
            self.config('#' * 65537)
    def test_missing_config_is_actionable(self):
        with self.assertRaisesRegex(ConfigurationError, 'cannot read'):
            load_config(self.path)
    def test_log_cannot_replace_database(self):
        with self.assertRaisesRegex(ConfigurationError, 'must differ'):
            self.config('storage: {path: data.sqlite3}\nlogging: {file: data.sqlite3}')


class StorageAndApplicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'private/atlas.sqlite3'
        self.config = replace(Config(), storage=StorageConfig(self.path, 2000))
    def tearDown(self):
        self.temp.cleanup()
    def seed(self):
        store = Store(self.path)
        store.ingest(ROOT / 'examples/demo.jsonl')
        store.close()
    def test_status_does_not_initialize(self):
        result = Application(self.config).status()
        self.assertEqual(result['database']['state'], 'uninitialized')
        self.assertFalse(self.path.parent.exists())
        self.assertFalse(result['bridge']['companion_implemented'])
    def test_existing_database_and_report(self):
        self.seed()
        before = self.path.read_bytes()
        app = Application(self.config)
        self.assertEqual(app.status()['database']['observations'], 7)
        self.assertEqual(len(app.report()['findings']), 5)
        self.assertIn('# ATLAS RF', app.report('markdown'))
        self.assertEqual(before, self.path.read_bytes())
    def test_query_only_storage(self):
        self.seed()
        with reader(self.path) as store:
            with self.assertRaises(sqlite3.OperationalError):
                store.db.execute('DELETE FROM observations')
    def test_unknown_database_schema(self):
        self.seed()
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('PRAGMA user_version=42')
        with self.assertRaisesRegex(StorageError, 'version 1'):
            database_status(self.path)
    def test_corruption_does_not_become_empty_assessment(self):
        self.path.parent.mkdir()
        self.path.write_text('not sqlite')
        with self.assertRaises(sqlite3.DatabaseError):
            database_status(self.path)
    def test_report_missing_database_fails_without_creation(self):
        with self.assertRaises(sqlite3.OperationalError):
            Application(self.config).report()
        self.assertFalse(self.path.exists())
    def test_database_symlink_rejected(self):
        self.seed()
        link = Path(self.temp.name) / 'linked.sqlite3'
        link.symlink_to(self.path)
        with self.assertRaises(StorageError):
            database_status(link)


class ResourceTests(unittest.TestCase):
    def test_real_snapshot(self):
        snapshot = ResourceMonitor().sample('/tmp/atlas.sqlite3')
        self.assertGreater(snapshot['rss_bytes'], 0)
        self.assertGreater(snapshot['disk_free_bytes'], 0)
    def test_all_budget_failures(self):
        good = dict(rss_bytes=20 * 1024**2, available_memory_bytes=1024 * 1024**2, disk_free_bytes=1024 * 1024**2)
        enforce(good, MonitorConfig())
        for key, value in [('rss_bytes', 300 * 1024**2), ('available_memory_bytes', 1), ('disk_free_bytes', 1)]:
            with self.subTest(key=key), self.assertRaises(ResourceLimitError):
                enforce(dict(good, **{key: value}), MonitorConfig())
    def test_unknown_measurements_not_fabricated(self):
        enforce(dict(rss_bytes=None, available_memory_bytes=None, disk_free_bytes=None), MonitorConfig())
    def test_monitor_limit_and_stop(self):
        app = Application(Config())
        app.config = replace(app.config, monitor=replace(app.config.monitor, interval_seconds=0.5))
        with patch('atlas.core.application.time.sleep') as sleep:
            self.assertEqual(len(list(app.monitor(samples=3))), 3)
            self.assertEqual(sleep.call_count, 2)
        stopped = threading.Event()
        stopped.set()
        self.assertEqual(list(app.monitor(stop=stopped)), [])


class DiagnosticsAndLoggingTests(unittest.TestCase):
    def test_denial_is_not_usable_network(self):
        with patch('atlas.core.diagnostics.socket.socket', side_effect=PermissionError(1, 'denied')):
            self.assertEqual(tcp_socket_check()['status'], 'UNSUPPORTED')
        with patch('atlas.core.diagnostics.shutil.which', return_value=None):
            self.assertEqual(netlink_check()['status'], 'UNSUPPORTED')
    def test_doctor_never_invokes_radio_collection(self):
        with patch('atlas.wifi.collector.wifi', side_effect=AssertionError('must not scan')), \
             patch('atlas.bluetooth.collector.ble', side_effect=AssertionError('must not scan')):
            result = diagnose(Config())
        self.assertIn(result['wifi']['status'], ('UNSUPPORTED', 'UNVERIFIED'))
        self.assertFalse(result['bridge']['companion_implemented'])
    def test_json_logging_controls_and_reconfigure(self):
        stream = io.StringIO()
        logger = configure(LoggingConfig(), stream)
        configure(LoggingConfig(), stream)
        event(logger, 'test.event', 'untrusted\n\x1b[31m', value='name\nvalue')
        lines = stream.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry['event'], 'test.event')
        self.assertEqual(entry['data']['value'], 'name\nvalue')
        self.assertNotIn('\x1b', lines[0])
    def test_private_rotation(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'events.jsonl'
            logger = configure(LoggingConfig(file=path), io.StringIO())
            handler = logger.handlers[1]
            handler.maxBytes = 200
            previous_umask = os.umask(0o022)
            try:
                for _ in range(8):
                    event(logger, 'test.rotation', 'x' * 100)
            finally:
                os.umask(previous_umask)
            self.assertTrue(path.with_name(path.name + '.1').exists())
            self.assertFalse(path.with_name(path.name + '.3').exists())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            configure(LoggingConfig(), io.StringIO())


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'atlas', *args], cwd=ROOT, capture_output=True, text=True, timeout=5)
    def test_status_stdout_and_logs_separated(self):
        with tempfile.TemporaryDirectory() as d:
            result = self.run_cli('--db', str(Path(d) / 'missing.sqlite3'), 'status')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['database']['state'], 'uninitialized')
        self.assertEqual([json.loads(line)['event'] for line in result.stderr.splitlines()], ['command.started', 'command.completed'])
    def test_doctor_and_one_shot_monitor(self):
        doctor = self.run_cli('doctor')
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        self.assertIn('capabilities', json.loads(doctor.stdout)['checks'])
        monitor = self.run_cli('monitor', '--once')
        self.assertEqual(monitor.returncode, 0, monitor.stderr)
        self.assertEqual(json.loads(monitor.stdout)['event'], 'resource.snapshot')
    def test_bad_config_json_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            config = Path(d) / 'bad.yaml'
            config.write_text('monitor: {max_rss_mb: bad}')
            result = self.run_cli('--config', str(config), 'status')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertEqual(json.loads(result.stderr)['event'], 'command.failed')
        self.assertNotIn('Traceback', result.stderr)
    def test_report_missing_database_error(self):
        with tempfile.TemporaryDirectory() as d:
            result = self.run_cli('--db', str(Path(d) / 'missing.sqlite3'), 'report')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
    def test_monitor_sigterm_clean_exit(self):
        child = subprocess.Popen([sys.executable, '-m', 'atlas', 'monitor'], cwd=ROOT,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(json.loads(child.stdout.readline())['event'], 'resource.snapshot')
            child.send_signal(signal.SIGTERM)
            stdout, stderr = child.communicate(timeout=3)
            self.assertEqual(child.returncode, 0, stderr)
            self.assertIn('command.completed', stderr)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()
    def test_resource_failure_exit_code(self):
        with patch('atlas.cli.Application.monitor', side_effect=ResourceLimitError('test budget')), \
             patch('sys.stderr', new_callable=io.StringIO) as stderr:
            self.assertEqual(main(['monitor', '--once']), 3)
            self.assertEqual(json.loads(stderr.getvalue().splitlines()[-1])['event'], 'resource.limit')


if __name__ == '__main__':
    unittest.main()
