"""Transport tests use explicitly synthetic data, never simulated hardware access."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from atlas.bridge.bundle import BridgeError, MAX_BUNDLE, read_bundle, verify_probe
from atlas.core.application import Application
from atlas.core.config import Config, StorageConfig
from atlas.storage.reader import database_status, reader

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'examples/bridge-fixture/session.atlas.json'
PROBE = ROOT / 'examples/bridge-fixture/probe.json'
NONCE = 'b72fc58c-55d2-43cc-8c61-79a88f8b0a54'


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'session.atlas.json'
        self.doc = json.loads(FIXTURE.read_text())
    def tearDown(self):
        self.temp.cleanup()
    def save(self):
        self.path.write_text(json.dumps(self.doc))
        return self.path
    def rehash(self):
        payload = self.doc['payload_jsonl'].encode()
        self.doc['metadata']['bytes'] = len(payload)
        self.doc['metadata']['rows'] = len(payload.splitlines())
        self.doc['sha256'] = hashlib.sha256(payload).hexdigest()
    def test_fixture_integrity_and_explicit_provenance(self):
        bundle = read_bundle(FIXTURE)
        self.assertTrue(bundle.summary()['synthetic'])
        self.assertEqual(len(bundle.observations), 4)
        self.assertEqual(bundle.summary()['hardware_access'], 'UNVERIFIED')
        self.assertEqual(bundle.summary()['authenticity'], 'UNVERIFIED')
    def test_incomplete_export_rejected(self):
        self.doc['complete'] = False
        with self.assertRaisesRegex(BridgeError, 'not finalized'):
            read_bundle(self.save())
    def test_damage_and_partial_documents_rejected(self):
        self.doc['payload_jsonl'] += ' '
        with self.assertRaises(BridgeError):
            read_bundle(self.save())
        self.path.write_text(FIXTURE.read_text()[:-10])
        with self.assertRaises(BridgeError):
            read_bundle(self.path)
    def test_count_hash_and_version_mismatches(self):
        for key, value in [('rows', 5), ('bytes', 1), ('rows', True), ('rows', 10001)]:
            self.doc = json.loads(FIXTURE.read_text())
            self.doc['metadata'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(BridgeError):
                read_bundle(self.save())
        self.doc = json.loads(FIXTURE.read_text())
        self.doc['schema_version'] = True
        with self.assertRaises(BridgeError):
            read_bundle(self.save())
        self.doc = json.loads(FIXTURE.read_text())
        self.doc['sha256'] = '\u202e' * 64
        with self.assertRaises(BridgeError):
            read_bundle(self.save())
    def test_provenance_conflict_rejected(self):
        self.doc['metadata']['synthetic'] = False
        with self.assertRaisesRegex(BridgeError, 'provenance'):
            read_bundle(self.save())
    def test_unknown_keys_and_duplicate_json_rejected(self):
        self.doc['unexpected'] = 1
        with self.assertRaises(BridgeError):
            read_bundle(self.save())
        self.path.write_text('{"kind":"first","kind":"second"}')
        with self.assertRaisesRegex(BridgeError, 'duplicate'):
            read_bundle(self.path)
    def test_no_network_events_allowed(self):
        row = dict(kind='service', id='192.0.2.1/tcp/23', ip='192.0.2.1', port=23,
                   observed_at='2026-01-01T12:00:00Z', source='synthetic:fixture')
        self.doc['payload_jsonl'] = json.dumps(row) + '\n'
        self.rehash()
        with self.assertRaisesRegex(BridgeError, 'only radio'):
            read_bundle(self.save())
    def test_invalid_observation_rejected_even_with_valid_hash(self):
        row = json.loads(self.doc['payload_jsonl'].splitlines()[0])
        row['rssi'] = 500
        self.doc['payload_jsonl'] = json.dumps(row) + '\n'
        self.rehash()
        with self.assertRaisesRegex(BridgeError, 'invalid observation'):
            read_bundle(self.save())
    def test_complete_record_boundary_required(self):
        self.doc['payload_jsonl'] = self.doc['payload_jsonl'].rstrip('\n')
        self.rehash()
        with self.assertRaisesRegex(BridgeError, 'newline'):
            read_bundle(self.save())
    def test_probe_nonce_must_match_and_fixture_never_verifies_host(self):
        result = verify_probe(PROBE, NONCE)
        self.assertTrue(result['nonce_matches'])
        self.assertTrue(result['synthetic'])
        self.assertEqual(result['status'], 'UNVERIFIED')
        self.assertFalse(result['path_on_android_share'])
        with self.assertRaisesRegex(BridgeError, 'mismatch'):
            verify_probe(PROBE, '00000000-0000-4000-8000-000000000000')
    def test_import_is_atomic_replay_safe_and_preserves_time(self):
        db = Path(self.temp.name) / 'private/atlas.sqlite3'
        app = Application(replace(Config(), storage=StorageConfig(db, 2000)))
        self.assertEqual(app.import_bridge(FIXTURE)['inserted'], 4)
        self.assertEqual(app.import_bridge(FIXTURE)['inserted'], 0)
        with reader(db) as store:
            rows = store.observations()
        self.assertEqual(rows[0]['observed_at'], '2026-01-01T12:00:00.000000+00:00')
        self.assertEqual(len(app.report()['findings']), 4)
        self.doc['payload_jsonl'] += '{"kind":"wifi"}\n'
        self.rehash()
        with self.assertRaises(BridgeError):
            app.import_bridge(self.save())
        self.assertEqual(database_status(db)['observations'], 4)
    def test_invalid_bundle_does_not_initialize_database(self):
        db = Path(self.temp.name) / 'not-created/atlas.sqlite3'
        app = Application(replace(Config(), storage=StorageConfig(db, 2000)))
        self.doc['complete'] = False
        with self.assertRaises(BridgeError):
            app.import_bridge(self.save())
        self.assertFalse(db.parent.exists())
    def test_cli_verify_and_import(self):
        db = Path(self.temp.name) / 'atlas.sqlite3'
        base = [sys.executable, '-m', 'atlas', '--db', str(db), 'bridge']
        for action in ('verify', 'import'):
            result = subprocess.run(base + [action, str(FIXTURE)], cwd=ROOT, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)['synthetic'])
        result = subprocess.run(base + ['verify-probe', str(PROBE), '--nonce', NONCE],
                                cwd=ROOT, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'UNVERIFIED')


if __name__ == '__main__':
    unittest.main()
