"""Additional regression checks for bounded BLE history and incomplete GATT metadata."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from atlas.bluetooth.engine import analyze, scan_file
from atlas.bridge.bundle import read_bundle
from atlas.core.errors import AtlasError
from atlas.core.events import validate
from atlas.storage.sqlite import Store

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT/'examples/ble/telemetry.atlas.json'
SOURCE = 'synthetic:android-ble:lab'
SINCE = '2026-04-16T10:03:00Z'


class BleBoundsTests(unittest.TestCase):
    def test_success_requires_explicit_service_result(self):
        o = next(o for o in read_bundle(FIXTURE).observations if o['kind']=='ble_gatt')
        o.pop('gatt_services')
        with self.assertRaises(ValueError):
            validate(o)
    def test_history_bound_and_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory)/'atlas.db')
            try:
                store.add(read_bundle(FIXTURE).observations)
                with patch('atlas.bluetooth.engine.MAX_HISTORY_ROWS',2):
                    result = analyze(store,SOURCE,SINCE)
                self.assertEqual(result['coverage']['examined'],2)
                self.assertTrue(result['coverage']['truncated'])
                findings = analyze(store,SOURCE,SINCE)['findings']
                self.assertTrue(findings)
                self.assertTrue(all(f['evidence_confidence']=='synthetic' for f in findings))
            finally:
                store.close()
    def test_invalid_import_never_initializes_database(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory)/'missing.db'
            path = Path(directory)/'bad.jsonl'
            path.write_text('{"kind":"ble","kind":"ble"}\n')
            with self.assertRaises(AtlasError):
                scan_file(db,path)
            self.assertFalse(db.exists())

    def test_duplicate_hint_at_limit_does_not_claim_truncation(self):
        original = next(o for o in read_bundle(FIXTURE).observations if o['kind']=='ble')
        rows = [dict(original, name=name, observed_at=time) for name,time in (
            ('A','2026-04-16T10:02:00Z'), ('B','2026-04-16T10:03:10Z'),
            ('A','2026-04-16T10:03:20Z'), ('B','2026-04-16T10:03:30Z'))]
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory)/'atlas.db')
            try:
                store.add(rows)
                result = analyze(store,SOURCE,SINCE,limit=2)
                self.assertEqual(len(result['findings']),2)
                self.assertEqual(result['coverage']['examined'],4)
                self.assertFalse(result['coverage']['truncated'])
            finally:
                store.close()
