"""Explicitly synthetic cellular unit/integration cases; no device or network is accessed."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from atlas.cellular.analysis import analyze
from atlas.cellular.baseline import build, load
from atlas.cellular.engine import ingest, inspect
from atlas.cellular.performance import request
from atlas.cli import main
from atlas.core.events import validate, fingerprint
from atlas.reporting.reports import report, markdown
from atlas.security.evidence import verify
from atlas.security.retention import retain
from atlas.storage.sqlite import Store
from atlas.storage.reader import reader
from atlas.ui.dashboard import snapshot
from test_cellular_transport import envelope, signed_export
from atlas.cellular.transport import generate_key, key_bytes, challenge
from examples.cellular.generate import cell, row, observations, SOURCE

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT/'examples/cellular/observations.jsonl'


class CellularTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root/'history.sqlite3'

    def rows(self):
        return [validate(o) for o in observations()]

    def add(self, rows=None):
        store = Store(self.db)
        try: return store.add(rows or self.rows())
        finally: store.close()

    def baseline(self):
        store = Store(self.db)
        try: return build(store, SOURCE, '2026-04-18T10:01:00Z')
        finally: store.close()

    def cli(self, *args):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = main(['--db', str(self.db), 'cellular', *args])
        return code, output.getvalue(), error.getvalue()

    def test_fixture_schema_and_exact_missing_values(self):
        values = self.rows()
        signal = next(o for o in values if o['cellular_event'] == 'signal')
        self.assertNotIn('cell_id', signal)
        self.assertNotIn('measurement_elapsed_ms', signal)
        self.assertNotIn('lte_rsrq', signal)
        self.assertEqual(signal['cell_freshness'], 'unknown')
        self.assertEqual(validate(cell(0, cell_id=0, pci=0, tac=0, lte_rssnr=0))['cell_id'], 0)
        self.assertEqual(next(o for o in values if o.get('technology') == 'NR')['cell_id'], 9000000)

    def test_sentinels_nulls_booleans_and_sensitive_fields_rejected(self):
        for field, value in [('cell_id', 2147483647), ('cell_id', None), ('pci', True),
                             ('lte_rsrp', 2147483647), ('bands', [3]*65), ('bands', [3, 3]),
                             ('mcc', '１２３'), ('mnc', '1'), ('imsi', 'forbidden'),
                             ('iccid', 'forbidden'), ('imei', 'forbidden'), ('authentication_keys', {}),
                             ('raw_modem_signaling', 'forbidden'), ('nr_ss_sinr', 10)]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate(cell(0, **{field: value}))

    def test_freshness_and_receipt_consistency_rejected(self):
        cases = [dict(cell_freshness='recent', cell_age_ms=20000),
                 dict(cell_freshness='recent', cell_origin='cached_read'),
                 dict(cell_freshness='unknown'), dict(cell_age_ms=0),
                 dict(registered=False, connection_status='primary')]
        for fields in cases:
            with self.subTest(fields=fields), self.assertRaises(ValueError): validate(cell(0, **fields))
        invalid = cell(0); del invalid['measurement_elapsed_ms']
        with self.assertRaises(ValueError): validate(invalid)
        with self.assertRaises(ValueError): validate(row('signal', 0, technology='LTE', cell_age_ms=1))

    def test_atomic_import_sqlite_replay_and_original_timestamp(self):
        with patch('socket.socket', side_effect=AssertionError('no sockets')):
            first = ingest(self.db, FIXTURE, synthetic=True)
            second = ingest(self.db, FIXTURE, synthetic=True)
        self.assertEqual(first['inserted'], 25)
        self.assertEqual(second['inserted'], 0)
        with reader(self.db) as store:
            saved = store.observations()
        self.assertEqual({fingerprint(o) for o in saved}, {fingerprint(o) for o in self.rows()})
        self.assertEqual(next(o for o in saved if o['id'] == 'synthetic-cell-0')['observed_at'], '2026-04-18T10:00:00.000000+00:00')
        self.assertEqual(verify(self.db)['integrity'], 'VERIFIED')

    def test_unlabelled_raw_data_and_unsigned_real_exports_rejected_before_db(self):
        with self.assertRaises(ValueError): ingest(self.db, FIXTURE)
        bad = self.root/'bad.jsonl'
        bad.write_text(json.dumps(dict(cell(0), source='android:device:cellular'))+'\n')
        with self.assertRaises(ValueError): ingest(self.db, bad, synthetic=True)
        from atlas.storage.ingest import ingest_file
        with self.assertRaises(ValueError): ingest_file(self.db, bad)
        from atlas.bridge.bundle import read_bundle, BridgeError
        exported = self.root/'unsigned.atlas.json'
        exported.write_text(json.dumps(envelope([dict(cell(0), source='android:device:cellular')], synthetic=False)))
        with self.assertRaises(BridgeError): read_bundle(exported)
        self.assertFalse(self.db.exists())

    def test_invalid_mixed_input_does_not_create_database(self):
        bad = self.root/'mixed.jsonl'
        bad.write_text(json.dumps(cell(0))+'\n'+json.dumps({'kind': 'cellular'})+'\n')
        with self.assertRaises(ValueError): ingest(self.db, bad, synthetic=True)
        self.assertFalse(self.db.exists())

    def test_deterministic_rule_outputs(self):
        self.add()
        self.baseline()
        result = inspect(self.db, SOURCE, use_baseline=True)
        from collections import Counter
        counts = Counter(f['rule'] for f in result['findings'])
        self.assertEqual(counts, {'serving-cell-change': 1, 'cell-identity-frequency-change': 1,
                                  'cell-not-in-reviewed-baseline': 2, 'lte-nr-transition': 2,
                                  'network-display-change': 1, 'cellular-data-interruption': 1,
                                  'cellular-registration-interruption': 1, 'cellular-connectivity-interruption': 1,
                                  'sustained-signal-degradation': 1})
        self.assertEqual(result, inspect(self.db, SOURCE, use_baseline=True))
        self.assertTrue(all(f['severity'] in {'info', 'review'} for f in result['findings']))
        self.assertTrue(all('no IMSI-catcher' in f['interpretation'] for f in result['findings']))

    def test_scope_and_neighbor_cached_unknown_controls(self):
        first = validate(cell(0))
        for extra in (dict(cell(30, cell_id=200), source='synthetic:other'),
                      cell(30, cell_id=200, collection_session='synthetic-session-b'),
                      cell(30, cell_id=200, subscription_id=2),
                      cell(30, cell_id=200, connection_status='secondary'),
                      cell(30, cell_id=200, registered=False, connection_status='none'),
                      cell(30, cell_id=200, cell_freshness='cached', cell_origin='cached_read'),
                      cell(301, cell_id=200)):
            self.assertEqual(analyze([first, validate(extra)])['findings'], [], extra)
        unknown = cell(30, cell_id=200, cell_freshness='unknown')
        for f in ('cell_age_ms', 'measurement_elapsed_ms'): unknown.pop(f)
        self.assertEqual(analyze([first, validate(unknown)])['findings'], [])

    def test_missing_identity_does_not_imply_handover_and_duplicate_timestamp_not_trend(self):
        unknown = cell(30, lte_rsrp=-130); unknown.pop('cell_id')
        rows = [validate(cell(0)), validate(unknown)]
        self.assertEqual(analyze(rows)['findings'], [])
        duplicate = dict(cell(0), id='synthetic-replayed-cell')
        self.assertEqual(analyze([validate(cell(0)), validate(duplicate), validate(cell(30, lte_rsrp=-110))])['trends'], [])

    def test_signal_callback_changes_not_used_as_modem_trend(self):
        values = [validate(row('signal', t, technology='LTE', lte_rsrp=v)) for t, v in [(0, -80), (30, -100), (60, -120)]]
        result = analyze(values)
        self.assertEqual(result['trends'], [])
        self.assertEqual(result['findings'], [])

    def test_sparse_rat_updates_preserve_previous_data_state(self):
        values = [row('technology', 0, network_type=13, data_state=2),
                  row('technology', 30, display_override=3), row('technology', 60, data_state=0)]
        result = analyze([validate(o) for o in values])
        self.assertEqual([f['rule'] for f in result['findings']], ['cellular-data-interruption'])

    def test_wifi_loss_is_not_cellular_interruption(self):
        values = [row('connectivity', 0, default_transport='wifi', network_validated=True),
                  row('connectivity', 30, default_transport='none', network_validated=False)]
        self.assertEqual(analyze([validate(o) for o in values])['findings'], [])

    def test_immutable_reviewed_baseline_and_read_only_inspection(self):
        self.add(); baseline = self.baseline()
        self.assertEqual(baseline['samples'], 3)
        self.assertEqual(len(baseline['profiles'][0]['cells']), 1)
        self.assertEqual(baseline['profiles'][0]['signals']['lte_rsrp']['median'], -92)
        before = self.db.read_bytes()
        with reader(self.db) as store: self.assertEqual(load(store, SOURCE), baseline)
        inspect(self.db, SOURCE, use_baseline=True)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(verify(self.db)['tables']['cellular_baselines'], 1)

    def test_baseline_excludes_duplicate_stale_and_neighbor_records(self):
        rows = [cell(0), dict(cell(0), id='synthetic-duplicate'),
                cell(30, registered=False, connection_status='none'),
                cell(60, cell_freshness='cached', cell_origin='cached_read')]
        self.add([validate(o) for o in rows]); self.assertEqual(self.baseline()['samples'], 1)

    def test_retention_invalidates_cellular_baseline_and_purge(self):
        self.add(); self.baseline()
        result = retain(self.db, days=1, apply=True, at='2026-04-20T00:00:00Z')
        self.assertEqual(result['rows']['cellular_baselines'], 1)
        self.assertEqual(verify(self.db)['tables']['cellular_baselines'], 0)

    def test_performance_comparison_requires_bound_matching_endpoint_and_byte_counts(self):
        result = analyze(self.rows())['performance']
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]['comparable'])
        self.assertEqual(result[0]['transports']['wifi']['median_duration_ms'], 100)
        tests = [o for o in self.rows() if o['cellular_event'] == 'performance']
        tests[1]['bytes_received'] = 1024
        self.assertFalse(analyze(tests)['performance'][0]['comparable'])
        tests[1]['test_endpoint'] = 'https://example.invalid/other'
        self.assertFalse(any(p['comparable'] for p in analyze(tests)['performance']))
        with self.assertRaises(ValueError): validate(dict(tests[0], bound_network=False))

    def test_endpoint_authorization_and_request_expiry(self):
        output = self.root/'request.json'
        for url, auth in [('http://example.invalid', True), ('https://user:pass@example.invalid', True),
                          ('https://example.invalid/?token=secret', True), ('https://example.invalid', False)]:
            with self.assertRaises(ValueError): request(url, auth, output)
            self.assertFalse(output.exists())
        value = request('https://example.invalid/test', True, output)
        self.assertEqual(value['max_bytes'], 65536)
        self.assertTrue(value['expires_at'] > value['created_at'])
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_authenticated_synthetic_export_cli_import_and_replay(self):
        key = self.root/'bridge.key'; generate_key(key)
        nonce = challenge(self.root/'challenge.json')['nonce']
        export = self.root/'authenticated.atlas.json'
        export.write_text(json.dumps(signed_export(envelope(observations(), nonce=nonce), key_bytes(key))))
        code, out, _ = self.cli('verify', '--input', str(export), '--key', str(key), '--nonce', nonce)
        self.assertEqual(code, 0); self.assertTrue(json.loads(out)['challenge_verified'])
        self.assertFalse(self.db.exists())
        args = ('ingest', '--input', str(export), '--key', str(key), '--nonce', nonce, '--synthetic')
        self.assertEqual(self.cli(*args)[0], 0)
        self.assertEqual(json.loads(self.cli(*args)[1])['inserted'], 0)
        self.assertEqual(self.cli('baseline', '--source', SOURCE, '--through', '2026-04-18T10:01:00Z')[0], 0)
        self.assertEqual(self.cli('inspect', '--source', SOURCE, '--baseline')[0], 0)

    def test_session_availability_drop_metadata_is_retained_once(self):
        ingest(self.db, ROOT/'examples/cellular/session.atlas.json', synthetic=True)
        ingest(self.db, ROOT/'examples/cellular/session.atlas.json', synthetic=True)
        result = inspect(self.db, SOURCE)
        self.assertEqual(len(result['recent_sessions']), 1)
        self.assertEqual(result['recent_sessions'][0]['metadata']['statuses']['cellular'], 'SYNTHETIC: no Android APIs invoked')
        self.assertEqual(verify(self.db)['tables']['cellular_sessions'], 1)

    def test_zero_observation_cellular_session_keeps_availability_and_needs_auth(self):
        from atlas.bridge.bundle import BridgeError
        doc = envelope([], synthetic=False)
        sensor = '00000000-0000-4000-8000-000000000002'
        doc['metadata'].update(statuses={'cellular': 'permission_denied'}, sensor_id=sensor)
        export = self.root/'empty.atlas.json'
        export.write_text(json.dumps(doc))
        with self.assertRaises((ValueError, BridgeError)): ingest(self.db, export)
        self.assertFalse(self.db.exists())
        doc['metadata']['synthetic'] = True
        export.write_text(json.dumps(doc))
        result = ingest(self.db, export, synthetic=True)
        self.assertEqual(result['observations'], 0)
        sessions = inspect(self.db, 'synthetic:' + sensor + ':cellular')['recent_sessions']
        self.assertEqual(sessions[0]['metadata']['statuses']['cellular'], 'permission_denied')

    def test_derived_baseline_tampering_is_detected(self):
        self.add(); self.baseline()
        store = Store(self.db)
        try:
            value = load(store, SOURCE)
            value['samples'] = 999
            store.db.execute('UPDATE cellular_baselines SET body=?', (json.dumps(value),))
            store.db.commit()
        finally: store.close()
        with self.assertRaises(ValueError): verify(self.db)

    def test_event_specific_metadata_is_not_reinterpreted(self):
        with self.assertRaises(ValueError): validate(cell(0, service_state=0))
        with self.assertRaises(ValueError): validate(cell(0, rssi=-90))

    def test_report_dashboard_topology_and_limit_coverage(self):
        self.add(); self.baseline()
        with reader(self.db) as store: result = report(store)
        self.assertEqual(result['cellular']['observations'], 25)
        self.assertIn('## Cellular observations', markdown(result))
        self.assertTrue(any(n['kind'] == 'cellular' for n in result['topology']['nodes']))
        self.assertIn('sustained-signal-degradation', '\n'.join(snapshot(self.db, 'cellular', 'findings')['lines']))
        self.assertTrue(inspect(self.db, SOURCE, limit=1)['coverage']['truncated'])
        with self.assertRaises(ValueError): inspect(self.db, SOURCE, limit=5001)

class CellularResourceTests(unittest.TestCase):
    def test_fresh_process_synthetic_resource_budget_and_loss(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'run'
            result = subprocess.run([sys.executable, str(ROOT/'scripts/verify_cellular.py'),
                                     '--output', str(output), '--events', '100'],
                                    cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertTrue(data['synthetic'])
            self.assertFalse(data['hardware_demonstrated'])
            metrics = data['resources']
            self.assertEqual(metrics['submitted'], 200)
            self.assertEqual(metrics['stored'], 200)
            self.assertEqual(metrics['event_loss'], 0)
            self.assertEqual(metrics['normal_stream_findings'], 0)
            self.assertLess(metrics['peak_rss_bytes_process_lifetime'], 150*1024*1024)
            self.assertLess(metrics['latency_ms']['p95'], 1000)

if __name__ == '__main__': unittest.main()
