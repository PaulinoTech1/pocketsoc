"""Source-scoped Wi-Fi intelligence tests; all radio values are synthetic fixtures."""
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from atlas.bridge.bundle import read_bundle
from atlas.core.errors import AtlasError
from atlas.core.events import validate
from atlas.storage.reader import reader
from atlas.storage.sqlite import Store
from atlas.wifi.ingest import scan_file
from atlas.wifi.intelligence import build_baseline, detect, load_baseline
from atlas.wifi.schema import band, eligibility

ROOT = Path(__file__).resolve().parents[1]
TRAINING = ROOT/'examples/wifi/training.atlas.json'
EVALUATION = ROOT/'examples/wifi/evaluation.atlas.json'
SOURCE = 'synthetic:android-wifi:office'


def row(**fields):
    o = dict(kind='wifi', id='02:aa:bb:cc:00:01', name='Test Lab', source='synthetic:test',
             observed_at='2026-04-15T10:00:00Z', frequency_mhz=2412, channel=1, security='WPA2',
             rssi=-55, scan_freshness='fresh', scan_age_ms=500)
    o.update(fields)
    return o


class WifiSchemaTests(unittest.TestCase):
    def test_supported_bands_and_channel_consistency(self):
        for frequency, channel, name in [(2412,1,'2.4GHz'), (2484,14,'2.4GHz'), (5180,36,'5GHz'),
                                         (5745,149,'5GHz'), (5935,2,'6GHz'), (5975,5,'6GHz'), (7115,233,'6GHz')]:
            o = validate(row(frequency_mhz=frequency, channel=channel))
            self.assertEqual(band(o['frequency_mhz']), name)
        with self.assertRaises(ValueError):
            validate(row(frequency_mhz=5975,channel=1))
    def test_invalid_fields_and_types(self):
        for fields in ({'frequency_mhz':True}, {'frequency_mhz':0}, {'channel':0}, {'channel':True},
                       {'scan_age_ms':-1}, {'scan_age_ms':False}, {'scan_freshness':'live'}, {'scan_freshness':[]}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                validate(row(**fields))
    def test_missing_fields_are_not_fabricated(self):
        o = row()
        for key in ('frequency_mhz','channel','scan_age_ms','scan_freshness'):
            o.pop(key)
        result = validate(o)
        self.assertNotIn('frequency_mhz', result)
        self.assertNotIn('channel', result)
        self.assertEqual(eligibility(result), 'unknown')
    def test_freshness_age_consistency(self):
        self.assertEqual(eligibility(row(scan_age_ms=30001)), 'stale')
        self.assertEqual(eligibility(row(scan_age_ms=30000)), 'fresh')
        self.assertEqual(eligibility(row(scan_freshness='cached')), 'cached')


class WifiIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name)/'atlas.sqlite3'
        self.store = Store(self.db)
    def tearDown(self):
        self.store.close()
        self.temp.cleanup()
    def train(self):
        self.store.add(read_bundle(TRAINING).observations)
        return build_baseline(self.store,SOURCE)
    def test_realistic_training_and_all_five_rules(self):
        baseline = self.train()
        self.assertEqual(baseline['samples'],15)
        self.assertEqual(len(baseline['profiles']),5)
        self.assertEqual(baseline['skipped'],dict(stale=1,cached=1,unknown=1))
        self.store.add(read_bundle(EVALUATION).observations)
        result = detect(self.store,SOURCE)
        counts = Counter(f['rule'] for f in result['findings'])
        self.assertEqual(counts, {'unknown-bssid':4,'unseen-ssid':2,'unexpected-security-change':1,
                                  'unusual-channel-change':1,'suspicious-ssid-duplication':1})
        self.assertFalse(result['coverage']['truncated'])
        self.assertEqual(result['coverage']['skipped'], {'cached':1,'stale':1,'duplicate_measurement':1})
        self.assertTrue(all(not f['confirmed_attack'] for f in result['findings']))
    def test_duplicate_ssid_alone_never_an_attack(self):
        self.train()
        self.store.add([dict(read_bundle(TRAINING).observations[1], id='02:11:22:00:00:10', observed_at='2026-04-15T11:00:00Z')])
        result = detect(self.store,SOURCE)
        self.assertEqual([f['rule'] for f in result['findings']], ['unknown-bssid'])
    def test_source_isolation_and_missing_baseline(self):
        self.train()
        with self.assertRaises(AtlasError):
            detect(self.store,'android:other:wifi')
    def test_stale_cached_unknown_cannot_train(self):
        self.store.add([row(scan_freshness=state) for state in ('cached','stale','unknown')])
        with self.assertRaisesRegex(AtlasError,'no eligible'):
            build_baseline(self.store,'synthetic:test')
    def test_snapshot_is_persistent_and_not_auto_trained(self):
        before = self.train()
        self.store.add(read_bundle(EVALUATION).observations)
        with reader(self.db) as ro:
            self.assertEqual(load_baseline(ro,SOURCE),before)
            self.assertGreater(len(detect(ro,SOURCE)['findings']),0)
        after = build_baseline(self.store,SOURCE)
        self.assertNotEqual(before['id'],after['id'])
        self.assertEqual(detect(self.store,SOURCE)['findings'],[])
        self.assertGreater(len(detect(self.store,SOURCE,before['id'])['findings']),0)
    def test_failed_retraining_does_not_replace_saved_snapshot(self):
        baseline=self.train()
        self.store.add(read_bundle(EVALUATION).observations)
        with patch('atlas.wifi.intelligence.MAX_VARIANTS',1), self.assertRaises(AtlasError):
            build_baseline(self.store,SOURCE)
        self.assertEqual(load_baseline(self.store,SOURCE)['id'],baseline['id'])
    def test_cutoff_out_of_order_and_late_data(self):
        observations = read_bundle(TRAINING).observations + read_bundle(EVALUATION).observations
        self.store.add(reversed(observations))
        b = build_baseline(self.store,SOURCE,'2026-04-15T10:03:00Z')
        self.assertEqual(b['samples'],15)
        self.assertGreater(len(detect(self.store,SOURCE)['findings']),0)
        late = dict(observations[0], id='02:11:22:00:00:ff', observed_at='2026-04-15T09:00:00Z')
        self.store.add([late])
        self.assertEqual(detect(self.store,SOURCE)['coverage']['late_pre_baseline_rows'],1)
    def test_unknown_security_is_not_a_change_or_duplication(self):
        self.train()
        self.store.add([dict(read_bundle(TRAINING).observations[0], id='02:11:22:00:00:fe',
                             security='UNKNOWN', observed_at='2026-04-15T11:00:00Z')])
        self.assertEqual([f['rule'] for f in detect(self.store,SOURCE)['findings']], ['unknown-bssid'])
    def test_incomplete_security_baseline_cannot_establish_suspicious_duplicate(self):
        self.store.add([row(), row(id='02:aa:bb:cc:00:02',security='UNKNOWN')])
        build_baseline(self.store,'synthetic:test')
        self.store.add([row(id='02:aa:bb:cc:00:03',security='OPEN',observed_at='2026-04-15T11:00:00Z')])
        self.assertEqual([f['rule'] for f in detect(self.store,'synthetic:test')['findings']],['unknown-bssid'])
    def test_security_token_order_does_not_trigger_change(self):
        self.train()
        self.store.add([dict(read_bundle(TRAINING).observations[0], security='WPA3 WPA2',observed_at='2026-04-15T11:00:00Z')])
        self.assertEqual(detect(self.store,SOURCE)['findings'],[])
    def test_hidden_ssid_does_not_trigger_unseen_name(self):
        self.train()
        self.store.add([dict(read_bundle(TRAINING).observations[0], name='',observed_at='2026-04-15T11:00:00Z')])
        self.assertEqual(detect(self.store,SOURCE)['findings'],[])
    def test_channel_change_requires_three_supplied_measurements(self):
        self.store.add([row()])
        build_baseline(self.store,'synthetic:test')
        self.store.add([row(observed_at='2026-04-15T11:00:00Z',frequency_mhz=2462,channel=11)])
        self.assertEqual(detect(self.store,'synthetic:test')['findings'],[])
    def test_same_channel_number_different_band_is_new_radio(self):
        self.store.add([row(observed_at=f'2026-04-15T10:0{m}:00Z') for m in range(3)])
        build_baseline(self.store,'synthetic:test')
        self.store.add([row(observed_at='2026-04-15T11:00:00Z',frequency_mhz=5955,channel=1)])
        result=detect(self.store,'synthetic:test')
        self.assertEqual(result['findings'][0]['rule'],'unusual-channel-change')
        self.assertEqual(result['findings'][0]['band'],'6GHz')
    def test_limit_reports_partial_coverage(self):
        self.train()
        self.store.add(read_bundle(EVALUATION).observations)
        result=detect(self.store,SOURCE,limit=1)
        self.assertTrue(result['coverage']['truncated'])
        self.assertEqual(len(result['findings']),1)
    def test_import_replay_and_atomic_invalid_batch(self):
        self.assertEqual(scan_file(self.db,TRAINING)['inserted'],18)
        self.assertEqual(scan_file(self.db,TRAINING)['inserted'],0)
        bad=Path(self.temp.name)/'bad.jsonl'
        bad.write_text(json.dumps(row())+'\n'+json.dumps(row(channel=999))+'\n')
        with self.assertRaises(AtlasError):
            scan_file(self.db,bad)
        self.assertEqual(self.store.stats()['wifi'],18)
    def test_legacy_history_stays_compatible_and_ineligible(self):
        o=row()
        for key in ('scan_freshness','scan_age_ms','frequency_mhz','channel'):
            o.pop(key)
        self.store.add([o])
        self.assertEqual(self.store.observations()[0]['name'],'Test Lab')
        with self.assertRaises(AtlasError):
            build_baseline(self.store,'synthetic:test')


class WifiCliTests(unittest.TestCase):
    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            base=[sys.executable,'-m','atlas','--db',str(Path(d)/'atlas.sqlite3'),'wifi']
            def run(*args):
                p=subprocess.run(base+list(args),cwd=ROOT,capture_output=True,text=True,timeout=5)
                self.assertEqual(p.returncode,0,p.stderr)
                return json.loads(p.stdout)
            result=run('scan','--input',str(TRAINING))
            self.assertFalse(result['radio_scan_performed'])
            self.assertEqual(set(result['bands']),{'2.4GHz','5GHz','6GHz'})
            b=run('baseline','--source',SOURCE)
            self.assertEqual(run('baseline','--source',SOURCE,'--show')['id'],b['id'])
            run('scan','--input',str(EVALUATION))
            self.assertEqual(len(run('anomalies','--source',SOURCE)['findings']),9)


if __name__=='__main__':
    unittest.main()
