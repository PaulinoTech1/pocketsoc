"""Deterministic policy checks with only synthetic observations."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml
from atlas.core.errors import AtlasError, ConfigurationError
from atlas.detection.engine import run, history, explain, security_rank
from atlas.detection.policy import load_policy
from atlas.storage.sqlite import Store

ROOT=Path(__file__).resolve().parents[1]
CLOCK='2026-04-17T10:01:00Z'
SOURCE='synthetic:detection:wifi'


def wifi(time='2026-04-17T10:00:00Z',**kwargs):
    value=dict(kind='wifi',id='02:aa:bb:cc:00:02',source=SOURCE,name='Atlas Lab',security='WPA2',
               observed_at=time,scan_freshness='fresh',scan_age_ms=100)
    value.update(kwargs)
    return value


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.db=Path(self.temp.name)/'atlas.db'
        self.rules=Path(self.temp.name)/'rules.yaml'
        self.policy=yaml.safe_load((ROOT/'config/detection.yaml').read_text())
        self.save()
        self.store=Store(self.db)
    def tearDown(self):
        self.store.close()
        self.temp.cleanup()
    def save(self):
        self.rules.write_text(yaml.safe_dump(self.policy))
    def assess(self):
        return run(self.db,self.rules,CLOCK)
    def fixture(self):
        self.store.ingest(ROOT/'examples/detection/telemetry.jsonl')
    def test_all_five_rules_and_complete_evidence(self):
        self.fixture()
        result=self.assess()
        self.assertEqual(result['saved'],5)
        self.assertEqual({f['rule_id'] for f in result['findings']},{r['id'] for r in self.policy['rules']})
        for f in result['findings']:
            for key in ('rule_id','timestamp','supporting_observations','severity','confidence','affected_assets','recommended_investigation'):
                self.assertTrue(f[key])
            self.assertEqual(len(f['supporting_observations']),2)
            self.assertEqual(f['classification'],'anomaly')
            self.assertFalse(f['confirmed_incident'])
            self.assertEqual(explain(self.db,f['id']),f)
        self.assertEqual(result['confirmed_incidents'],0)
    def test_replay_suppression_and_history_read_only(self):
        self.fixture()
        first=self.assess()
        self.assertEqual(self.assess()['saved'],0)
        self.assertEqual(self.assess()['suppressed'],5)
        data=self.db.read_bytes()
        h=history(self.db,limit=2)
        self.assertEqual(h['total'],5)
        self.assertTrue(h['truncated'])
        self.assertEqual(history(self.db,rule_id='network.exposure')['total'],1)
        explain(self.db,first['findings'][0]['id'])
        self.assertEqual(self.db.read_bytes(),data)
    def test_stale_cached_unknown_and_old_observations(self):
        records=[]
        for state in ('cached','stale','unknown'):
            records.extend([wifi(scan_freshness=state),wifi('2026-04-17T10:00:10Z',scan_freshness=state)])
        records.extend([wifi(scan_age_ms=30001),wifi('2026-04-17T10:00:10Z',scan_age_ms=30001),
                        wifi('2026-04-17T09:00:00Z'),wifi('2026-04-17T09:00:10Z')])
        self.store.add(records)
        self.assertEqual(self.assess()['saved'],0)
    def test_normal_multi_ap_and_unknown_security(self):
        self.policy['rules']=self.policy['rules'][:2]
        self.policy['rules'][1]['approved_bssids'].append('02:aa:bb:cc:00:02')
        self.save()
        self.store.add([wifi(security='UNKNOWN'),wifi('2026-04-17T10:00:10Z',security='UNKNOWN')])
        self.assertEqual(self.assess()['saved'],0)
    def test_wpa3_downgrade_and_mixed_modes(self):
        self.assertGreater(security_rank('WPA3'),security_rank('WPA2'))
        self.assertEqual(security_rank('[WPA2-PSK-CCMP][SAE]'),3)
        self.assertIsNone(security_rank('UNKNOWN'))
        self.policy['rules']=self.policy['rules'][:1]
        self.save()
        self.store.add([wifi(security='WPA3'),wifi('2026-04-17T10:00:10Z',security='WPA3')])
        self.assertEqual(self.assess()['saved'],0)
    def test_threshold_distinct_measurements_and_window(self):
        self.store.add([wifi(),wifi(rssi=-55)])
        self.assertEqual(self.assess()['saved'],0)
        self.store.add([wifi('2026-04-17T10:00:10Z')])
        self.assertEqual(self.assess()['saved'],2)
    def test_threshold_window_expiry(self):
        self.policy['defaults']['window_seconds']=5
        self.save()
        self.store.add([wifi(),wifi('2026-04-17T10:00:10Z')])
        self.assertEqual(self.assess()['saved'],0)
    def test_source_and_ssid_scope(self):
        self.store.add([wifi(source='synthetic:other'),wifi('2026-04-17T10:00:10Z',source='synthetic:other'),
                        wifi(name='Other'),wifi('2026-04-17T10:00:10Z',name='Other')])
        self.assertEqual(self.assess()['saved'],0)
    def test_new_measurements_suppressed_during_cooldown(self):
        self.store.add([wifi(),wifi('2026-04-17T10:00:10Z')])
        self.assertEqual(self.assess()['saved'],2)
        self.store.add([wifi('2026-04-17T10:00:20Z'),wifi('2026-04-17T10:00:30Z')])
        self.assertEqual(self.assess()['saved'],0)
    def test_changed_policy_resets_matching_scope(self):
        self.store.add([wifi(),wifi('2026-04-17T10:00:10Z')])
        self.assertEqual(self.assess()['saved'],2)
        self.policy['rules']=self.policy['rules'][:1]
        self.policy['rules'][0]['expected_security']='WPA2'
        self.save()
        self.assertEqual(self.assess()['saved'],0)
    def test_ble_rotation_partial_and_missing_uuids(self):
        records=[]
        for second in (0,10):
            base=dict(kind='ble',id='c2:11:22:33:44:01',source='synthetic:detection:ble',
                      observed_at=f'2026-04-17T10:00:{second:02d}Z',advertisement_complete=True)
            records.extend([base,dict(base,service_uuids=[]),dict(base,service_uuids=['181a'],advertisement_complete=False),
                            dict(base,id='62:ab:cd:ef:00:02',service_uuids=['181a'])])
        self.store.add(records)
        self.assertEqual(self.assess()['saved'],0)
    def test_gatt_failures_and_complete_changes(self):
        self.policy['rules']=[self.policy['rules'][2]]
        self.policy['rules'][0]['evidence_kind']='gatt'
        self.save()
        records=[]
        for second in (0,10):
            records.append(dict(kind='ble_gatt',id='c2:11:22:33:44:01',source='synthetic:detection:ble',
                observed_at=f'2026-04-17T10:00:{second:02d}Z',authorization_id='00000000-0000-4000-8000-000000000001',
                operation='discover_services',writes_performed=False,pairing_initiated=False,gatt_status='timeout',gatt_services=[]))
        self.store.add(records)
        self.assertEqual(self.assess()['saved'],0)
        self.store.add([dict(o,gatt_status='complete') for o in records])
        self.assertEqual(self.assess()['saved'],1)
        self.assertTrue(self.assess()['suppressed'])
    def test_allowed_networks_ports_and_no_protocol_guess(self):
        self.fixture()
        f=next(f for f in self.assess()['findings'] if f['rule_id']=='network.management-interface')
        self.assertEqual(f['explanation']['management_protocol'],'unverified')
        self.assertNotIn('192.0.2.5',[a['observed_id'] for f in history(self.db)['findings'] for a in f['affected_assets']])
    def test_rules_disabled(self):
        self.fixture()
        for r in self.policy['rules']: r['enabled']=False
        self.save()
        self.assertEqual(self.assess()['saved'],0)
    def test_missing_database_not_created(self):
        missing=Path(self.temp.name)/'missing.db'
        with self.assertRaises(AtlasError): run(missing,self.rules,CLOCK)
        self.assertFalse(missing.exists())
    def test_limits_fail_atomically(self):
        self.fixture()
        with patch('atlas.detection.engine.MAX_FINDINGS',1),self.assertRaises(AtlasError): self.assess()
        self.assertEqual(history(self.db)['total'],0)
        with patch('atlas.detection.engine.MAX_ROWS',1),self.assertRaises(AtlasError): self.assess()
        self.assertEqual(history(self.db)['total'],0)
    def test_no_finding_and_bad_history_limits(self):
        self.assertEqual(history(self.db)['total'],0)
        with self.assertRaises(AtlasError): explain(self.db,'0'*64)
        with self.assertRaises(AtlasError): explain(self.db,'bad')
        with self.assertRaises(AtlasError): history(self.db,0)
    def test_deterministic_across_databases_and_input_order(self):
        self.fixture()
        first=self.assess()['findings']
        other=Path(self.temp.name)/'second.db'
        store=Store(other)
        try:
            rows=[json.loads(line) for line in (ROOT/'examples/detection/telemetry.jsonl').read_text().splitlines()]
            store.add(reversed(rows))
        finally: store.close()
        self.assertEqual(first,run(other,self.rules,CLOCK)['findings'])
    def test_strict_yaml_and_policy_types(self):
        valid=copy.deepcopy(self.policy)
        for change in ({'min_observations':True},{'min_observations':21},{'confidence':'certain'},{'type':'eval'},
                       {'sources':[]},{'extra':'bad'},{'severity':[]},{'expected_security':'unknown'}):
            self.policy=copy.deepcopy(valid)
            self.policy['rules'][0].update(change)
            self.save()
            with self.subTest(change=change),self.assertRaises((ConfigurationError,ValueError)):
                load_policy(self.rules)
        for text in ('version: 1\nversion: 1\nrules: []\n','version: 1\nrules: &x []\n','!!python/object:builtins.object {}','x'*65537):
            self.rules.write_text(text)
            with self.assertRaises(ConfigurationError): load_policy(self.rules)
    def test_equal_timestamp_evidence_is_independent_of_import_order(self):
        rows=[wifi(rssi=-60),wifi(rssi=-50),wifi('2026-04-17T10:00:10Z',rssi=-55)]
        self.store.add(rows)
        first=self.assess()['findings']
        other=Path(self.temp.name)/'reverse.db'
        store=Store(other)
        try: store.add(reversed(rows))
        finally: store.close()
        self.assertEqual(first,run(other,self.rules,CLOCK)['findings'])
    def test_cooldown_expiry_allows_new_measurements(self):
        self.policy['defaults']['cooldown_seconds']=15
        self.save()
        self.store.add([wifi(),wifi('2026-04-17T10:00:10Z')])
        first=self.assess()
        self.assertEqual(first['saved'],2)
        self.store.add([wifi('2026-04-17T10:00:30Z')])
        result=self.assess()
        self.assertEqual(result['saved'],2)
        self.assertTrue(all(f['timestamp']=='2026-04-17T10:00:30.000000+00:00' for f in result['findings']))
    def test_future_observations_do_not_change_historical_assessment(self):
        self.store.add([wifi('2026-04-17T10:02:00Z'),wifi('2026-04-17T10:02:10Z')])
        self.assertEqual(self.assess()['saved'],0)
    def test_purge_invalidates_retained_sensitive_evidence(self):
        self.fixture()
        finding=self.assess()['findings'][0]
        self.store.purge('2026-04-18T00:00:00Z')
        self.assertEqual(self.store.stats(),{})
        with self.assertRaisesRegex(AtlasError, 'not found'):
            explain(self.db,finding['id'])
    def test_detection_does_not_open_collectors_or_network(self):
        self.fixture()
        with patch('socket.socket',side_effect=AssertionError('unexpected socket')):
            self.assertEqual(self.assess()['saved'],5)
    def test_network_approved_endpoints_and_old_exposure(self):
        self.policy['rules']=self.policy['rules'][3:]
        self.save()
        rows=[]
        for second in (0,10):
            rows.append(dict(kind='service',id='192.0.2.5/tcp/443',ip='192.0.2.5',port=443,
                             source='synthetic:detection:network',observed_at=f'2026-04-17T10:00:{second:02d}Z'))
            rows.append(dict(kind='service',id='192.0.2.55/tcp/22',ip='192.0.2.55',port=22,
                             source='synthetic:detection:network',observed_at=f'2026-04-17T09:00:{second:02d}Z'))
        self.store.add(rows)
        self.assertEqual(self.assess()['saved'],0)
    def test_ipv6_network_policy(self):
        self.policy['rules']=[self.policy['rules'][4]]
        self.policy['rules'][0]['allowed_networks']=['2001:db8::/64']
        self.save()
        rows=[]
        for second in (0,10):
            rows.append(dict(kind='service',id='2001:db8::1/tcp/443',ip='2001:db8::1',port=443,
                             source='synthetic:detection:network',observed_at=f'2026-04-17T10:00:{second:02d}Z'))
        self.store.add(rows)
        self.assertEqual(self.assess()['saved'],0)
    def test_zero_cooldown_still_suppresses_exact_replay(self):
        self.policy['defaults']['cooldown_seconds']=0
        self.save()
        self.fixture()
        self.assertEqual(self.assess()['saved'],5)
        self.assertEqual(self.assess()['saved'],0)
    def test_gatt_expected_services_are_not_a_change(self):
        self.policy['rules']=[self.policy['rules'][2]]
        self.policy['rules'][0]['evidence_kind']='gatt'
        self.save()
        for second in (0,10):
            self.store.add([dict(kind='ble_gatt',id='c2:11:22:33:44:01',source='synthetic:detection:ble',
                observed_at=f'2026-04-17T10:00:{second:02d}Z',authorization_id='00000000-0000-4000-8000-000000000001',
                operation='discover_services',writes_performed=False,pairing_initiated=False,gatt_status='complete',
                gatt_services=[dict(uuid='180f',characteristics=[])])])
        self.assertEqual(self.assess()['saved'],0)
    def test_cli_run_explain_history(self):
        self.fixture()
        base=[sys.executable,'-m','atlas','--db',str(self.db),'detect']
        def call(*args):
            result=subprocess.run(base+list(args),cwd=ROOT,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            return json.loads(result.stdout)
        result=call('run','--save','--rules',str(self.rules),'--at',CLOCK)
        self.assertEqual(result['saved'],5)
        identity=result['findings'][0]['id']
        self.assertEqual(call('explain',identity)['id'],identity)
        self.assertEqual(call('history')['total'],5)
