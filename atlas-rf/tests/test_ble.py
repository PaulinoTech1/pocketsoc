"""BLE analysis/authorization tests use synthetic telemetry only."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from atlas.bluetooth.engine import analyze, analyze_and_store, inspect, scan_file
from atlas.bluetooth.gatt import request
from atlas.bluetooth.schema import normalize_uuid
from atlas.bridge.bundle import read_bundle
from atlas.core.errors import AtlasError
from atlas.core.events import validate
from atlas.storage.reader import reader
from atlas.storage.sqlite import Store

ROOT=Path(__file__).resolve().parents[1]
FIXTURE=ROOT/'examples/ble/telemetry.atlas.json'
SOURCE='synthetic:android-ble:lab'
ADDRESS='c2:11:22:33:44:01'
SINCE='2026-04-16T10:03:00Z'


def advertisement(**changes):
    value=dict(kind='ble',id=ADDRESS,name='Beacon',source=SOURCE,observed_at='2026-04-16T10:00:00Z',
               rssi=-64,service_uuids=['1809'],manufacturer_data={'65535':'0100'},
               advertisement_complete=True,connectable=True,evidence_confidence='synthetic')
    value.update(changes)
    return value


class BleSchemaTests(unittest.TestCase):
    def test_uuid_normalization_and_dedup(self):
        value=validate(advertisement(service_uuids=['180F','0000180f',normalize_uuid('180f')]))
        self.assertEqual(value['service_uuids'],[normalize_uuid('180f')])
    def test_invalid_payloads_and_bounds(self):
        for changes in ({'service_uuids':['invalid']},{'service_uuids':['180f']*65},
                        {'manufacturer_data':{'0x004c':'aa'}},{'manufacturer_data':{'65536':'aa'}},
                        {'manufacturer_data':{'76':'xyz'}},{'manufacturer_data':{'76':'aa'*257}},
                        {'advertisement_hex':'a'},{'advertisement_hex':'aa'*1651},
                        {'connectable':1},{'advertisement_complete':'true'},{'evidence_confidence':'certain'}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                validate(advertisement(**changes))
    def test_gatt_requires_scope_and_no_writes_or_pairing(self):
        value=next(o for o in read_bundle(FIXTURE).observations if o['kind']=='ble_gatt')
        for changes in ({'writes_performed':True},{'pairing_initiated':True},{'operation':'read_characteristic'},
                        {'authorization_id':'none'},{'gatt_services':[{'uuid':'1809','characteristics':[{'uuid':'2a1c','properties':256}]}]}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                validate(dict(value,**changes))
    def test_missing_metadata_not_invented(self):
        value=validate(dict(kind='ble',id=ADDRESS,source=SOURCE,observed_at='2026-04-16T10:00:00Z'))
        self.assertNotIn('service_uuids',value)
        self.assertNotIn('manufacturer_data',value)
        self.assertNotIn('evidence_confidence',value)
    def test_fields_not_allowed_on_other_event_kinds(self):
        with self.assertRaises(ValueError):
            validate(dict(kind='wifi',id=ADDRESS,source=SOURCE,observed_at='2026-04-16T10:00:00Z',security='WPA2',service_uuids=['180f']))


class BleEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'atlas.sqlite3'
        self.store=Store(self.path)
    def tearDown(self):
        self.store.close()
        self.temp.cleanup()
    def test_fixture_scan_anomalies_and_persisted_confidence(self):
        result=scan_file(self.path,FIXTURE)
        self.assertEqual(result['inserted'],11)
        self.assertFalse(result['radio_scan_performed'])
        result=analyze_and_store(self.path,SOURCE,SINCE)
        self.assertEqual({f['rule'] for f in result['findings']},
                         {'new-advertising-services','unexpected-advertisement-configuration',
                          'advertised-capabilities-added','known-gatt-capabilities-changed'})
        self.assertEqual(len(result['findings']),4)
        self.assertEqual(result['evidence_saved'],4)
        self.assertEqual(analyze_and_store(self.path,SOURCE,SINCE)['evidence_saved'],0)
        rows=self.store.db.execute('SELECT observed_at,confidence,body FROM ble_findings').fetchall()
        self.assertEqual(len(rows),4)
        self.assertTrue(all(t and c in ('low','medium') and json.loads(b)['physical_identity_confidence']=='unverified' for t,c,b in rows))
    def test_rotation_never_merges_by_name_payload_or_uuid(self):
        self.store.add([advertisement(),advertisement(id='62:ab:cd:ef:00:02',name='Changed',observed_at='2026-04-16T10:03:10Z')])
        result=analyze(self.store,SOURCE,SINCE)
        self.assertEqual(result['findings'],[])
        view=inspect(self.store,SOURCE,ADDRESS)
        self.assertEqual(view['total'],1)
        self.assertEqual(view['physical_identity_confidence'],'unverified')
    def test_address_reuse_after_window_does_not_establish_change(self):
        self.store.add([advertisement(),advertisement(name='Different',observed_at='2026-04-16T10:20:00Z')])
        self.assertEqual(analyze(self.store,SOURCE,SINCE)['findings'],[])
    def test_partial_advertisement_never_removes_capabilities(self):
        self.store.add([advertisement(),advertisement(service_uuids=[],manufacturer_data={},advertisement_complete=False,
                                                    observed_at='2026-04-16T10:03:10Z')])
        self.assertEqual(analyze(self.store,SOURCE,SINCE)['findings'],[])
    def test_missing_fields_do_not_establish_new_capabilities(self):
        initial=advertisement()
        initial.pop('service_uuids')
        self.store.add([initial,advertisement(observed_at='2026-04-16T10:03:10Z')])
        self.assertEqual(analyze(self.store,SOURCE,SINCE)['findings'],[])
    def test_failed_gatt_never_removes_capabilities(self):
        records=[o for o in read_bundle(FIXTURE).observations if o['kind']=='ble_gatt']
        self.store.add(records[:2])
        self.assertEqual(analyze(self.store,SOURCE,SINCE)['findings'],[])
    def test_source_isolation(self):
        self.store.add([advertisement(),advertisement(source='synthetic:other',name='Other',observed_at='2026-04-16T10:03:10Z')])
        self.assertEqual(analyze(self.store,'synthetic:other',SINCE)['findings'],[])
    def test_new_advertising_service_is_novelty_not_identity(self):
        self.store.add([advertisement(),advertisement(id='62:ab:cd:ef:00:02',service_uuids=['180f'],observed_at='2026-04-16T10:03:10Z')])
        result=analyze(self.store,SOURCE,SINCE)
        self.assertEqual([f['rule'] for f in result['findings']],['new-advertising-services'])
        self.assertFalse(result['findings'][0]['confirmed_attack'])
    def test_output_limit_is_explicit(self):
        self.store.add(read_bundle(FIXTURE).observations)
        result=analyze(self.store,SOURCE,SINCE,limit=1)
        self.assertTrue(result['coverage']['truncated'])
        self.assertEqual(len(result['findings']),1)
    def test_replay_and_invalid_batch_atomicity(self):
        self.assertEqual(scan_file(self.path,FIXTURE)['inserted'],11)
        self.assertEqual(scan_file(self.path,FIXTURE)['inserted'],0)
        bad=Path(self.temp.name)/'bad.jsonl'
        bad.write_text(json.dumps(advertisement())+'\n'+json.dumps(advertisement(service_uuids=['not uuid']))+'\n')
        with self.assertRaises(AtlasError):
            scan_file(self.path,bad)
        self.assertEqual(sum(self.store.stats().values()),11)
    def test_inspect_evidence_confidence_and_history(self):
        self.store.add(read_bundle(FIXTURE).observations)
        result=inspect(self.store,SOURCE,ADDRESS,limit=2)
        self.assertTrue(result['truncated'])
        self.assertEqual(len(result['evidence']),2)
        self.assertTrue(all(e['confidence']=='synthetic' for e in result['evidence']))


class GattAuthorizationTests(unittest.TestCase):
    def test_request_requires_explicit_authorization_and_scope(self):
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'request.json'
            with self.assertRaises(AtlasError):
                request(ADDRESS,False,output)
            self.assertFalse(output.exists())
            result=request(ADDRESS,True,output)
            self.assertFalse(result['connection_performed'])
            doc=json.loads(output.read_text())
            self.assertEqual(doc['operation'],'discover_services')
            self.assertFalse(doc['writes_allowed'])
            self.assertFalse(doc['pairing_allowed'])
            self.assertEqual(output.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):
                request(ADDRESS,True,output)
    def test_cli_fixture_workflow_and_unauthorized_request(self):
        with tempfile.TemporaryDirectory() as d:
            base=[sys.executable,'-m','atlas','--db',str(Path(d)/'atlas.sqlite3'),'ble']
            def run(*args,expected=0):
                result=subprocess.run(base+list(args),cwd=ROOT,capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,expected,result.stderr)
                return json.loads(result.stdout) if result.stdout else None
            run('scan','--input',str(FIXTURE))
            view=run('inspect','--address',ADDRESS,'--source',SOURCE)
            self.assertFalse(view['connection_performed'])
            self.assertEqual(len(run('anomalies','--source',SOURCE,'--since',SINCE)['findings']),4)
            target=Path(d)/'request.json'
            run('inspect','--address',ADDRESS,'--gatt','--output',str(target),expected=2)
            self.assertFalse(target.exists())
            run('inspect','--address',ADDRESS,'--gatt','--authorized','--output',str(target))
            self.assertTrue(target.exists())


if __name__=='__main__':
    unittest.main()
