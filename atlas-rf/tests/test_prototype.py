"""Integrated controlled-fixture, CLI and resource regression coverage."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from atlas.cli import main
from atlas.core.events import validate
from atlas.demo import scenario
from atlas.storage.sqlite import Store
from atlas.topology.graph import topology
from atlas.ui.dashboard import snapshot

ROOT=Path(__file__).resolve().parents[1]


class PrototypeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory()
        cls.root=Path(cls.temporary.name)
        cls.output=cls.root/'demo'
        completed=subprocess.run([sys.executable,'-m','atlas','demo','--output',str(cls.output),'--events','100'],
                                 cwd=ROOT,capture_output=True,text=True,timeout=120)
        if completed.returncode:
            raise AssertionError(completed.stderr)
        cls.result=json.loads(completed.stdout)
        cls.db=cls.output/'demo.sqlite3'

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def invoke(self,*args):
        out,err=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            code=main(['--db',str(self.db),*args])
        return code,out.getvalue(),err.getvalue()

    def test_full_scenario_and_replay_accounting(self):
        self.assertEqual(self.result['findings'],dict(wifi=9,ble=4,policy=5))
        self.assertEqual(self.result['fixture_event_accounting'],dict(submitted=55,stored=55,loss=0,
                                                                    replay_submitted=12,replay_inserted=0))
        self.assertFalse(self.result['hardware_measurements'])
        self.assertEqual(self.result['evidence_integrity'],'VERIFIED')

    def test_labelled_confusion_matrix(self):
        score=self.result['detection_accuracy']
        self.assertEqual(score['matrix'],dict(true_positive=5,false_positive=0,true_negative=15,false_negative=0))
        self.assertEqual(score['accuracy'],1)
        self.assertEqual(score['false_positive_rate'],0)
        self.assertEqual(len({c['case_id'] for c in score['cases']}),20)

    def test_fresh_process_resource_and_latency_accounting(self):
        metrics=self.result['resources']
        self.assertEqual(metrics['events_submitted'],100)
        self.assertEqual(metrics['events_stored'],100)
        self.assertEqual(metrics['event_loss'],0)
        self.assertEqual(metrics['event_processing_latency_ms']['samples'],100)
        self.assertGreater(metrics['cpu_seconds'],0)
        self.assertGreater(metrics['cpu_utilization_percent_one_core'],0)
        self.assertLess(metrics['peak_rss_bytes_process_lifetime'],150*1024*1024)
        self.assertLess(metrics['event_processing_latency_ms']['p95'],1000)
        self.assertTrue(metrics['budget_pass'])

    def test_all_requested_artifacts_exist_and_are_private(self):
        for name in ('baseline.json','evidence.json','evidence-manifest.json','results.json','report.md','dashboard.txt'):
            path=self.output/name
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_mode&0o777,0o600)
        self.assertEqual(self.output.stat().st_mode&0o777,0o700)

    def test_unified_read_cli_keeps_database_unchanged(self):
        before=self.db.read_bytes()
        for args in (['history'],['topology'],['report'],['security','verify'],['detect','history'],
                     ['wifi','baseline','--source','synthetic:android-wifi:office','--show']):
            code,out,_=self.invoke(*args)
            self.assertEqual(code,0,args)
            self.assertTrue(json.loads(out))
        self.assertEqual(before,self.db.read_bytes())

    def test_ip_analysis_is_scoped_and_never_opens_socket(self):
        with patch('socket.socket',side_effect=AssertionError('unexpected socket')):
            code,out,_=self.invoke('ip','analyze','--source','synthetic:detection:network','--scope','192.0.2.0/24')
        self.assertEqual(code,0)
        result=json.loads(out)
        self.assertEqual(len(result['observations']),6)
        self.assertEqual(result['network_connections_performed'],0)
        code,out,_=self.invoke('ip','analyze','--source','synthetic:detection:network','--scope','192.0.2.5')
        self.assertEqual(code,0)
        self.assertEqual(len(json.loads(out)['observations']),2)

    def test_unified_probe_fails_before_storage_without_authorization(self):
        with patch('socket.socket',side_effect=AssertionError('unexpected socket')):
            self.assertEqual(self.invoke('ip','probe','--scope','127.0.0.1','--ports','80')[0],2)

    def test_dashboard_plain_frame_is_safe_and_read_only(self):
        before=self.db.read_bytes()
        code,out,_=self.invoke('dashboard','--once')
        self.assertEqual(code,0)
        self.assertIn('ATLAS RF',out)
        self.assertIn('Retained evidence',out)
        self.assertNotIn('\x1b',out)
        self.assertEqual(before,self.db.read_bytes())

    def test_dashboard_refresh_gets_new_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'live.sqlite3'
            store=Store(db);store.add([scenario()['policy_observations'][0]]);store.close()
            self.assertEqual(snapshot(db)['total'],1)
            store=Store(db);store.add([scenario()['policy_observations'][1]]);store.close()
            self.assertEqual(snapshot(db)['total'],2)

    def test_cross_protocol_topology_is_explicit_not_physical_identity(self):
        graph=json.loads((self.output/'evidence.json').read_text())['topology']
        self.assertGreater(graph['cross_protocol_hints'],0)
        self.assertTrue({'wifi','ble','host','service','mac'}<={n['kind'] for n in graph['nodes']})
        for edge in graph['edges']:
            if edge['relation']=='address-equality-unverified':
                self.assertEqual(edge['confidence'],'low')
                self.assertTrue(edge['source'].startswith('mac:'))
                self.assertTrue(edge['target'].startswith('wifi:'))

    def test_radio_addresses_do_not_merge_sources_or_protocols(self):
        row=scenario()['wifi_training'][0]
        same_address=validate(dict(kind='ble',id=row['id'],source='synthetic:other',observed_at=row['observed_at']))
        graph=topology([row,dict(row,source='synthetic:second'),same_address])
        self.assertEqual(len([n for n in graph['nodes'] if n['kind']=='wifi']),2)
        self.assertEqual(len(graph['edges']),3)
        self.assertEqual(graph['cross_protocol_hints'],0)

    def test_report_integrates_retained_evidence(self):
        code,out,_=self.invoke('report')
        self.assertEqual(code,0)
        saved=json.loads(out)['retained_evidence']
        self.assertEqual(saved['wifi_baselines']['total'],1)
        self.assertEqual(saved['ble_findings']['total'],4)
        self.assertEqual(saved['detection_findings']['total'],5)

    def test_large_retained_evidence_is_bounded_and_reports_truncation(self):
        from atlas.reporting.reports import report
        from atlas.storage.reader import reader
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'bounded.sqlite3'
            store=Store(db)
            store.db.execute('CREATE TABLE ble_findings (body TEXT)')
            store.db.execute('INSERT INTO ble_findings VALUES(?)',(json.dumps({'padding':'x'*(1024*1024+1)}),))
            store.db.commit();store.close()
            with reader(db) as store:
                evidence=report(store)['retained_evidence']['ble_findings']
            self.assertEqual(evidence['total'],1)
            self.assertEqual(evidence['records'],[])
            self.assertTrue(evidence['truncated'])
            frame=snapshot(db,mode='findings')
            self.assertTrue(frame['saved_findings_truncated'])
            self.assertLess(sum(map(len,frame['lines'])),2000)

    def test_invalid_import_does_not_initialize_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'missing.sqlite3';bad=Path(tmp)/'bad.jsonl';bad.write_text('{}\n')
            from atlas.storage.ingest import ingest_file
            with self.assertRaises(ValueError): ingest_file(db,bad)
            self.assertFalse(db.exists())

    def test_demo_refuses_existing_output_and_production_db_override(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(out):
            self.assertEqual(main(['demo','--output',str(self.output),'--events','100']),2)
            self.assertEqual(main(['--db',str(self.db),'demo','--output',str(self.root/'new')]),2)
        self.assertFalse((self.root/'new').exists())

    def test_legacy_import_alias_uses_the_unified_cli(self):
        from atlas_rf.cli import main as alias
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'alias.sqlite3'
            with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(alias(['--db',str(db),'import',str(self.output/'network_observations.jsonl')]),0)
            self.assertEqual(snapshot(db)['total'],2)
