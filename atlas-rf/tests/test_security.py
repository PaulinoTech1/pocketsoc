"""Security regressions: synthetic evidence only; never scan radios or probe host networks."""
import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from atlas.cli import main
from atlas_rf.cli import main as legacy
from atlas.bridge.bundle import BridgeError
from atlas.core.config import load_config
from atlas.core.events import validate
from atlas.core.isolation import command, probe, run, bounded
from atlas.core.privilege import enforce_unprivileged
from atlas.security.evidence import snapshot, verify
from atlas.security.retention import retain
from atlas.storage.sqlite import Store

ROOT = Path(__file__).resolve().parents[1]


def observation(**changes):
    value = dict(kind='wifi', id='02:00:00:00:00:01', source='synthetic:security',
                 observed_at='2026-01-01T00:00:00Z', name='Sensitive identifier', security='WPA2')
    value.update(changes)
    return value


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / 'evidence.db'
        store = Store(self.db)
        store.add([observation()])
        store.close()

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, args, entry=main):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = entry(['--db', str(self.db), *args])
        return code, out.getvalue(), err.getvalue()

    def test_snapshot_and_verification_are_read_only(self):
        before = self.db.read_bytes()
        first = snapshot(self.db)
        self.assertEqual(first['integrity'], 'VERIFIED')
        self.assertEqual(first['authenticity'], 'UNVERIFIED')
        self.assertEqual(snapshot(self.db), first)
        self.assertEqual(self.db.read_bytes(), before)

    def test_modified_body_is_detected(self):
        with sqlite3.connect(self.db) as db:
            value = json.loads(db.execute('SELECT body FROM observations').fetchone()[0])
            value['name'] = 'forged'
            db.execute('UPDATE observations SET body=?', (json.dumps(value),))
        with self.assertRaisesRegex(ValueError, 'integrity'):
            snapshot(self.db)

    def test_modified_indexed_metadata_is_detected(self):
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE observations SET source='forged'")
        with self.assertRaisesRegex(ValueError, 'integrity'):
            snapshot(self.db)

    def test_all_derived_tables_verify_and_tampering_fails(self):
        from atlas.bluetooth.engine import scan_file, analyze_and_store
        from atlas.detection.engine import run as detect
        from atlas.wifi.ingest import scan_file as wifi_scan
        from atlas.wifi.intelligence import build_baseline
        scan_file(self.db, ROOT/'examples/ble/telemetry.atlas.json')
        analyze_and_store(self.db, 'synthetic:android-ble:lab', '2026-04-16T10:03:00Z')
        wifi_scan(self.db, ROOT/'examples/wifi/training.atlas.json')
        store=Store(self.db)
        store.ingest(ROOT/'examples/detection/telemetry.jsonl')
        build_baseline(store,'synthetic:android-wifi:office')
        store.close()
        detect(self.db, ROOT/'config/detection.yaml', '2026-04-17T10:01:00Z')
        good=snapshot(self.db)
        self.assertEqual(set(good['tables']), {'observations','ble_findings','wifi_baselines','detection_findings'})
        for table in ('ble_findings','detection_findings'):
            with sqlite3.connect(self.db) as db:
                identity,body=db.execute(f'SELECT rowid,body FROM {table} LIMIT 1').fetchone()
                value=json.loads(body);value['confidence']='forged'
                db.execute(f'UPDATE {table} SET body=? WHERE rowid=?',(json.dumps(value),identity))
            with self.assertRaisesRegex(ValueError,'integrity'):
                snapshot(self.db)
            with sqlite3.connect(self.db) as db:
                db.execute(f'UPDATE {table} SET body=? WHERE rowid=?',(body,identity))
        retain(self.db,7,True,at='2026-10-29T00:00:00Z')
        self.assertTrue(all(count==0 for count in snapshot(self.db)['tables'].values()))

    def test_retention_transaction_rolls_back_on_derived_failure(self):
        with sqlite3.connect(self.db) as db:
            db.execute('CREATE TABLE ble_findings (observed_at TEXT)')
            db.execute("INSERT INTO ble_findings VALUES('2026-01-01T00:00:00Z')")
            db.execute("CREATE TRIGGER block_retention BEFORE DELETE ON ble_findings BEGIN SELECT RAISE(ABORT, 'blocked'); END")
        with self.assertRaises(sqlite3.Error):
            retain(self.db,7,True,at='2026-10-29T00:00:00Z')
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM observations').fetchone()[0],1)

    def test_manifest_detects_deletion(self):
        manifest = self.root / 'manifest.json'
        manifest.write_text(json.dumps(snapshot(self.db)))
        with sqlite3.connect(self.db) as db:
            db.execute('DELETE FROM observations')
        with self.assertRaisesRegex(ValueError, 'differs'):
            verify(self.db, manifest)

    def test_manifest_detects_valid_addition(self):
        manifest = self.root / 'manifest.json'
        manifest.write_text(json.dumps(snapshot(self.db)))
        store = Store(self.db)
        store.add([observation(observed_at='2026-01-02T00:00:00Z')])
        store.close()
        with self.assertRaises(ValueError):
            verify(self.db, manifest)

    def test_seal_private_exclusive_and_cli_verify(self):
        manifest = self.root / 'manifest.json'
        self.assertEqual(self.invoke(['security','seal','--output',str(manifest)])[0],0)
        self.assertEqual(manifest.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.invoke(['security','seal','--output',str(manifest)])[0],2)
        self.assertEqual(self.invoke(['security','verify','--manifest',str(manifest)])[0],0)

    def test_retention_preview_and_atomic_derived_copy_expiry(self):
        store = Store(self.db)
        store.db.execute('CREATE TABLE wifi_baselines (id TEXT, source TEXT, created_at TEXT, body TEXT)')
        store.db.execute("INSERT INTO wifi_baselines VALUES('x','test','2026-10-28T00:00:00.000000+00:00','{}')")
        store.db.commit()
        store.close()
        before = self.db.read_bytes()
        result = retain(self.db,7,at='2026-10-29T00:00:00Z')
        self.assertFalse(result['applied'])
        self.assertEqual(result['rows'],{'observations':1,'wifi_baselines':1})
        self.assertEqual(before,self.db.read_bytes())
        retain(self.db,7,True,at='2026-10-29T00:00:00Z')
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM observations').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM wifi_baselines').fetchone()[0],0)

    def test_retention_boundary_and_configuration_validation(self):
        self.assertEqual(retain(self.db,1,at='2026-01-02T00:00:00Z')['rows']['observations'],0)
        with self.assertRaisesRegex(ValueError, 'existing'):
            retain(self.root/'missing.db',7,True)
        self.assertFalse((self.root/'missing.db').exists())
        for days in (0, True, 3651, '7'):
            with self.assertRaises(ValueError):
                retain(self.db,days)
        config = self.root / 'config.yaml'
        config.write_text('storage: {retention_days: 30}')
        self.assertEqual(load_config(config).storage.retention_days,30)
        config.write_text('storage: {retention_days: false}')
        with self.assertRaises(Exception):
            load_config(config)

    def test_missing_read_database_is_not_created_by_either_cli(self):
        self.db.unlink()
        self.assertEqual(self.invoke(['status'])[0],0)
        self.assertFalse(self.db.exists())
        for action in ('history','report','topology'):
            self.assertEqual(self.invoke([action],legacy)[0],2)
            self.assertFalse(self.db.exists())

    def test_legacy_read_does_not_change_database(self):
        before = self.db.read_bytes()
        self.assertEqual(self.invoke(['history'],legacy)[0],0)
        self.assertEqual(self.db.read_bytes(),before)

    def test_tcp_probe_requires_explicit_authorization_before_database_creation(self):
        self.db.unlink()
        with patch('socket.socket',side_effect=AssertionError('unexpected network')):
            self.assertEqual(self.invoke(['probe','--scope','127.0.0.1','--ports','80'],legacy)[0],2)
        self.assertFalse(self.db.exists())

    def test_coordinate_and_credential_fields_rejected(self):
        for key in ('latitude','longitude','location','password','token','credentials'):
            with self.assertRaises(ValueError):
                validate(observation(**{key:'sensitive'}))

    def test_duplicate_keys_and_fifo_and_symlink_rejected(self):
        path = self.root / 'bad.jsonl'
        path.write_text('{"kind":"wifi","kind":"ble"}\n')
        store = Store(self.db)
        try:
            with self.assertRaises((ValueError, BridgeError)):
                store.ingest(path)
            link = self.root / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError):
                store.ingest(link)
            fifo = self.root / 'fifo'; os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError,'regular'):
                store.ingest(fifo)
            self.assertEqual(sum(store.stats().values()),1)
        finally:
            store.close()

    def test_hardlinked_database_and_sidecar_symlink_rejected(self):
        link = self.root / 'link.db'; os.link(self.db,link)
        with self.assertRaisesRegex(ValueError,'one link'):
            Store(link)
        link.unlink()
        sidecar = Path(str(self.db)+'-journal'); sidecar.symlink_to(self.root/'victim')
        with self.assertRaisesRegex(ValueError,'sidecar'):
            Store(self.db)
        self.assertFalse((self.root/'victim').exists())

    def test_batch_limit_rolls_back(self):
        store = Store(self.db)
        try:
            with patch('atlas.storage.sqlite.MAX_ROWS',1):
                with self.assertRaisesRegex(ValueError,'batch'):
                    store.add([observation(observed_at='2026-01-02T00:00:00Z'),observation(observed_at='2026-01-03T00:00:00Z')])
            self.assertEqual(sum(store.stats().values()),1)
        finally:
            store.close()

    def test_sensitive_errors_are_not_logged(self):
        bad = self.root / 'private-SUPERSECRET.jsonl'
        bad.write_text('{"source":"SUPERSECRET"}\n')
        code,out,err=self.invoke(['wifi','scan','--input',str(bad)])
        self.assertEqual(code,2)
        self.assertNotIn('SUPERSECRET',out+err)

    def test_analysis_cli_defaults_to_read_only(self):
        store = Store(self.db)
        store.ingest(ROOT/'examples/detection/telemetry.jsonl')
        store.close()
        before=self.db.read_bytes()
        code,out,_=self.invoke(['detect','run','--rules',str(ROOT/'config/detection.yaml'),'--at','2026-04-17T10:01:00Z'])
        self.assertEqual(code,0)
        self.assertTrue(json.loads(out)['preview'])
        self.assertEqual(json.loads(out)['saved'],0)
        self.assertEqual(self.db.read_bytes(),before)

    def test_privilege_refusal(self):
        with patch('atlas.core.privilege.os.geteuid',return_value=0):
            with self.assertRaisesRegex(ValueError,'ordinary user'):
                enforce_unprivileged()

    def test_android_permission_and_location_defaults(self):
        import xml.etree.ElementTree as ET
        manifest=ET.parse(ROOT/'android/collector/app/src/main/AndroidManifest.xml').getroot()
        attr='{http://schemas.android.com/apk/res/android}'
        perms={p.get(attr+'name'):p for p in manifest.findall('uses-permission')}
        self.assertEqual(set(perms), {'android.permission.ACCESS_WIFI_STATE','android.permission.CHANGE_WIFI_STATE',
            'android.permission.ACCESS_COARSE_LOCATION','android.permission.ACCESS_FINE_LOCATION',
            'android.permission.BLUETOOTH_SCAN','android.permission.BLUETOOTH_CONNECT',
            'android.permission.READ_PHONE_STATE','android.permission.ACCESS_NETWORK_STATE',
            'android.permission.CHANGE_NETWORK_STATE','android.permission.INTERNET'})
        self.assertEqual(perms['android.permission.BLUETOOTH_SCAN'].get(attr+'usesPermissionFlags'),'neverForLocation')
        source=(ROOT/'android/collector/app/src/main/java/org/atlasrf/collector/MainActivity.kt').read_text()
        self.assertIn('isChecked = false',source)
        self.assertIn('if (includeWifi.isChecked)',source)
        self.assertNotIn('getLastKnownLocation',source)


class IsolationTests(unittest.TestCase):
    def test_profile_has_no_host_data_or_network_mounts(self):
        with patch('atlas.core.isolation.trusted_tool',return_value='/usr/bin/bwrap'):
            args=command(['/usr/bin/true'])
        for flag in ('--unshare-all','--unshare-user','--disable-userns','--cap-drop','--clearenv','--new-session'):
            self.assertIn(flag,args)
        self.assertNotIn('--share-net',args)
        self.assertNotIn('--unshare-user-try',args)
        for path in ('/home','/run','/mnt/shared','/sys'):
            self.assertNotIn(path,args)

    def test_missing_isolation_never_falls_back(self):
        with patch('atlas.core.isolation.command',side_effect=ValueError('required isolation missing')), patch('atlas.core.isolation.bounded') as child:
            with self.assertRaises(ValueError):
                run(['/usr/bin/true'])
            child.assert_not_called()

    def test_failed_sandbox_is_not_retried_unsandboxed(self):
        with patch('atlas.core.isolation.trusted_tool', side_effect=lambda name: '/usr/bin/'+name), patch('atlas.core.isolation.bounded',side_effect=ValueError('denied')) as child:
            with self.assertRaises(ValueError):
                run(['/usr/bin/true'])
            self.assertEqual(child.call_count,1)
            self.assertEqual(Path(child.call_args.args[0][0]).name,'bwrap')

    def test_host_collector_profiles_refused(self):
        for tool in ('ip','nmcli','bluetoothctl'):
            with self.assertRaisesRegex(ValueError,'import telemetry'):
                run([tool])

    def test_argument_and_timeout_validation(self):
        for args in ('true',[],['true','\0'],['x'*4097]):
            with self.assertRaises(ValueError):
                run(args)
        for timeout in (True,0,31,float('nan')):
            with self.assertRaises(ValueError):
                run(['true'],timeout)

    def test_bounded_execution_timeout_and_output_limit(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            bounded(['/usr/bin/python3','-I','-c','import time;time.sleep(5)'],.05)
        with self.assertRaises(ValueError):
            bounded(['/usr/bin/python3','-I','-c',"import sys;sys.stdout.write('x'*(3*1024*1024))"],5)

    def test_real_runtime_probe_and_fail_closed_behavior(self):
        result=probe()
        self.assertEqual(result['fallback'],'refuse_execution')
        if result['usable']:
            self.assertEqual(run(['/usr/bin/true']),'')
        else:
            with self.assertRaises(ValueError):
                run(['/usr/bin/true'])
