"""Local synthetic protocol cases, never Android or modem acceptance evidence."""
import json
from pathlib import Path
import tempfile
import unittest

from atlas.bridge.bundle import BridgeError, read_bundle
from atlas.cellular.transport import generate_key, key_bytes, challenge
from atlas.core.events import validate
from atlas.storage.reader import reader
from test_cellular_transport import envelope, signed_export


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inbox = self.root/'inbox'; self.inbox.mkdir()
        self.db = self.root/'private'/'atlas.sqlite3'
        self.key = self.root/'bridge.key'; generate_key(self.key)
        self.nonce = challenge(self.root/'challenge.json')['nonce']

    def export(self, name='session.atlas.json', rows=None, statuses=None):
        # A locally generated authenticated envelope with android labels tests validation,
        # not physical provenance; never used for hardware completion.
        inner = envelope(rows or [], synthetic=False, nonce=self.nonce)
        inner['metadata']['statuses'] = statuses or {'cellular': 'listening_public_apis', 'cellular:subscriptions': 'none_active'}
        path = self.inbox/name
        path.write_text(json.dumps(signed_export(inner, key_bytes(self.key))))
        return path

    def test_disabled_cellular_is_not_collection_but_failed_collection_requires_mac(self):
        path = self.inbox/'wifi.atlas.json'
        inner = envelope([], synthetic=False)
        inner['metadata']['statuses'] = {'cellular': 'disabled_by_default'}
        path.write_text(json.dumps(inner))
        self.assertFalse(read_bundle(path).authenticated)
        inner['metadata']['statuses']['cellular'] = 'read_phone_state_required'
        path.write_text(json.dumps(inner))
        with self.assertRaises(BridgeError): read_bundle(path)

    def test_default_radio_scope_accepts_no_subscription_without_inventing_one(self):
        value = dict(kind='cellular', id='test', source='synthetic:default-radio',
                     observed_at='2026-10-29T12:00:00Z', collection_session='test',
                     cellular_event='signal', technology='LTE', lte_rsrp=-100,
                     cell_freshness='unknown', subscription_scope='default_radio')
        self.assertNotIn('subscription_id', validate(value))
        with self.assertRaises(ValueError): validate({k:v for k,v in value.items() if k != 'subscription_scope'})
        with self.assertRaises(ValueError): validate(dict(value, subscription_id=0))
        with self.assertRaises(ValueError): validate(dict(value, cellular_event='subscription', technology='LTE'))

    def test_status_only_session_ingests_without_radio_success(self):
        from atlas.bridge.inbox import poll
        self.export()
        result = poll(self.inbox, self.db, self.key, self.nonce, {})
        self.assertEqual(result['accepted'], 1)
        self.assertEqual(result['inserted'], 0)
        self.assertEqual(result['measurement_rows'], 0)
        self.assertEqual(result['hardware_access'], 'UNVERIFIED')
        with reader(self.db) as store:
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM cellular_sessions').fetchone()[0], 1)

    def test_bad_auth_and_partial_files_do_not_initialize_storage(self):
        from atlas.bridge.inbox import poll
        path = self.export(); doc=json.loads(path.read_text()); doc['hmac_sha256']='0'*64
        path.write_text(json.dumps(doc))
        (self.inbox/'partial.atlas.json').write_text('{')
        result = poll(self.inbox, self.db, self.key, self.nonce, {})
        self.assertEqual(result['rejected'], 2)
        self.assertFalse(self.db.exists())

    def test_changed_partial_retried_and_valid_replay_deduplicated(self):
        from atlas.bridge.inbox import poll
        seen={}; path=self.inbox/'session.atlas.json'; path.write_text('{')
        self.assertEqual(poll(self.inbox,self.db,self.key,self.nonce,seen)['rejected'],1)
        self.export()
        self.assertEqual(poll(self.inbox,self.db,self.key,self.nonce,seen)['accepted'],1)
        self.assertEqual(poll(self.inbox,self.db,self.key,self.nonce,seen)['unchanged'],1)
        self.assertEqual(poll(self.inbox,self.db,self.key,self.nonce,{})['inserted'],0)

    def test_missing_directory_is_transport_not_sim_failure(self):
        from atlas.bridge.inbox import poll
        result=poll(self.root/'missing',self.db,self.key,self.nonce,{})
        self.assertEqual(result['transport'],'INBOX_UNAVAILABLE')
        self.assertFalse(self.db.exists())

    def test_synthetic_and_symlink_exports_are_rejected(self):
        from atlas.bridge.inbox import poll
        inner=envelope([],synthetic=True,nonce=self.nonce)
        (self.inbox/'fixture.atlas.json').write_text(json.dumps(signed_export(inner,key_bytes(self.key))))
        target=self.root/'outside.atlas.json';target.write_text('{}')
        (self.inbox/'alias.atlas.json').symlink_to(target)
        result=poll(self.inbox,self.db,self.key,self.nonce,{})
        self.assertEqual(result['rejected'],2)
        self.assertFalse(self.db.exists())

    def test_cellular_rows_ingested_and_default_scope_not_trained_as_subscription(self):
        from atlas.bridge.inbox import poll
        row=dict(kind='cellular',id='test',source='android:test:cellular',
                 observed_at='2026-10-29T12:00:00Z',collection_session='test',
                 cellular_event='signal',technology='LTE',lte_rsrp=-100,
                 cell_freshness='unknown',subscription_scope='default_radio')
        self.export(rows=[row])
        result=poll(self.inbox,self.db,self.key,self.nonce,{})
        self.assertEqual(result['inserted'],1)
        self.assertEqual(result['measurement_rows'],1)
        with reader(self.db) as store:
            self.assertNotIn('subscription_id',store.observations()[0])

    def test_wrong_challenge_is_auth_failure_and_not_measurement_failure(self):
        from atlas.bridge.inbox import poll
        self.export()
        result=poll(self.inbox,self.db,self.key,'f'*64,{})
        self.assertEqual(result['errors'][0]['category'],'AUTHENTICATION_FAILED')
        self.assertEqual(result['measurement_rows'],0)
        self.assertFalse(self.db.exists())

    def test_default_cell_not_eligible_for_subscribed_baseline_or_serving_trends(self):
        from atlas.cellular.analysis import analyze, serving
        value=validate(dict(kind='cellular', id='default', source='synthetic:radio',
                       observed_at='2026-10-29T12:00:00Z', collection_session='test',
                       cellular_event='cell', technology='LTE', lte_rsrp=-100,
                       cell_freshness='recent', cell_origin='callback', cell_age_ms=0,
                       measurement_elapsed_ms=1000, registered=True, mcc='310',mnc='260',
                       cell_id=123, subscription_scope='default_radio'))
        self.assertFalse(serving(value))
        self.assertEqual(analyze([value])['trends'],[])

    def test_cli_watch_once_and_idempotent_measurements(self):
        import contextlib
        import io
        from atlas.cli import main
        from atlas.bridge.inbox import poll
        row=dict(kind='cellular',id='one',source='android:test:cellular',
                 observed_at='2026-10-29T12:00:00Z',collection_session='test',
                 cellular_event='signal',technology='LTE',lte_rsrp=-100,
                 cell_freshness='unknown',subscription_scope='default_radio')
        self.export(rows=[row])
        output=io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            code=main(['--db',str(self.db),'bridge','watch','--inbox',str(self.inbox),
                       '--key',str(self.key),'--nonce',self.nonce,'--once'])
        self.assertEqual(code,0)
        self.assertEqual(json.loads(output.getvalue())['inserted'],1)
        self.assertEqual(poll(self.inbox,self.db,self.key,self.nonce,{})['inserted'],0)

    def test_inbox_bound_and_no_writes_to_share(self):
        from atlas.bridge.inbox import poll
        from unittest.mock import patch
        self.export()
        before={p.name:p.read_bytes() for p in self.inbox.iterdir()}
        poll(self.inbox,self.db,self.key,self.nonce,{})
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.inbox.iterdir()})
        with patch('atlas.bridge.inbox.MAX_ENTRIES',0):
            result=poll(self.inbox,self.db,self.key,self.nonce,{})
        self.assertEqual(result['transport'],'INBOX_LIMIT_EXCEEDED')
