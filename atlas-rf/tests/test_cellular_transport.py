"""Local authenticated-protocol validation; explicitly not Android hardware evidence."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from atlas.bridge.bundle import read_bundle
from atlas.cellular.transport import DOMAIN, generate_key, key_bytes, challenge


def envelope(rows, synthetic=True, nonce=None):
    payload = ''.join(json.dumps(o) + '\n' for o in rows)
    metadata = dict(session_id=str(uuid.uuid4()), synthetic=synthetic, rows=len(rows), bytes=len(payload.encode()))
    if nonce is not None:
        metadata['bridge_nonce'] = nonce
    return dict(kind='atlas-radio-export', schema_version=1, complete=True,
                metadata=metadata, sha256=hashlib.sha256(payload.encode()).hexdigest(), payload_jsonl=payload)


def signed_export(inner, key):
    signed = json.dumps(inner, ensure_ascii=False, separators=(',', ':'))
    return dict(kind='atlas-authenticated-export', schema_version=1, signed_json=signed,
                hmac_sha256=hmac.new(key, DOMAIN + signed.encode(), hashlib.sha256).hexdigest())


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = self.root/'bridge.key'
        generate_key(self.key)
        self.nonce = challenge(self.root/'challenge.json')['nonce']
        self.export = self.root/'session.atlas.json'
        self.inner = envelope([], nonce=self.nonce)
        self.doc = signed_export(self.inner, key_bytes(self.key))
        self.export.write_text(json.dumps(self.doc))

    def test_signed_challenge_response(self):
        result = read_bundle(self.export, self.key, self.nonce)
        self.assertTrue(result.authenticated)
        self.assertEqual(result.summary()['authenticity'], 'SHARED_KEY_VERIFIED')
        self.assertEqual(result.summary()['hardware_access'], 'UNVERIFIED')

    def test_tamper_wrong_key_missing_key_and_replay_challenge_rejected(self):
        for key, nonce in ((None, self.nonce), (self.key, 'a'*64)):
            with self.assertRaises(ValueError): read_bundle(self.export, key, nonce)
        self.key.write_text('00'*32)
        with self.assertRaises(ValueError): read_bundle(self.export, self.key, self.nonce)
        self.doc['signed_json'] += ' '
        self.export.write_text(json.dumps(self.doc))
        with self.assertRaises(ValueError): read_bundle(self.export, self.key, self.nonce)

    def test_key_permissions_and_symlink_rejected(self):
        os.chmod(self.key, 0o644)
        with self.assertRaises(ValueError): key_bytes(self.key)
        os.chmod(self.key, 0o600)
        alias = self.root/'alias'; alias.symlink_to(self.key)
        with self.assertRaises(OSError): key_bytes(alias)

    def test_invalid_outer_version_and_nonhex_mac_rejected(self):
        for field, value in (('schema_version', True), ('hmac_sha256', 'é'*64)):
            doc = dict(self.doc, **{field: value})
            self.export.write_text(json.dumps(doc))
            with self.assertRaises(ValueError): read_bundle(self.export, self.key, self.nonce)

    def test_metadata_covered_by_authentication(self):
        inner = json.loads(self.doc['signed_json'])
        inner['metadata']['synthetic'] = False
        self.doc['signed_json'] = json.dumps(inner)
        self.export.write_text(json.dumps(self.doc))
        with self.assertRaises(ValueError): read_bundle(self.export, self.key, self.nonce)


class InteroperabilityVectorTests(unittest.TestCase):
    def test_utf8_domain_vector_matches_kotlin_test(self):
        value = '{"carrier":"Tést"}'
        digest = hmac.new(bytes(range(32)), DOMAIN + value.encode('utf-8'), hashlib.sha256).hexdigest()
        self.assertEqual(digest, "c284a780583cad6462a33289e9c604926bada30b23bf7d8aedf690c784c9b456")
