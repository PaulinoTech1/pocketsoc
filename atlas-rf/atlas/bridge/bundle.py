"""Bounded, finalized file transport. SHA-256 detects damage, not sender authenticity."""
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import os
import stat
from pathlib import Path
import uuid
from atlas.core.errors import AtlasError
from atlas.core.events import MAX_LINE, validate

MAX_BUNDLE = 16 * 1024 * 1024
MAX_PAYLOAD = 8 * 1024 * 1024
MAX_EVENTS = 10_000


class BridgeError(AtlasError):
    pass


@dataclass(frozen=True)
class VerifiedBundle:
    metadata: dict
    observations: list
    digest: str
    payload_bytes: int
    authenticated: bool = False

    def summary(self):
        return dict(format='atlas-radio-export/v1', session_id=self.metadata['session_id'],
                    synthetic=self.metadata['synthetic'], observations=len(self.observations),
                    payload_bytes=self.payload_bytes, sha256=self.digest, integrity='VERIFIED',
                    authenticity='SHARED_KEY_VERIFIED' if self.authenticated else 'UNVERIFIED', hardware_access='UNVERIFIED',
                    note='Shared-key verification authenticates supplied bytes, not hardware origin; unsigned hashes establish integrity only.')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BridgeError('duplicate JSON key')
        result[key] = value
    return result


def parse(text):
    try:
        return json.loads(text, object_pairs_hook=unique_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(BridgeError('nonfinite JSON value')))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise BridgeError('invalid JSON document') from exc


def read_limited(path, maximum):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise BridgeError('export must be a regular file')
        if info.st_size > maximum:
            raise BridgeError('export exceeds transport size limit')
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise BridgeError('export exceeds transport size limit')
    return data


def read_bundle(path, key_path=None, nonce=None):
    envelope = parse(read_limited(path, MAX_BUNDLE))
    authenticated = isinstance(envelope, dict) and envelope.get("kind") == "atlas-authenticated-export"
    if authenticated:
        from atlas.cellular.transport import unwrap
        envelope = unwrap(envelope, key_path, nonce)
    return validate_envelope(envelope, authenticated)


def validate_envelope(envelope, authenticated=False):
    expected = {'kind', 'schema_version', 'complete', 'metadata', 'sha256', 'payload_jsonl'}
    if not isinstance(envelope, dict) or set(envelope) != expected:
        raise BridgeError('export must have exactly the documented envelope fields')
    if envelope['kind'] != 'atlas-radio-export' or type(envelope['schema_version']) is not int or envelope['schema_version'] != 1:
        raise BridgeError('unsupported bridge format')
    if envelope['complete'] is not True:
        raise BridgeError('export is not finalized')
    metadata = envelope['metadata']
    if not isinstance(metadata, dict) or len(json.dumps(metadata).encode()) > 65536:
        raise BridgeError('metadata must be a bounded object')
    if type(metadata.get('synthetic')) is not bool:
        raise BridgeError('metadata.synthetic must be boolean')
    for key in ('rows', 'bytes'):
        if type(metadata.get(key)) is not int or metadata[key] < 0:
            raise BridgeError(f'metadata.{key} must be a nonnegative integer')
    if metadata['rows'] > MAX_EVENTS or metadata['bytes'] > MAX_PAYLOAD:
        raise BridgeError('declared session limits exceeded')
    try:
        uuid.UUID(metadata['session_id'])
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise BridgeError('session_id must be a UUID') from exc
    payload = envelope['payload_jsonl']
    if not isinstance(payload, str):
        raise BridgeError('payload_jsonl must be a string')
    try:
        data = payload.encode('utf-8')
    except UnicodeError as exc:
        raise BridgeError('payload contains invalid Unicode') from exc
    if len(data) > MAX_PAYLOAD or len(data) != metadata['bytes']:
        raise BridgeError('payload byte count does not match')
    digest = hashlib.sha256(data).hexdigest()
    expected_hash = envelope['sha256']
    if not isinstance(expected_hash, str) or not re.fullmatch('[0-9a-f]{64}', expected_hash) or not hmac.compare_digest(digest, expected_hash):
        raise BridgeError('payload checksum mismatch')
    if data and not data.endswith(b'\n'):
        raise BridgeError('payload must end at a complete newline-delimited record')
    lines = data.splitlines()
    if len(lines) != metadata['rows']:
        raise BridgeError('payload row count does not match')
    observations = []
    for number, line in enumerate(lines, 1):
        if not line or len(line) + 1 > MAX_LINE:
            raise BridgeError(f'row {number}: blank or oversized record')
        try:
            observation = validate(parse(line))
        except (ValueError, TypeError, OverflowError) as exc:
            raise BridgeError(f'row {number}: invalid observation') from exc
        if observation['kind'] not in ('wifi', 'ble', 'ble_gatt', 'cellular'):
            raise BridgeError('bridge accepts only radio observation kinds')
        prefix = 'synthetic:' if metadata['synthetic'] else 'android:'
        if not observation['source'].startswith(prefix):
            raise BridgeError('source label conflicts with session provenance')
        observations.append(observation)
    statuses = metadata.get('statuses', {})
    cellular_session = any(o['kind'] == 'cellular' for o in observations) or (isinstance(statuses, dict) and any(str(k).startswith('cellular') for k in statuses))
    if not metadata["synthetic"] and cellular_session and not authenticated:
        raise BridgeError("real cellular exports require authenticated transport")
    return VerifiedBundle(metadata, observations, digest, len(data), authenticated)


def verify_probe(path, nonce):
    try:
        uuid.UUID(nonce)
    except (TypeError, ValueError, AttributeError) as exc:
        raise BridgeError('expected nonce must be a UUID displayed by the Android app') from exc
    doc = parse(read_limited(path, 4096))
    if not isinstance(doc, dict) or set(doc) != {'kind', 'schema_version', 'nonce', 'synthetic'}:
        raise BridgeError('invalid transport probe')
    if doc['kind'] != 'atlas-transport-probe' or type(doc['schema_version']) is not int or doc['schema_version'] != 1:
        raise BridgeError('unsupported probe format')
    try:
        uuid.UUID(doc['nonce'])
    except (TypeError, ValueError, AttributeError) as exc:
        raise BridgeError('probe nonce must be a UUID') from exc
    if type(doc['synthetic']) is not bool or not isinstance(doc['nonce'], str) or not hmac.compare_digest(doc['nonce'], nonce):
        raise BridgeError('probe nonce mismatch')
    shared = Path(path).resolve().is_relative_to(Path('/mnt/shared'))
    return dict(nonce_matches=True, synthetic=doc['synthetic'], path_on_android_share=shared,
                status='SUPPORTED' if shared and not doc['synthetic'] else 'UNVERIFIED',
                authenticity='UNVERIFIED',
                note='Operator-matched nonce verifies this file read; fixture/local reads do not prove Android-to-VM delivery.')
