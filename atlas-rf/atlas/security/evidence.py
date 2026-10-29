"""Bounded logical evidence verification and externally retainable snapshot digests."""
import hashlib
import hmac
from atlas.bridge.bundle import parse, read_limited
from atlas.core.events import encoded, fingerprint, validate
from atlas.storage.reader import reader

TABLES = {'observations', 'wifi_baselines', 'ble_findings', 'detection_findings', 'cellular_baselines', 'cellular_sessions'}
MAX_ROWS = 200_000
MAX_BYTES = 256 * 1024 * 1024


def snapshot(path):
    digest = hashlib.sha256()
    counts = {}
    total = size = 0
    with reader(path) as store:
        db = store.db
        # Bound malicious schemas and SQLite work as well as returned data.
        ticks = [0]
        def progress():
            ticks[0] += 1
            return ticks[0] > 200_000
        db.set_progress_handler(progress, 1000)
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise ValueError('SQLite integrity check failed')
        tables = list(db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"))
        if any(name not in TABLES for name, _ in tables):
            raise ValueError('unknown evidence table; verification refused')
        for name, schema in tables:
            digest.update(encoded([name, schema]).encode() + b'\n')
            counts[name] = 0
            # Column names are from fixed application tables, never imported SQL.
            columns = [d[0] for d in db.execute(f'SELECT * FROM {name} LIMIT 0').description]
            for row in db.execute(f'SELECT * FROM {name} ORDER BY 1'):
                total += 1
                if total > MAX_ROWS:
                    raise ValueError('evidence exceeds verification row budget')
                body = encoded(list(row)).encode()
                size += len(body)
                if size > MAX_BYTES:
                    raise ValueError('evidence exceeds verification byte budget')
                digest.update(body + b'\n')
                counts[name] += 1
                record = dict(zip(columns, row))
                value = parse(record['body'])
                if name == 'observations':
                    observation = validate(value)
                    if (record['fingerprint'] != fingerprint(observation) or record['body'] != encoded(observation) or
                        any(record[col] != observation[key] for col, key in
                            [('kind','kind'),('identity','id'),('observed_at','observed_at'),('source','source')])):
                        raise ValueError('observation integrity mismatch')
                elif name in ('ble_findings', 'detection_findings'):
                    field = 'evidence_id' if name == 'ble_findings' else 'id'
                    claimed = value.pop(field)
                    if claimed != record[field] or hashlib.sha256(encoded(value).encode()).hexdigest() != claimed:
                        raise ValueError('finding integrity mismatch')
                    mirrored = ('source', 'observed_at', 'confidence') if name == 'ble_findings' else ('rule_id', 'timestamp')
                    if any(record[key] != value[key] for key in mirrored):
                        raise ValueError('finding metadata integrity mismatch')
                    for supporting in value.get('supporting_observations', []):
                        if supporting['observation_id'] != fingerprint(validate(supporting['observation'])):
                            raise ValueError('supporting evidence integrity mismatch')
                elif value.get('id') != record['id'] or value.get('source') != record['source']:
                    raise ValueError('baseline/session integrity mismatch')
                elif name in {'cellular_baselines', 'cellular_sessions'}:
                    body = dict(value); claimed = body.pop('id')
                    if name == 'cellular_sessions': body.pop('created_at')
                    if hashlib.sha256(encoded(body).encode()).hexdigest() != claimed:
                        raise ValueError('cellular derived evidence hash mismatch')
    return dict(format='atlas-evidence-snapshot/v1', sha256=digest.hexdigest(), tables=counts,
                integrity='VERIFIED', authenticity='UNVERIFIED',
                note='Unkeyed hashes cannot authenticate a sender or defeat a writer who replaces evidence and manifest. Retain the manifest independently.')


def verify(path, manifest=None):
    actual = snapshot(path)
    if manifest is not None:
        expected = parse(read_limited(manifest, 65536))
        if (not isinstance(expected, dict) or expected.get('format') != actual['format'] or
            not isinstance(expected.get('sha256'), str) or
            not hmac.compare_digest(expected['sha256'], actual['sha256']) or expected.get('tables') != actual['tables']):
            raise ValueError('evidence snapshot differs from retained manifest')
        actual['manifest_match'] = True
    return actual
