"""Reuse canonical validation, transactional history and finalized export transport."""
import json
from collections import Counter
from pathlib import Path
from atlas.bridge.bundle import read_bundle, read_limited, parse, MAX_PAYLOAD, MAX_EVENTS
from atlas.core.events import validate, MAX_LINE
from atlas.storage.sqlite import Store
from atlas.storage.reader import reader


def ingest(database, path, key_path=None, nonce=None, synthetic=False):
    path = Path(path)
    bundle = None
    if path.name.endswith('.atlas.json'):
        bundle = read_bundle(path, key_path, nonce)
        if not bundle.metadata['synthetic'] and not bundle.authenticated:
            raise ValueError('all real cellular sessions require authenticated transport, including zero-row exports')
        if bundle.metadata['synthetic'] != synthetic:
            raise ValueError('synthetic bundle requires --synthetic; real bundle must omit it')
        rows = [o for o in bundle.observations if o['kind'] == 'cellular']
    else:
        if not synthetic:
            raise ValueError("raw cellular JSONL requires --synthetic; real telemetry requires authenticated .atlas.json")
        rows = []
        for number, line in enumerate(read_limited(path, MAX_PAYLOAD).splitlines(), 1):
            if number > MAX_EVENTS or len(line) + 1 > MAX_LINE:
                raise ValueError('cellular input exceeds transport limits')
            if line.strip():
                row = validate(parse(line))
                if row['kind'] != 'cellular':
                    raise ValueError('standalone cellular input must contain only cellular records')
                if not row['source'].startswith('synthetic:'):
                    raise ValueError('synthetic JSONL requires explicit synthetic: sources')
                rows.append(row)
    store = Store(database)
    try:
        if bundle is not None:
            from dataclasses import replace
            inserted = store.add_radio_bundle(replace(bundle, observations=rows))
        else:
            inserted = store.add(rows)
    finally:
        store.close()
    return dict(observations=len(rows), inserted=inserted, replayed=len(rows)-inserted,
                collection_performed=False, freshness=dict(Counter(o['cell_freshness'] for o in rows)))


from .analysis import analyze


def inspect(database, source, limit=2000, use_baseline=False):
    if type(limit) is not int or not 1 <= limit <= 5000:
        raise ValueError('cellular limit must be 1..5000')
    with reader(database) as store:
        total = store.db.execute("SELECT COUNT(*) FROM observations WHERE kind='cellular' AND source=?", (source,)).fetchone()[0]
        values = store.db.execute("SELECT body FROM observations WHERE kind='cellular' AND source=? ORDER BY observed_at DESC,seq DESC LIMIT ?", (source, limit))
        rows = [json.loads(r[0]) for r in values]
        tables = {r[0] for r in store.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        sessions = []
        if 'cellular_sessions' in tables:
            sessions = [json.loads(r[0]) for r in store.db.execute("SELECT body FROM cellular_sessions WHERE source=? ORDER BY created_at DESC LIMIT 10", (source,))]
        from .baseline import load
        baseline = load(store, source) if use_baseline else None
    return dict(analyze(rows, baseline), records=rows, recent_sessions=sessions, coverage=dict(total=total, analyzed=len(rows), truncated=total>len(rows), limit=limit))
