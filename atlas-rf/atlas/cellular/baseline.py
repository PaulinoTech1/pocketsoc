"""Explicit frozen reviewed cellular history. No automatic trust learning."""
import hashlib
import json
import statistics
from collections import defaultdict
from atlas.core.events import encoded, now, timestamp
from .analysis import serving, identity, METRICS


def build(store, source, through):
    through = timestamp(through)
    count = store.db.execute("SELECT COUNT(*) FROM observations WHERE kind='cellular' AND source=? AND observed_at<=?", (source, through)).fetchone()[0]
    if count > 50000:
        raise ValueError('cellular baseline exceeds 50000-row bound; narrow training cutoff/source')
    rows = [json.loads(r[0]) for r in store.db.execute("SELECT body FROM observations WHERE kind='cellular' AND source=? AND observed_at<=? ORDER BY observed_at,seq", (source, through))]
    groups = defaultdict(list)
    seen = set()
    for o in rows:
        if not serving(o) or identity(o) is None:
            continue
        key = (o['collection_session'], o['subscription_id'], o.get('connection_status'), identity(o), o.get('measurement_elapsed_ms'))
        if key not in seen:
            groups[o['subscription_id']].append(o)
            seen.add(key)
    if not groups:
        raise ValueError('baseline needs recent serving measurements with complete MCC/MNC/cell identity')
    profiles = []
    for sub, samples in sorted(groups.items()):
        signals = {}
        for rat in ('LTE', 'NR'):
            for metric in METRICS:
                values = [o[metric] for o in samples if o['technology'] == rat and metric in o]
                if values:
                    signals[metric] = dict(samples=len(values), median=statistics.median(values), minimum=min(values), maximum=max(values))
        profiles.append(dict(subscription_id=sub, samples=len(samples),
                             cells=[list(c) for c in sorted({identity(o) for o in samples})], signals=signals))
    value = dict(source=source, through_at=through, created_at=now(), profiles=profiles,
                 samples=sum(p['samples'] for p in profiles),
                 caveat='Reviewed observation history, not a trusted tower allowlist. Subscription IDs may change after SIM reconfiguration.')
    value['id'] = hashlib.sha256(encoded(value).encode()).hexdigest()
    store.db.execute('CREATE TABLE IF NOT EXISTS cellular_baselines (id TEXT PRIMARY KEY, source TEXT NOT NULL, created_at TEXT NOT NULL, body TEXT NOT NULL)')
    with store.db:
        store.db.execute('INSERT INTO cellular_baselines VALUES(?,?,?,?)', (value['id'], source, value['created_at'], encoded(value)))
    return value


def load(store, source):
    tables = {r[0] for r in store.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    row = store.db.execute('SELECT body FROM cellular_baselines WHERE source=? ORDER BY created_at DESC,rowid DESC LIMIT 1', (source,)).fetchone() if 'cellular_baselines' in tables else None
    if row is None:
        raise ValueError('no reviewed cellular baseline for source')
    return json.loads(row[0])
