"""Explicit, immutable source-scoped baselines and explainable post-baseline review hints."""
from collections import Counter
import json
import re
import uuid
from atlas.core.errors import AtlasError
from atlas.core.events import now, timestamp
from atlas.detection.rules import security_level
from .schema import band, eligibility

MAX_BSSIDS = 4096
MAX_VARIANTS = 32


def security_signature(value):
    return ' '.join(sorted(set(re.split(r'[\s,/]+', value.upper().strip()))))


def radio(o):
    if 'frequency_mhz' in o and 'channel' in o and band(o['frequency_mhz']) != 'unknown':
        return (o['frequency_mhz'], o['channel'])
    return None


def rows(db, source, condition='', arguments=()):
    query = 'SELECT seq,body FROM observations WHERE kind=? AND source=? ' + condition + ' ORDER BY observed_at,seq'
    for seq, body in db.execute(query, ('wifi', source, *arguments)):
        yield seq, json.loads(body)


def build_baseline(store, source, through=None):
    if not source or len(source) > 256:
        raise AtlasError('a nonempty source label up to 256 characters is required')
    db = store.db
    # One transaction freezes the input snapshot and its saved aggregate together.
    db.execute('BEGIN IMMEDIATE')
    try:
        db.execute('CREATE INDEX IF NOT EXISTS wifi_source_history ON observations(kind,source,observed_at,seq)')
        maximum = db.execute('SELECT MAX(observed_at),COALESCE(MAX(seq),0) FROM observations WHERE kind=? AND source=?',
                             ('wifi', source)).fetchone()
        through = timestamp(through) if through else maximum[0]
        if through is None:
            raise AtlasError('no Wi-Fi observations for this source')
        profiles, skipped, last = {}, Counter(), {}
        count, first = 0, None
        for _, o in rows(db, source, 'AND observed_at<=?', (through,)):
            state = eligibility(o)
            if state != 'fresh':
                skipped[state] += 1
                continue
            if last.get(o['id']) == o['observed_at']:
                skipped['duplicate_measurement'] += 1
                continue
            last[o['id']] = o['observed_at']
            if o['id'] not in profiles:
                if len(profiles) >= MAX_BSSIDS:
                    raise AtlasError('baseline exceeds 4096 BSSIDs; use a narrower source or training period')
                profiles[o['id']] = dict(bssid=o['id'], ssids=set(), securities=set(), radios=set(),
                                          samples=0, channel_samples=0, security_unknown_seen=False, first_seen=o['observed_at'],
                                          last_seen=o['observed_at'], rssi_min=None, rssi_max=None)
            p = profiles[o['id']]
            if o.get('name'):
                p['ssids'].add(o['name'])
            if security_level(o['security']) is not None:
                p['securities'].add(security_signature(o['security']))
            else:
                p['security_unknown_seen'] = True
            value = radio(o)
            if value:
                p['radios'].add(value)
                p['channel_samples'] += 1
            if any(len(p[k]) > MAX_VARIANTS for k in ('ssids', 'securities', 'radios')):
                raise AtlasError('baseline exceeds 32 variants per BSSID; review source history')
            p['samples'] += 1
            p['last_seen'] = o['observed_at']
            if 'rssi' in o:
                p['rssi_min'] = min(p['rssi_min'], o['rssi']) if p['rssi_min'] is not None else o['rssi']
                p['rssi_max'] = max(p['rssi_max'], o['rssi']) if p['rssi_max'] is not None else o['rssi']
            count += 1
            first = first or o['observed_at']
        if not count:
            raise AtlasError('no eligible fresh Wi-Fi observations; stale/cached/unknown data cannot train a baseline')
        for p in profiles.values():
            for key in ('ssids', 'securities'):
                p[key] = sorted(p[key])
            p['radios'] = [list(value) for value in sorted(p['radios'])]
        baseline = dict(id=str(uuid.uuid4()), version=1, source=source, created_at=now(),
                        through_at=through, snapshot_seq=maximum[1], first_observed_at=first,
                        samples=count, skipped=dict(skipped), profiles=profiles,
                        note='Observed history, not an approval list. Training data must be reviewed by the operator.')
        body = json.dumps(baseline, ensure_ascii=True, separators=(',', ':'))
        if len(body.encode()) > 8 * 1024 * 1024:
            raise AtlasError('baseline snapshot exceeds 8 MiB')
        db.execute('CREATE TABLE IF NOT EXISTS wifi_baselines (id TEXT PRIMARY KEY, source TEXT NOT NULL, created_at TEXT NOT NULL, body TEXT NOT NULL)')
        db.execute('CREATE INDEX IF NOT EXISTS wifi_baseline_source ON wifi_baselines(source,created_at)')
        db.execute('INSERT INTO wifi_baselines VALUES(?,?,?,?)', (baseline['id'], source, baseline['created_at'], body))
        db.commit()
        return baseline
    except BaseException:
        db.rollback()
        raise


def load_baseline(store, source, baseline_id=None):
    db = store.db
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='wifi_baselines'").fetchone():
        raise AtlasError('no saved Wi-Fi baseline; run atlas wifi baseline first')
    if baseline_id:
        record = db.execute('SELECT body FROM wifi_baselines WHERE source=? AND id=?', (source, baseline_id)).fetchone()
    else:
        record = db.execute('SELECT body FROM wifi_baselines WHERE source=? ORDER BY created_at DESC,rowid DESC LIMIT 1', (source,)).fetchone()
    if record is None:
        raise AtlasError('no saved baseline for this source/id')
    return json.loads(record[0])


def detect(store, source, baseline_id=None, limit=500):
    if type(limit) is not int or not 1 <= limit <= 5000:
        raise AtlasError('finding limit must be 1..5000')
    b = load_baseline(store, source, baseline_id)
    profiles, ssids = b['profiles'], {}
    for identity, p in profiles.items():
        for name in p['ssids']:
            entry = ssids.setdefault(name, dict(bssids=set(), securities=set(), unknown_security=False))
            entry['bssids'].add(identity)
            entry['securities'].update(p['securities'])
            entry['unknown_security'] |= p['security_unknown_seen']
    db = store.db
    total = db.execute('SELECT COUNT(*) FROM observations WHERE kind=? AND source=? AND observed_at>?',
                       ('wifi', source, b['through_at'])).fetchone()[0]
    late = db.execute('SELECT COUNT(*) FROM observations WHERE kind=? AND source=? AND seq>? AND observed_at<=?',
                      ('wifi', source, b['snapshot_seq'], b['through_at'])).fetchone()[0]
    findings, emitted, last, skipped = [], set(), {}, Counter()
    examined, truncated = 0, False
    def add(rule, o, detail, severity='info'):
        nonlocal truncated
        key = (rule, o['id'], o.get('name'), security_signature(o['security']), radio(o))
        if key in emitted:
            return
        if len(findings) >= limit:
            truncated = True
            return
        emitted.add(key)
        findings.append(dict(rule=rule, severity=severity, bssid=o['id'], ssid=o.get('name'),
                             source=source, observed_at=o['observed_at'], scan_freshness=o['scan_freshness'],
                             frequency_mhz=o.get('frequency_mhz'), channel=o.get('channel'),
                             band=band(o.get('frequency_mhz')), rssi=o.get('rssi'),
                             advertised_security=o['security'], evidence=detail,
                             classification='review_hint', confirmed_attack=False))
    for _, o in rows(db, source, 'AND observed_at>?', (b['through_at'],)):
        examined += 1
        state = eligibility(o)
        if state != 'fresh':
            skipped[state] += 1
            continue
        # Maps and output remain bounded, including a stream of previously unknown identities.
        if o['id'] not in last and len(last) >= MAX_BSSIDS:
            truncated = True
            break
        if last.get(o['id']) == o['observed_at']:
            skipped['duplicate_measurement'] += 1
            continue
        last[o['id']] = o['observed_at']
        known, name = profiles.get(o['id']), o.get('name')
        signature, level = security_signature(o['security']), security_level(o['security'])
        if known is None:
            add('unknown-bssid', o, 'BSSID absent from frozen source baseline; new infrastructure or changing identifiers are possible.')
        if name and name not in ssids:
            add('unseen-ssid', o, 'Nonempty SSID absent from frozen source baseline; novelty is not evidence of an attack.')
        if known and known['securities'] and level is not None and signature not in known['securities']:
            add('unexpected-security-change', o, dict(baseline_security=known['securities'], current=o['security'],
                caveat='Advertised configuration changed; upgrades, reconfiguration and parser differences are possible.'),
                'medium' if level < min(security_level(v) for v in known['securities']) else 'info')
        value = radio(o)
        if known and value and known['channel_samples'] >= 3 and list(value) not in known['radios']:
            add('unusual-channel-change', o, dict(baseline_radios=known['radios'], current=list(value),
                caveat='A new frequency/channel after at least three channel samples. DFS, automatic channel selection and maintenance are legitimate explanations.'))
        duplicated = ssids.get(name) if name else None
        if duplicated and not duplicated['unknown_security'] and o['id'] not in duplicated['bssids'] and duplicated['securities'] and level is not None:
            prior_levels = [security_level(v) for v in duplicated['securities']]
            if min(prior_levels) >= 3 and level <= 1:
                add('suspicious-ssid-duplication', o, dict(known_bssids=sorted(duplicated['bssids'])[:8],
                    baseline_security=sorted(duplicated['securities'])[:8], current=o['security'],
                    caveat='Unfamiliar SSID/BSSID association plus weaker advertised security warrants review. Duplicate SSIDs alone are normal in roaming/mesh networks; this is not proof of an evil twin.'), 'medium')
        if truncated:
            break
    return dict(baseline_id=b['id'], source=source, through_at=b['through_at'], findings=findings,
                coverage=dict(post_baseline_rows=total, examined=examined, skipped=dict(skipped),
                              late_pre_baseline_rows=late, truncated=truncated, finding_limit=limit),
                limitations=['Source labels and advertised security are unauthenticated.',
                             'Only explicitly fresh results are assessed; supplied capture ages over 30 seconds are excluded. Missing ages are not synthesized.',
                             'Frozen baseline is not automatically updated; review training before replacing it.',
                             'SSID duplication alone is not an attack; no finding here confirms an attack.',
                             'Late pre-baseline observations are retained but excluded from post-baseline assessment.'])
