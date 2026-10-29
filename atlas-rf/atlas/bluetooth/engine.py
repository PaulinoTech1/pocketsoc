"""BLE temporal evidence analysis. No address-to-physical-device identification or linking."""
from collections import Counter
import hashlib
import json
import datetime as dt
from pathlib import Path
from atlas.bridge.bundle import MAX_PAYLOAD, MAX_EVENTS, parse, read_bundle, read_limited
from atlas.core.errors import AtlasError
from atlas.core.events import MAX_LINE, encoded, mac, timestamp, validate
from atlas.storage.sqlite import Store

KINDS=('ble','ble_gatt')
MAX_ADDRESSES=4096
MAX_SERVICES=4096
MAX_HISTORY_ROWS=100_000
WINDOW_SECONDS=300


def scan_file(database,path):
    path=Path(path)
    if path.name.endswith('.atlas.json'):
        observations=[o for o in read_bundle(path).observations if o['kind'] in KINDS]
    else:
        observations=[]
        for n,line in enumerate(read_limited(path,MAX_PAYLOAD).splitlines(),1):
            if n>MAX_EVENTS or len(line)+1>MAX_LINE:
                raise AtlasError('BLE input exceeds 10000 lines or 16 KiB per line')
            if not line.strip():
                continue
            try:
                o=validate(parse(line))
            except (ValueError,TypeError,OverflowError) as exc:
                raise AtlasError(f'invalid BLE observation at line {n}') from exc
            if o['kind'] not in KINDS:
                raise AtlasError('BLE JSONL accepts advertisements and ble_gatt evidence only')
            observations.append(o)
    store=Store(database)
    try:
        inserted=store.add(observations)
        store.db.execute('CREATE INDEX IF NOT EXISTS ble_source_history ON observations(source,observed_at,seq)')
        store.db.commit()
    finally:
        store.close()
    return dict(mode='import',observations=len(observations),inserted=inserted,
                kinds=dict(Counter(o['kind'] for o in observations)),
                sources=sorted({o['source'] for o in observations}),radio_scan_performed=False,
                note='Explicit file telemetry, not guest radio access. Addresses are not physical identities.')


def inspect(store,source,address,limit=100):
    if not 1<=limit<=1000:
        raise AtlasError('inspect limit must be 1..1000')
    address=mac(address)
    records=store.db.execute('SELECT body FROM observations WHERE source=? AND identity=? AND kind IN (?,?) ORDER BY observed_at DESC,seq DESC LIMIT ?',
                             (source,address,*KINDS,limit)).fetchall()
    total=store.db.execute('SELECT COUNT(*) FROM observations WHERE source=? AND identity=? AND kind IN (?,?)',
                          (source,address,*KINDS)).fetchone()[0]
    evidence=[dict(observation=json.loads(body),confidence=json.loads(body).get('evidence_confidence','unknown'),
                   physical_identity_confidence='unverified') for (body,) in reversed(records)]
    return dict(source=source,observed_address=address,evidence=evidence,total=total,truncated=total>len(evidence),
                connection_performed=False,physical_identity_confidence='unverified',
                note='History for an address/source, potentially involving multiple devices or rotating addresses. No cross-address linkage is inferred.')


def gatt_capabilities(o):
    return sorted((s['uuid'],tuple(sorted((c['uuid'],c['properties']) for c in s['characteristics']))) for s in o.get('gatt_services',[]))


def analyze(store,source,since,limit=500):
    if not 1<=limit<=5000:
        raise AtlasError('finding limit must be 1..5000')
    since=timestamp(since)
    previous,known_services,emitted={},set(),set()
    findings=[]
    coverage=dict(examined=0,history_rows=0,evaluation_rows=0,truncated=False,
                  partial_advertisements=0,failed_gatt=0,expired_comparisons=0,reference_advertisements=0)
    def add(rule,o,old,detail,confidence='low'):
        key=(rule,o['id'],encoded(detail))
        if key in emitted:
            return
        if len(findings)>=limit:
            coverage['truncated']=True
            return
        body=dict(rule=rule,source=source,observed_address=o['id'],observed_at=o['observed_at'],
                  previous_observed_at=old['observed_at'] if old else None,
                  confidence=confidence,evidence_confidence=o.get('evidence_confidence','unknown'),
                  previous_evidence_confidence=old.get('evidence_confidence','unknown') if old else None,
                  physical_identity_confidence='unverified',
                  association_scope='same-source/address within five minutes' if old else 'source service history',
                  classification='review_hint',confirmed_attack=False,evidence=detail,
                  limitations='Address reuse/rotation, normal telemetry and incomplete advertisements may explain differences. No physical identity established.')
        emitted.add(key)
        body['evidence_id']=hashlib.sha256(encoded(body).encode()).hexdigest()
        findings.append(body)
    query='SELECT body FROM observations WHERE source=? AND kind IN (?,?) ORDER BY observed_at,seq'
    for (body,) in store.db.execute(query,(source,*KINDS)):
        if coverage['examined'] >= MAX_HISTORY_ROWS:
            coverage['truncated']=True
            break
        o=json.loads(body)
        evaluation=o['observed_at']>since
        coverage['examined']+=1
        coverage['evaluation_rows' if evaluation else 'history_rows']+=1
        key=(o['kind'],o['id'])
        if key not in previous and len(previous)>=MAX_ADDRESSES:
            coverage['truncated']=True
            break
        old_entry=previous.get(key)
        old=old_entry[0] if old_entry else None
        gap=None
        if old:
            gap=(dt.datetime.fromisoformat(o['observed_at'])-dt.datetime.fromisoformat(old['observed_at'])).total_seconds()
            if gap<=0:
                continue
            if gap>WINDOW_SECONDS:
                coverage['expired_comparisons']+=1
                old=None
        streak=old_entry[1] if old is not None else 0
        if o['kind']=='ble':
            services=set(o.get('service_uuids',[]))
            if not evaluation and 'service_uuids' in o:
                coverage['reference_advertisements']+=1
            if len(known_services|services)>MAX_SERVICES:
                coverage['truncated']=True
                break
            if evaluation and coverage['reference_advertisements'] and services-known_services:
                add('new-advertising-services',o,None,dict(added_service_uuids=sorted(services-known_services),
                    caveat='New to recorded source history, not proof of a new physical device.'))
            known_services.update(services)
            complete=o.get('advertisement_complete') is True
            if not complete:
                coverage['partial_advertisements']+=1
            changes={}
            if evaluation and old and complete and old.get('advertisement_complete') is True:
                for field in ('name','manufacturer_data','connectable'):
                    if field in o and field in old and o[field]!=old[field]:
                        if field=='manufacturer_data':
                            changes[field]=dict(previous_sha256=hashlib.sha256(encoded(old[field]).encode()).hexdigest(),
                                                current_sha256=hashlib.sha256(encoded(o[field]).encode()).hexdigest(),
                                                caveat='Payload bytes often contain changing counters or sensor values; not an identity or compromise signal.')
                        else:
                            changes[field]=dict(previous=old[field],current=o[field])
                if changes:
                    add('unexpected-advertisement-configuration',o,old,changes,'medium' if streak>=3 else 'low')
            if evaluation and old and complete and old.get('advertisement_complete') is True and 'service_uuids' in old and services-set(old.get('service_uuids',[])):
                add('advertised-capabilities-added',o,old,dict(added_service_uuids=sorted(services-set(old.get('service_uuids',[]))),
                    caveat='Newly advertised presence only; alternating packets may explain it. Missing UUIDs never establish a removed capability.'))
            signature=lambda v: {k:v[k] for k in ('name','manufacturer_data','connectable','service_uuids','advertisement_complete') if k in v}
            stable=old is not None and signature(old)==signature(o)
            previous[key]=(o,streak+1 if stable else 1)
        else:
            if o.get('gatt_status')!='complete':
                coverage['failed_gatt']+=1
                # Failure/partial discovery never removes known capabilities or replaces a good snapshot.
                continue
            if evaluation and old and gatt_capabilities(old)!=gatt_capabilities(o):
                add('known-gatt-capabilities-changed',o,old,dict(previous_services=old['gatt_services'],current_services=o['gatt_services'],
                    authorization_id=o['authorization_id'],operation='discover_services',
                    caveat='Two successful API enumerations differ for this temporal address. Android may cache GATT metadata; no device identity or vulnerability is proven.'),'medium')
            previous[key]=(o,streak+1)
        if coverage['truncated']:
            break
    return dict(source=source,since=since,findings=findings,coverage=coverage,
                insufficient_reference_history=coverage['history_rows']==0,
                note='Rolling chronological evidence comparison, not a device identity model. Findings require review.')


def analyze_and_store(path,source,since,limit=500):
    if not Path(path).exists():
        raise AtlasError('no observation database; import BLE telemetry first')
    store=Store(path)
    try:
        store.db.execute('BEGIN IMMEDIATE')
        result=analyze(store,source,since,limit)
        store.db.execute('CREATE TABLE IF NOT EXISTS ble_findings (evidence_id TEXT PRIMARY KEY, source TEXT NOT NULL, observed_at TEXT NOT NULL, confidence TEXT NOT NULL, body TEXT NOT NULL)')
        count=0
        for f in result['findings']:
            count+=store.db.execute('INSERT OR IGNORE INTO ble_findings VALUES(?,?,?,?,?)',
                (f['evidence_id'],f['source'],f['observed_at'],f['confidence'],encoded(f))).rowcount
        store.db.commit()
        result['evidence_saved']=count
        return result
    except BaseException:
        store.db.rollback()
        raise
    finally:
        store.close()
