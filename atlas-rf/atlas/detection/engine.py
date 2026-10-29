"""Deterministic policy predicates and transactional anomaly evidence; no incident verdicts."""
from collections import Counter, deque
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from atlas.core.errors import AtlasError
from atlas.core.events import encoded, now, timestamp
from atlas.storage.reader import reader
from atlas.storage.sqlite import Store
from atlas.wifi.schema import eligibility
from .policy import load_policy

MAX_ROWS=50_000
MAX_GROUPS=4096
MAX_FINDINGS=500
MAX_EVIDENCE_BYTES=8*1024*1024
LIMITATIONS = [
    'Policy mismatch is an anomaly, not a confirmed security incident.',
    'Source labels and supplied telemetry are not authenticated.',
    'Radio addresses do not establish physical identity; rotation/reuse can explain changes.',
    'TCP acceptance establishes observed reachability, not protocol identity or Internet exposure.',
]


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def security_rank(value):
    # Rank advertised modes conservatively; mixed modes use their weakest advertised mode.
    value=value.upper()
    if value in ('OPEN','NONE','--'):
        return 0
    ranks=[]
    for token,rank in [('WEP',1),('WPA',2),('WPA2',3),('RSN',3),('OWE',3),('WPA3',4),('SAE',4)]:
        if re.search(r'(?<![A-Z0-9])'+token+r'(?![A-Z0-9])',value):
            ranks.append(rank)
    return min(ranks) if ranks else None


def predicate(rule,o):
    """Return factual policy mismatch details only; no inference from absent measurements."""
    kind=rule['type']
    if kind in ('ap-security-downgrade','unrecognized-bssid'):
        if o['kind']!='wifi' or o.get('name')!=rule['ssid'] or eligibility(o)!='fresh':
            return None
        if kind=='unrecognized-bssid':
            if o['id'] in rule['approved_bssids']:
                return None
            return dict(ssid=rule['ssid'],observed_bssid=o['id'],approved_bssids=rule['approved_bssids'])
        actual=security_rank(o['security'])
        if actual is None or actual>=security_rank(rule['expected_security']):
            return None
        return dict(ssid=rule['ssid'],expected_security=rule['expected_security'],observed_security=o['security'],
                    interpretation='Weaker advertised security than the configured expectation; negotiation is unverified.')
    if kind=='ble-service-change':
        if o['id']!=rule['address']:
            return None
        expected=set(rule['expected_services'])
        if rule['evidence_kind']=='advertisement':
            if o['kind']!='ble' or o.get('advertisement_complete') is not True or 'service_uuids' not in o:
                return None
            actual=set(o['service_uuids'])
            added=actual-expected
            removed=set()  # Missing advertisement UUIDs never prove capability removal.
        else:
            if o['kind']!='ble_gatt' or o.get('gatt_status')!='complete':
                return None
            actual={service['uuid'] for service in o['gatt_services']}
            added,removed=actual-expected,expected-actual
        if not added and not removed:
            return None
        return dict(added_services=sorted(added),missing_services=sorted(removed),evidence_kind=rule['evidence_kind'],
                    interpretation='Same temporal address only; GATT may be cached and advertisement omissions do not prove removal.')
    if o['kind']!='service':
        return None
    permitted=any(ipaddress.ip_address(o['ip']) in ipaddress.ip_network(network) for network in rule['allowed_networks'])
    if kind=='unknown-management-interface':
        if o['port'] not in rule['ports'] or permitted:
            return None
        return dict(ip=o['ip'],port=o['port'],management_protocol='unverified',
                    interpretation='Successful TCP connection on a configured management port outside approved networks.')
    if permitted and o['port'] in rule['allowed_ports']:
        return None
    return dict(ip=o['ip'],port=o['port'],network_allowed=permitted,port_allowed=o['port'] in rule['allowed_ports'],
                interpretation='Observed TCP acceptance outside policy; external/Internet reachability is unverified.')


def evaluate(db,policy,at):
    """Stream bounded history; thresholds count distinct measurement times per mismatch/asset."""
    findings=[]
    coverage=Counter(examined=0,stale=0,threshold_pending=0)
    evidence_bytes=0
    clock=dt.datetime.fromisoformat(at)
    for rule in policy['rules']:
        if not rule['enabled']:
            continue
        cutoff=(clock-dt.timedelta(seconds=rule['max_age_seconds'])).isoformat(timespec='microseconds')
        groups={}
        count=0
        query='SELECT seq,fingerprint,body FROM observations WHERE observed_at>=? AND observed_at<=? ORDER BY observed_at,fingerprint,seq'
        for seq,fingerprint,body in db.execute(query,(cutoff,at)):
            count+=1
            if count>MAX_ROWS:
                raise AtlasError('detection history exceeds 50000 rows per rule; narrow max_age_seconds or source history')
            o=json.loads(body)
            if o['source'] not in rule['sources']:
                continue
            coverage['examined']+=1
            if o['kind']=='wifi' and eligibility(o)!='fresh':
                coverage['stale']+=1
            detail=predicate(rule,o)
            if detail is None:
                continue
            key=digest(dict(rule=rule,source=o['source'],asset=o['id'],mismatch=detail))
            if key not in groups:
                if len(groups)>=MAX_GROUPS:
                    raise AtlasError('detection exceeds 4096 asset/mismatch groups per rule')
                groups[key]=dict(queue=deque(),last_time=None,last_emit=None)
            state=groups[key]
            # Different values from one measurement time cannot inflate a threshold.
            if state['last_time']==o['observed_at']:
                continue
            state['last_time']=o['observed_at']
            measured=dt.datetime.fromisoformat(o['observed_at'])
            queue=state['queue']
            queue.append((seq,measured,fingerprint))
            while queue and (measured-queue[0][1]).total_seconds()>rule['window_seconds']:
                queue.popleft()
            while len(queue)>rule['min_observations']:
                queue.popleft()
            if len(queue)<rule['min_observations']:
                continue
            if state['last_emit'] is not None and (measured-state['last_emit']).total_seconds()<rule['cooldown_seconds']:
                continue
            state['last_emit']=measured
            supporting=[]
            for row_id,_,fp in queue:
                raw=db.execute('SELECT body FROM observations WHERE seq=?',(row_id,)).fetchone()[0]
                evidence_bytes+=len(raw.encode())
                if evidence_bytes>MAX_EVIDENCE_BYTES:
                    raise AtlasError('detection supporting evidence exceeds 8 MiB; narrow policy or time bounds')
                supporting.append(dict(observation_id=fp,observation=json.loads(raw)))
            finding=dict(rule_id=rule['id'],rule_type=rule['type'],timestamp=o['observed_at'],
                         severity=rule['severity'],confidence=rule['confidence'],classification='anomaly',
                         confirmed_incident=False,affected_assets=[dict(source=o['source'],kind=o['kind'],
                             observed_id=o['id'],physical_identity_confidence='unverified' if o['kind'] in ('wifi','ble','ble_gatt') else 'not_applicable')],
                         supporting_observations=supporting,recommended_investigation=rule['investigation'],
                         explanation=detail,rule_snapshot=rule,policy_sha256=policy['sha256'],
                         threshold=dict(required=rule['min_observations'],observed=len(queue),window_seconds=rule['window_seconds']),
                         limitations=LIMITATIONS,suppression_key=key)
            finding['id']=digest(finding)
            findings.append(finding)
            if len(findings)>MAX_FINDINGS:
                raise AtlasError('detection exceeds 500 findings; narrow policy or age window')
        coverage['threshold_pending']+=sum(bool(s['queue']) and len(s['queue'])<rule['min_observations'] for s in groups.values())
    return sorted(findings,key=lambda f:(f['timestamp'],f['rule_id'],f['id'])),dict(coverage)


def run(path,rules,at=None):
    policy=load_policy(rules)
    at=timestamp(at or now())
    if not Path(path).exists():
        raise AtlasError('no observation database; import telemetry before detection')
    store=Store(path)
    try:
        store.db.execute('BEGIN IMMEDIATE')
        findings,coverage=evaluate(store.db,policy,at)
        store.db.execute('CREATE TABLE IF NOT EXISTS detection_findings (id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, timestamp TEXT NOT NULL, suppression_key TEXT NOT NULL, body TEXT NOT NULL)')
        store.db.execute('CREATE INDEX IF NOT EXISTS detection_suppression ON detection_findings(suppression_key,timestamp)')
        saved=[]
        suppressed=0
        for f in findings:
            if store.db.execute('SELECT 1 FROM detection_findings WHERE id=?',(f['id'],)).fetchone():
                suppressed+=1
                continue
            last=store.db.execute('SELECT MAX(timestamp) FROM detection_findings WHERE suppression_key=?',(f['suppression_key'],)).fetchone()[0]
            if last is not None and (dt.datetime.fromisoformat(f['timestamp'])-dt.datetime.fromisoformat(last)).total_seconds()<f['rule_snapshot']['cooldown_seconds']:
                suppressed+=1
                continue
            store.db.execute('INSERT INTO detection_findings VALUES(?,?,?,?,?)',(f['id'],f['rule_id'],f['timestamp'],f['suppression_key'],encoded(f)))
            saved.append(f)
        store.db.commit()
        return dict(evaluated_at=at,policy_sha256=policy['sha256'],findings=saved,saved=len(saved),
                    suppressed=suppressed,coverage=coverage,classification='anomalies_only',confirmed_incidents=0)
    except BaseException:
        store.db.rollback()
        raise
    finally:
        store.close()


def history(path,limit=100,rule_id=None):
    if type(limit) is not int or not 1<=limit<=500:
        raise AtlasError('history limit must be 1..500')
    with reader(path) as store:
        if not store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='detection_findings'").fetchone():
            return dict(findings=[],total=0,truncated=False)
        where,args=(' WHERE rule_id=?',[rule_id]) if rule_id else ('',[])
        total=store.db.execute('SELECT COUNT(*) FROM detection_findings'+where,args).fetchone()[0]
        rows=store.db.execute('SELECT id,rule_id,timestamp,body FROM detection_findings'+where+' ORDER BY timestamp DESC,id LIMIT ?',[*args,limit])
        # History is a compact index; explain retrieves complete retained evidence.
        findings=[]
        for identity,rule,time,body in rows:
            f=json.loads(body)
            findings.append(dict(id=identity,rule_id=rule,timestamp=time,severity=f['severity'],confidence=f['confidence'],
                                 classification=f['classification'],affected_assets=f['affected_assets']))
        return dict(findings=findings,total=total,truncated=total>len(findings))


def explain(path,finding_id):
    if not re.fullmatch('[a-f0-9]{64}',finding_id):
        raise AtlasError('finding must be its complete 64-character ID from detect run/history')
    with reader(path) as store:
        if store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='detection_findings'").fetchone():
            result=store.db.execute('SELECT body FROM detection_findings WHERE id=?',(finding_id,)).fetchone()
            if result:
                return json.loads(result[0])
    raise AtlasError('detection finding not found')
