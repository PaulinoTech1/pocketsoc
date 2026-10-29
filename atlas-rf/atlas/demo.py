"""Controlled end-to-end workflow; never accesses radios or opens network sockets."""
from collections import Counter
import copy
import datetime as dt
from importlib.resources import files
import json
from pathlib import Path
import resource
import statistics
import tempfile
import time

from atlas.bluetooth.engine import scan_file as ble_scan, analyze_and_store
from atlas.core.events import encoded, validate
from atlas.detection.engine import run as detect, evaluate
from atlas.detection.policy import load_policy
from atlas.network.analysis import assess
from atlas.reporting.reports import report, markdown
from atlas.security.evidence import verify
from atlas.storage.ingest import ingest_file
from atlas.storage.reader import reader
from atlas.storage.sqlite import Store
from atlas.topology.graph import topology
from atlas.ui.console import write_report
from atlas.ui.dashboard import snapshot
from atlas.wifi.ingest import scan_file as wifi_scan
from atlas.wifi.intelligence import build_baseline, detect as wifi_detect


def scenario():
    value=json.loads(files('atlas').joinpath('fixtures/prototype.json').read_text())
    if value.get('synthetic') is not True:
        raise ValueError('demo requires explicitly synthetic fixture data')
    return value


def write_jsonl(path,rows):
    # Shared exclusive/private output path, schema checked before writing.
    text=''.join(encoded(validate(row))+'\n' for row in rows)
    write_report(path,text,'markdown')


def score_cases(root,fixture):
    """Each unit is one independently labelled case/rule decision, not one RF packet."""
    results=[]
    matrix=dict(true_positive=0,false_positive=0,true_negative=0,false_negative=0)
    for case in fixture['accuracy_cases']:
        with tempfile.TemporaryDirectory(prefix='atlas-score-') as temporary:
            directory=Path(temporary)
            policy=copy.deepcopy(fixture['policy'])
            policy['rules']=[r for r in policy['rules'] if r['id']==case['rule_id']]
            policy_file=directory/'policy.yaml'
            write_report(policy_file,policy,'json') # JSON is a strict YAML subset.
            db=directory/'case.sqlite3'
            store=Store(db)
            try: store.add(case['observations'])
            finally: store.close()
            with reader(db) as store:
                findings,coverage=evaluate(store.db,load_policy(policy_file),fixture['clock'])
            predicted=bool(findings)
            expected=case['expected_alert']
            key=('true_positive' if expected else 'false_positive') if predicted else ('false_negative' if expected else 'true_negative')
            matrix[key]+=1
            results.append(dict(case_id=case['case_id'],rule_id=case['rule_id'],expected_alert=expected,
                                predicted_alert=predicted,findings=len(findings),correct=expected==predicted))
    tp,fp,tn,fn=(matrix[k] for k in ('true_positive','false_positive','true_negative','false_negative'))
    return dict(scope='20 hand-labelled synthetic policy decisions; not field accuracy or incident confirmation',
                unit='case/rule alert decision',matrix=matrix,accuracy=(tp+tn)/len(results),
                precision=tp/(tp+fp) if tp+fp else None,recall=tp/(tp+fn) if tp+fn else None,
                false_positive_rate=fp/(fp+tn) if fp+tn else None,cases=results)


def percentile(values,percent):
    ordered=sorted(values)
    return ordered[max(0,min(len(ordered)-1,int((len(ordered)-1)*percent/100+.5)))]


def benchmark(root,fixture,events):
    db=root/'resource-benchmark.sqlite3'
    policy=load_policy(root/'policy.yaml')
    template=next(r for r in fixture['policy_observations'] if r['kind']=='wifi' and r['security']=='WPA3')
    store=Store(db)
    start=time.perf_counter(); cpu=time.process_time()
    latencies=[]; event_latencies=[]; ingest_times=[]; submitted=processed=0
    # Fast-forward one simulated second/event; assessment uses the configured rolling age window.
    # Last 100 events are individually timed after the bulk warm-up, with the same detector.
    try:
        offset=0
        while offset<events:
            batch_start=time.perf_counter()
            count=min(100,events-100-offset) if offset<events-100 else 1
            batch=[]
            for index in range(offset,offset+count):
                when=dt.datetime(2026,4,17,10,0,tzinfo=dt.timezone.utc)+dt.timedelta(seconds=index)
                batch.append(dict(template,observed_at=when.isoformat(timespec='microseconds')))
            submitted+=len(batch)
            ingestion=time.perf_counter()
            processed+=store.add(batch)
            ingest_times.append((time.perf_counter()-ingestion)*1000/len(batch))
            evaluate(store.db,policy,batch[-1]['observed_at'])
            elapsed=(time.perf_counter()-batch_start)*1000
            (event_latencies if count==1 else latencies).append(elapsed)
            offset+=count
        stored=sum(store.stats().values())
    finally: store.close()
    wall=time.perf_counter()-start; cpu=time.process_time()-cpu
    peak=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
    def distribution(values):
        return dict(samples=len(values),p50=percentile(values,50),p95=percentile(values,95),
                    p99=percentile(values,99),maximum=max(values)) if values else None
    return dict(synthetic=True,events_submitted=submitted,events_processed=processed,events_stored=stored,
                event_loss=submitted-stored,event_loss_rate=(submitted-stored)/submitted,
                wall_seconds=wall,cpu_seconds=cpu,cpu_utilization_percent_one_core=100*cpu/wall,
                peak_rss_bytes_process_lifetime=peak,throughput_events_per_second=events/wall,
                batch_size=100,batches=len(latencies),batch_completion_latency_ms=distribution(latencies),
                event_processing_latency_ms=distribution(event_latencies),
                amortized_ingestion_ms_per_event=dict(median=statistics.median(ingest_times),maximum=max(ingest_times)),
                budgets=dict(peak_rss_bytes=150*1024*1024,event_p95_ms=1000,event_loss=0),
                budget_pass=peak<150*1024*1024 and percentile(event_latencies,95)<1000 and submitted==stored,
                limitations=['Peak RSS is lifetime getrusage for this demo process, not a per-phase allocation delta.',
                             'CPU 100% means one busy logical core; no sustained phone battery or RF benchmark.',
                             'Bulk batches and final 100 individual events include generation, validation, commit and rolling-window detection.',
                             'The simulated clock advances one second/event; throughput is execution speed, not a claimed RF arrival rate.',
                             'Event loss measures synthetic submitted/stored records only; no Android queue or over-air loss measured.'])


def demonstrate(output,events=10000):
    if type(events) is not int or not 100<=events<=50000:
        raise ValueError('demo benchmark events must be 100..50000')
    root=Path(output).expanduser().absolute()
    # New directory only: demo cannot overwrite user observations, evidence or prior results.
    root.mkdir(mode=0o700,parents=True)
    fixture=scenario()
    db=root/'demo.sqlite3'
    write_report(root/'policy.yaml',fixture['policy'],'json')
    steps=[]
    for name in ('wifi_training','wifi_evaluation','ble_training','ble_evaluation','policy_observations','network_observations'):
        write_jsonl(root/(name+'.jsonl'),fixture[name])
    steps.append(dict(stage='wifi_training_ingestion',result=wifi_scan(db,root/'wifi_training.jsonl')))
    store=Store(db)
    try: baseline=build_baseline(store,fixture['wifi_source'])
    finally: store.close()
    write_report(root/'baseline.json',baseline,'json')
    steps.append(dict(stage='historical_baseline',samples=baseline['samples'],profiles=len(baseline['profiles'])))
    steps.append(dict(stage='wifi_discovery_ingestion',result=wifi_scan(db,root/'wifi_evaluation.jsonl')))
    for name in ('ble_training','ble_evaluation'):
        steps.append(dict(stage=name+'_ingestion',result=ble_scan(db,root/(name+'.jsonl'))))
    for name in ('policy_observations','network_observations'):
        steps.append(dict(stage=name+'_ingestion',result=ingest_file(db,root/(name+'.jsonl'))))
    replay=ingest_file(db,root/'policy_observations.jsonl')
    with reader(db) as store:
        wifi=wifi_detect(store,fixture['wifi_source'])
    ble=analyze_and_store(db,fixture['ble_source'],fixture['ble_since'])
    policy=detect(db,root/'policy.yaml',fixture['clock'])
    observed_wifi=dict(Counter(f['rule'] for f in wifi['findings']))
    if observed_wifi!=fixture['expected_wifi_rules'] or sorted(f['rule'] for f in ble['findings'])!=sorted(fixture['expected_ble_rules']) or sorted(f['rule_id'] for f in policy['findings'])!=sorted(fixture['expected_policy_rules']):
        raise ValueError('controlled scenario differs from reviewed expectations')
    ip=assess(db,'synthetic:detection:network',['192.0.2.0/24'])
    with reader(db) as store:
        graph=topology(store.observations(2000))
        assessment=report(store,2000)
        total=sum(store.stats().values())
    frame=snapshot(db)
    write_report(root/'dashboard.txt','\n'.join(frame['lines'])+'\n','markdown')
    write_report(root/'report.md',markdown(assessment),'markdown')
    evidence=dict(synthetic=True,wifi=wifi,ble=ble,policy=policy,ip_analysis=ip,topology=graph,assessment=assessment)
    write_report(root/'evidence.json',evidence,'json')
    manifest=verify(db)
    write_report(root/'evidence-manifest.json',manifest,'json')
    verify(db,root/'evidence-manifest.json')
    accuracy=score_cases(root,fixture)
    resources=benchmark(root,fixture,events)
    expected=sum(len(fixture[name]) for name in ('wifi_training','wifi_evaluation','ble_training','ble_evaluation','policy_observations','network_observations'))
    result=dict(format='atlas-demo-result/v1',synthetic=True,hardware_measurements=False,output=str(root),
                stages=steps,fixture_event_accounting=dict(submitted=expected,stored=total,loss=expected-total,
                    replay_submitted=replay['observations'],replay_inserted=replay['inserted']),
                findings=dict(wifi=len(wifi['findings']),ble=len(ble['findings']),policy=len(policy['findings'])),
                topology=dict(nodes=len(graph['nodes']),edges=len(graph['edges']),
                    protocols=sorted({node['kind'] for node in graph['nodes']})),
                ip_analysis=dict(mode=ip['mode'],observations=len(ip['observations']),connections_performed=0),
                evidence_integrity=manifest['integrity'],dashboard='plain frame generated; run atlas --db OUTPUT/demo.sqlite3 dashboard for curses',
                detection_accuracy=accuracy,resources=resources,
                limitations=['All discovery and IP observations are invented controlled fixtures.',
                             'BLE GATT entries are imported synthetic evidence, not demonstrated connections.',
                             'No physical identity linkage or geographic location is inferred.',
                             'Accuracy is fixture-only and has no statistical field-validity claim.'])
    write_report(root/'results.json',result,'json')
    return result
