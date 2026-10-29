#!/usr/bin/env python3
"""Local synthetic integration/resource demonstration. Never opens a radio or socket."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import resource
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from atlas.cellular.analysis import analyze
from atlas.cellular.baseline import build
from atlas.cellular.engine import ingest, inspect
from atlas.core.events import validate
from atlas.reporting.reports import report, markdown
from atlas.security.evidence import verify
from atlas.storage.sqlite import Store
from atlas.storage.reader import reader
from atlas.ui.console import write_report
from atlas.ui.dashboard import snapshot


def run(output, events):
    os.umask(0o077)
    output.mkdir(mode=0o700, parents=True)
    db = output/'cellular.sqlite3'
    imported = ingest(db, ROOT/'examples/cellular/session.atlas.json', synthetic=True)
    replay = ingest(db, ROOT/'examples/cellular/session.atlas.json', synthetic=True)
    source = 'synthetic:android:cellular-lab'
    store = Store(db)
    try: baseline = build(store, source, '2026-04-18T10:01:00Z')
    finally: store.close()
    assessment = inspect(db, source, use_baseline=True)
    manifest = verify(db)
    write_report(output/'baseline.json', baseline, 'json')
    write_report(output/'analysis.json', assessment, 'json')
    write_report(output/'evidence-manifest.json', manifest, 'json')
    verify(db, output/'evidence-manifest.json')
    with reader(db) as store: integrated = report(store)
    write_report(output/'report.json', integrated, 'json')
    write_report(output/'report.md', markdown(integrated), 'markdown')
    write_report(output/'dashboard.txt', '\n'.join(snapshot(db, 'cellular', 'findings')['lines'])+'\n', 'markdown')
    # Fresh benchmark storage; one-second modem timestamps and stable serving signal.
    template = next(o for o in assessment['records'] if o['cellular_event'] == 'cell' and o['cell_freshness'] == 'recent' and o.get('technology') == 'LTE' and o.get('registered') is True)
    store = Store(output/'resource.sqlite3')
    wall = time.perf_counter(); cpu = time.process_time()
    latency = []; inserted = 0
    normal_findings = 0
    try:
        for start in range(0, events, 100):
            batch = []
            for index in range(start, min(events, start+100)):
                when = dt.datetime(2026, 4, 19, tzinfo=dt.timezone.utc)+dt.timedelta(seconds=index)
                value = dict(template, id=f'synthetic-benchmark-{index}',
                             observed_at=when.isoformat(), received_at=(when+dt.timedelta(milliseconds=100)).isoformat(),
                             collection_session='synthetic-benchmark', cell_age_ms=100,
                             measurement_elapsed_ms=1000000+index*1000, lte_rsrp=-90)
                batch.append(value)
            inserted += store.add(batch)
        # Individual samples include commit plus evaluation of latest bounded history.
        for index in range(100):
            started = time.perf_counter()
            when = dt.datetime(2026, 4, 19, tzinfo=dt.timezone.utc)+dt.timedelta(seconds=events+index)
            value = dict(template, id=f'synthetic-tail-{index}', observed_at=when.isoformat(),
                         received_at=(when+dt.timedelta(milliseconds=100)).isoformat(),
                         collection_session='synthetic-benchmark', cell_age_ms=100,
                         measurement_elapsed_ms=1000000+(events+index)*1000, lte_rsrp=-90)
            inserted += store.add([value])
            result = analyze(store.observations(2000))
            normal_findings += len(result['findings'])
            latency.append((time.perf_counter()-started)*1000)
        stored = sum(store.stats().values())
    finally: store.close()
    wall = time.perf_counter()-wall; cpu = time.process_time()-cpu
    ordered = sorted(latency)
    resources = dict(synthetic=True, workload='stable normal LTE; bulk inserts then 100 timed insert+latest-2000-rule evaluations',
                     submitted=events+100, stored=stored, inserted=inserted, event_loss=events+100-stored,
                     peak_rss_bytes_process_lifetime=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
                     cpu_seconds=cpu, wall_seconds=wall, cpu_percent_one_core=100*cpu/wall,
                     latency_ms=dict(samples=100, p50=statistics.median(ordered), p95=ordered[94], p99=ordered[98], maximum=ordered[-1]),
                     normal_stream_findings=normal_findings,
                     limitations=['No Android callback, network, RF loss, battery or hardware measurement.',
                                  '100 tail evaluations of overlapping windows are correlated, not independent field accuracy cases.',
                                  'Peak RSS is lifetime of this process; latency is a bounded history workload, not a real-time guarantee.'])
    summary = dict(synthetic=True, hardware_demonstrated=False, android_delivery='UNVERIFIED',
                   fixture_import=imported, fixture_replay=replay, baseline_samples=baseline['samples'],
                   deterministic_findings=len(assessment['findings']), trends=len(assessment['trends']),
                   performance_comparisons=assessment['performance'], evidence_integrity=manifest['integrity'],
                   resources=resources)
    write_report(output/'results.json', summary, 'json')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--events', type=int, default=10000, help='100..50000 bulk events plus 100 timed tail events')
    args = parser.parse_args()
    if not 100 <= args.events <= 50000: parser.error('events must be 100..50000')
    result = run(args.output, args.events)
    print(json.dumps(result, indent=2))
    return 0 if result['resources']['event_loss'] == 0 and result['resources']['normal_stream_findings'] == 0 else 1

if __name__ == '__main__': raise SystemExit(main())
