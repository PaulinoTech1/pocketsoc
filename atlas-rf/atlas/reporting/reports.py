"""Structured JSON and escaped Markdown reports."""
from atlas.core.events import now
from atlas.detection.rules import analyze
from atlas.topology.graph import topology

def report(store, limit=10000):
    rows = store.observations(limit)
    stats = store.stats()
    tables={row[0] for row in store.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    import json
    retained={}
    retained_bytes=0
    for table in ('wifi_baselines','ble_findings','detection_findings','cellular_baselines','cellular_sessions'):
        if table in tables:
            total=store.db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
            bodies=store.db.execute(f'SELECT substr(body,1,1048577) FROM {table} ORDER BY rowid DESC LIMIT 100')
            values=[]
            for (body,) in bodies:
                size=len(body.encode())
                if size>1024*1024 or retained_bytes+size>4*1024*1024:
                    continue
                retained_bytes+=size
                value=json.loads(body)
                if table in {'wifi_baselines','cellular_baselines'}:
                    value={key:value[key] for key in ('id','source','created_at','through_at','samples')}
                values.append(value)
            retained[table]=dict(total=total,returned=len(values),truncated=total>len(values),records=values,
                                 limits='100 rows/table, 1 MiB/record, 4 MiB total serialized retained evidence; use dedicated evidence commands for omitted records')
    from atlas.cellular.engine import analyze as cellular_analyze
    return dict(cellular=cellular_analyze(rows), retained_evidence=retained, project='ATLAS RF', generated_at=now(), counts=stats,
                coverage=dict(analyzed=len(rows), total=sum(stats.values()), limit=limit,
                              truncated=sum(stats.values()) > len(rows),
                              start=rows[0]['observed_at'] if rows else None,
                              end=rows[-1]['observed_at'] if rows else None),
                limitations=['Imported data is not authenticated; source labels are operator supplied.',
                             'MAC randomization and address reuse prevent reliable physical device identification.',
                             'RSSI supports relative signal analysis, not geographic localization.',
                             'Guest network observations may reflect NAT rather than the Android LAN.',
                             'Heuristic findings require review and are not confirmed vulnerabilities.'],
                findings=analyze(rows), topology=topology(rows))


def markdown(r):
    from atlas.core.events import clean
    def safe(value):
        text = clean(value)
        for c in '\\`*_{}[]<>()!|#':
            text = text.replace(c, '\\' + c)
        return text
    lines = ['# ATLAS RF security assessment', '', f"Generated: {r['generated_at']}", '',
             f"Analyzed {r['coverage']['analyzed']} of {r['coverage']['total']} observations (latest window).",
             f"Window: {r['coverage']['start']} to {r['coverage']['end']}", '', '## Findings', '']
    if not r['findings']:
        lines.append('No configured heuristic fired within this window. This does not establish security.')
    for f in r['findings']:
        lines.append(f"- **{f['severity'].upper()} / {f['rule']}** — {safe(f['identity'])}, {safe(f['source'])}, {f['observed_at']}: {safe(f['evidence'])}")
    cellular = r.get('cellular', {})
    lines += ['', '## Cellular observations', '',
              f"{cellular.get('observations', 0)} observations; {len(cellular.get('changes', []))} descriptive changes. See JSON for fields and evidence IDs; these are not attack findings."]
    lines += ['', '## Retained evidence', '']
    for name, evidence in r.get('retained_evidence',{}).items():
        lines.append(f"- {safe(name)}: {evidence['total']} saved records; {evidence['returned']} included in JSON.")
    lines += ['', '## Topology evidence', '',
              f"{len(r['topology']['nodes'])} nodes; {len(r['topology']['edges'])} edges. Export JSON for the complete graph.",
              r['topology']['caveat'], '', '## Limitations', '']
    lines += ['- ' + safe(item) for item in r['limitations']]
    if r['coverage']['truncated']:
        lines += ['', '**History truncated to the configured analysis window; baseline findings may be incomplete.**']
    return '\n'.join(lines) + '\n'
