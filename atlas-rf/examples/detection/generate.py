"""Invented policy mismatches and benign/stale controls; no network or radio access."""
import json
from pathlib import Path

rows=[]
for second in (0,10):
    time=f'2026-04-17T10:00:{second:02d}Z'
    rows.extend([
        dict(kind='wifi',id='02:aa:bb:cc:00:02',source='synthetic:detection:wifi',name='Atlas Lab',
             security='WPA2',observed_at=time,scan_freshness='fresh',scan_age_ms=100,rssi=-50),
        dict(kind='ble',id='c2:11:22:33:44:01',source='synthetic:detection:ble',name='Synthetic beacon',
             service_uuids=['180f','181a'],advertisement_complete=True,rssi=-60,
             observed_at=time,evidence_confidence='synthetic'),
        dict(kind='service',id='192.0.2.55/tcp/22',ip='192.0.2.55',port=22,
             source='synthetic:detection:network',observed_at=time),
        dict(kind='wifi',id='02:aa:bb:cc:00:01',source='synthetic:detection:wifi',name='Atlas Lab',
             security='WPA3',observed_at=time,scan_freshness='fresh',scan_age_ms=100),
        dict(kind='service',id='192.0.2.5/tcp/443',ip='192.0.2.5',port=443,
             source='synthetic:detection:network',observed_at=time),
        dict(kind='wifi',id='02:aa:bb:cc:00:03',source='synthetic:detection:wifi',name='Atlas Lab',
             security='OPEN',observed_at=time,scan_freshness='cached',scan_age_ms=100),
    ])
Path(__file__).with_name('telemetry.jsonl').write_text(''.join(json.dumps(o,sort_keys=True)+'\n' for o in rows))
