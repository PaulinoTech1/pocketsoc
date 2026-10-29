"""Generate deterministic synthetic Wi-Fi scenarios; never reads radio hardware."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parent
SOURCE = 'synthetic:android-wifi:office'
APS = [
    ('02:11:22:00:00:01', 'AtlasOffice', 2412, 1, -57, 'WPA2 WPA3'),
    ('02:11:22:00:00:02', 'AtlasOffice', 5180, 36, -49, 'WPA2 WPA3'),
    ('02:11:22:00:00:03', 'AtlasOffice', 5975, 5, -61, 'WPA3'),
    ('02:11:22:00:00:04', 'CafeGuest', 2437, 6, -76, 'OPEN'),
    ('02:11:22:00:00:05', 'Printer-Lab', 5745, 149, -66, 'WPA2'),
]

def observation(ap, when, **changes):
    identity, name, freq, channel, rssi, security = ap
    return dict(kind='wifi', id=identity, name=name, frequency_mhz=freq, channel=channel,
                rssi=rssi, security=security, source=SOURCE, observed_at=when,
                scan_freshness='fresh', scan_age_ms=420, **changes)


def write_bundle(name, observations, session):
    payload = ''.join(json.dumps(row, separators=(',', ':')) + '\n' for row in observations)
    envelope = dict(kind='atlas-radio-export', schema_version=1, complete=True,
                    metadata=dict(session_id=session, synthetic=True, rows=len(observations),
                                  bytes=len(payload.encode()), statuses={'session':'fixture_only'},
                                  fixture_description='Synthetic Wi-Fi scenario; no hardware measurements.'),
                    payload_jsonl=payload, sha256=hashlib.sha256(payload.encode()).hexdigest())
    (ROOT/name).write_text(json.dumps(envelope, indent=2)+'\n')

training = [observation(ap, f'2026-04-15T10:0{minute}:00Z') for minute in range(3) for ap in APS]
training += [dict(observation(APS[0], '2026-04-15T10:01:30Z'), security='OPEN', scan_age_ms=90000),
             dict(observation(APS[0], '2026-04-15T10:00:00Z'), scan_freshness='cached', scan_age_ms=1200),
             dict(observation(APS[0], '2026-04-15T10:02:15Z'), id='02:11:22:00:00:99', name='OldCache', scan_freshness='unknown')]
evaluation = [
    dict(observation(APS[1], '2026-04-15T10:10:00Z'), security='OPEN'),
    dict(observation(APS[0], '2026-04-15T10:10:00Z'), frequency_mhz=2462, channel=11),
    dict(observation(APS[1], '2026-04-15T10:10:00Z'), id='02:11:22:00:00:06'),
    dict(observation(APS[0], '2026-04-15T10:10:00Z'), id='02:11:22:00:00:07', frequency_mhz=2437, channel=6, security='OPEN', rssi=-38),
    dict(observation(APS[2], '2026-04-15T10:10:00Z'), id='02:11:22:00:00:08', name='Neighbor-Lab', frequency_mhz=6135, channel=37, rssi=-82),
    dict(observation(APS[0], '2026-04-15T10:09:00Z'), security='WEP', scan_freshness='cached'),
    dict(observation(APS[0], '2026-04-15T10:09:30Z'), id='02:11:22:00:00:aa', name='StalePhantom', scan_age_ms=95000),
    dict(observation(APS[0], '2026-04-15T10:10:00Z'), id='02:11:22:00:00:09', name=''),
    dict(observation(APS[2], '2026-04-15T10:10:00Z'), security='UNKNOWN'),
    dict(observation(APS[4], '2026-04-15T10:11:00Z'), name='Printer-Service'),
    dict(observation(APS[0], '2026-04-15T10:12:00Z'), rssi=-55),
]
# Another delivery of the same measured time must not inflate the training/anomaly count.
evaluation += [dict(evaluation[0], scan_age_ms=800)]
write_bundle('training.atlas.json', training, '156e59c8-2978-40dc-9955-985b283721a7')
write_bundle('evaluation.atlas.json', evaluation, '890bb4c0-92dc-4a8f-8045-cf074b849d28')
(ROOT/'training.jsonl').write_text(''.join(json.dumps(o)+'\n' for o in training))
