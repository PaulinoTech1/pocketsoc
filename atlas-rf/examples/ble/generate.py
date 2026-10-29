"""Synthetic BLE evidence generator. No radio access or GATT operations occur."""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).parent
SOURCE='synthetic:android-ble:lab'
ADDRESS='c2:11:22:33:44:01'
ROTATED='62:ab:cd:ef:00:02'


def ad(when,address=ADDRESS,name='AtlasBeacon',services=None,payload='0100',complete=True,connectable=True):
    services=['1809'] if services is None else services
    def element(kind,value):
        return bytes([len(value)+1,kind])+value
    raw=element(1,b'\x06')
    if services:
        raw+=element(3,b''.join(int(value,16).to_bytes(2,'little') for value in services))
    raw+=element(9,name.encode())+element(255,b'\xff\xff'+bytes.fromhex(payload))
    return dict(kind='ble',id=address,name=name,source=SOURCE,observed_at=when,rssi=-64,
                service_uuids=services,manufacturer_data={'65535':payload},advertisement_hex=raw.hex(),
                connectable=connectable,advertisement_complete=complete,evidence_confidence='synthetic')


def gatt(when,changed=False,status='complete'):
    services=[dict(uuid='1809',characteristics=[dict(uuid='2a1c',properties=2 if changed else 18)])]
    if changed:
        services.append(dict(uuid='180f',characteristics=[dict(uuid='2a19',properties=2)]))
    return dict(kind='ble_gatt',id=ADDRESS,source=SOURCE,observed_at=when,
                evidence_confidence='synthetic',authorization_id='cf6d021f-c3bc-4ecd-9b39-7b91cfe04ab4' if changed else '766d5b9e-05d6-4e3b-b375-ee44deed2cce',
                operation='discover_services',writes_performed=False,pairing_initiated=False,
                gatt_status=status,gatt_services=services if status=='complete' else [])

observations=[ad(f'2026-04-16T10:0{minute}:00Z') for minute in range(3)]
observations += [gatt('2026-04-16T10:02:30Z'),
    ad('2026-04-16T10:03:10Z',name='AtlasBeacon-v2',services=['1809','180f'],payload='0200',connectable=False),
    ad('2026-04-16T10:03:20Z',address=ROTATED),
    ad('2026-04-16T10:03:30Z',services=[],complete=False),
    ad('2026-04-16T10:03:40Z'),
    gatt('2026-04-16T10:03:50Z',status='failed'),
    gatt('2026-04-16T10:04:00Z',changed=True),
    ad('2026-04-16T10:20:00Z',name='Different advertiser',payload='ffff')]
payload=''.join(json.dumps(o,separators=(',',':'))+'\n' for o in observations)
(ROOT/'telemetry.jsonl').write_text(payload)
envelope=dict(kind='atlas-radio-export',schema_version=1,complete=True,
              metadata=dict(session_id='83d1c2ef-9b37-4082-aacc-59f4f30b855e',synthetic=True,
                            rows=len(observations),bytes=len(payload.encode()),
                            fixture_description='Synthetic advertisement changes, possible rotation and authorized GATT metadata; no real devices.'),
              payload_jsonl=payload,sha256=hashlib.sha256(payload.encode()).hexdigest())
(ROOT/'telemetry.atlas.json').write_text(json.dumps(envelope,indent=2)+'\n')
