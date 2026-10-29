"""Invented deterministic cellular scenarios. This file never reads hardware."""
import datetime as dt
import hashlib
import json
from pathlib import Path

SOURCE = 'synthetic:android:cellular-lab'
BASE = dt.datetime(2026, 4, 18, 10, tzinfo=dt.timezone.utc)


def row(event, second, **fields):
    value = dict(kind='cellular', id=f'synthetic-{event}-{second}', source=SOURCE,
                 observed_at=(BASE+dt.timedelta(seconds=second)).isoformat(),
                 collection_session='synthetic-session-a', cellular_event=event, cell_freshness='unknown')
    if event not in {'connectivity', 'performance'}:
        value['subscription_id'] = 1
    value.update(fields)
    return value


def cell(second, **fields):
    value = row('cell', second, technology='LTE', mcc='001', mnc='01', cell_id=100,
                pci=10, tac=20, arfcn=1800, bands=[3], lte_rsrp=-90, lte_rsrq=-9,
                lte_rssi=-70, lte_rssnr=15, registered=True, connection_status='primary',
                cell_origin='update', cell_freshness='recent', cell_age_ms=100,
                measurement_elapsed_ms=1000000+second*1000)
    value['received_at'] = (BASE+dt.timedelta(seconds=second, milliseconds=100)).isoformat()
    value.update(fields)
    return value


def observations():
    values = [cell(0), cell(30, lte_rsrp=-92), cell(60, lte_rsrp=-94),
              cell(90, lte_rsrp=-105), cell(120, lte_rsrp=-112), cell(150, lte_rsrp=-120),
              cell(180, cell_id=200), cell(210, cell_id=200, arfcn=1900),
              cell(220, cell_id=300, registered=False, connection_status='none'),
              row('cell', 225, technology='NR', mcc='001', mnc='01', cell_id=9000000,
                  pci=700, tac=90000, arfcn=630000, bands=[78], nr_ss_rsrp=-100,
                  nr_ss_rsrq=-15, nr_ss_sinr=10, registered=True, connection_status='secondary',
                  cell_origin='update', cell_freshness='recent', cell_age_ms=500,
                  measurement_elapsed_ms=1225000),
              cell(240, cell_id=400, cell_origin='cached_read', cell_freshness='cached'),
              row('signal', 250, technology='LTE', lte_rsrp=-115),
              row('subscription', 0, subscription_status='active', slot_index=0, carrier='Synthetic Test Carrier', sim_state=5),
              row('technology', 0, network_type=13, data_state=2, display_override=0),
              row('technology', 80, network_type=20),
              row('technology', 160, network_type=13, data_state=0, display_override=3),
              row('service', 0, service_state=0, roaming=False),
              row('service', 170, service_state=1, roaming=False),
              row('service', 190, service_state=0, roaming=False),
              row('connectivity', 0, cellular_available=True),
              row('connectivity', 175, cellular_available=False),
              row('connectivity', 200, cellular_available=True),
              row('connectivity', 205, default_transport='wifi', network_validated=True)]
    for transport, duration in (('wifi', 100), ('cellular', 200)):
        values.append(row('performance', 260 if transport == 'wifi' else 270, test_id='synthetic-test-pair',
                          test_endpoint='https://example.invalid/atlas-test', test_transport=transport,
                          test_status='success', bound_network=True, authorized=True,
                          duration_ms=duration, bytes_received=65536, http_status=206))
    return values


def main():
    root = Path(__file__).resolve().parent
    rows = observations()
    payload = ''.join(json.dumps(o, sort_keys=True) + '\n' for o in rows)
    (root/'observations.jsonl').write_text(payload)
    envelope = dict(kind='atlas-radio-export', schema_version=1, complete=True,
                    metadata=dict(session_id='00000000-0000-4000-8000-000000000001', synthetic=True,
                                  rows=len(rows), bytes=len(payload.encode()),
                                  statuses={'cellular': 'SYNTHETIC: no Android APIs invoked'}, drops={}),
                    sha256=hashlib.sha256(payload.encode()).hexdigest(), payload_jsonl=payload)
    (root/'session.atlas.json').write_text(json.dumps(envelope, indent=2)+'\n')

if __name__ == '__main__': main()
