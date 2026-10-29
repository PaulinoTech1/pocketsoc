"""Rebuild bundled invented scenarios and hand-labelled policy cases. No hardware access."""
import copy
import json
from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[2]
def bundle(relative):
    envelope=json.loads((ROOT/relative).read_text())
    assert envelope['metadata']['synthetic'] is True
    return [json.loads(line) for line in envelope['payload_jsonl'].splitlines()]

policy=yaml.safe_load((ROOT/'config/detection.yaml').read_text())
policy_rows=[json.loads(line) for line in (ROOT/'examples/detection/telemetry.jsonl').read_text().splitlines()]
ble=bundle('examples/ble/telemetry.atlas.json')
network=[dict(kind='neighbor',id='192.0.2.55',ip='192.0.2.55',mac='02:11:22:00:00:01',
              source='synthetic:detection:network',observed_at='2026-04-17T10:00:00Z',interface='fixture0'),
         dict(kind='route',id='192.0.2.0/24@fixture0',gateway='192.0.2.1',interface='fixture0',
              source='synthetic:detection:network',observed_at='2026-04-17T10:00:00Z')]
cases=[]
for rule in policy['rules']:
    kind='wifi' if rule['id'].startswith('wifi.') else 'ble' if rule['id'].startswith('ble.') else 'service'
    positive=copy.deepcopy(next(row for row in policy_rows if row['kind']==kind))
    benign=copy.deepcopy(positive)
    if kind=='wifi': benign.update(id='02:aa:bb:cc:00:01',security='WPA3')
    elif kind=='ble': benign['service_uuids']=['180f']
    else: benign.update(id='192.0.2.5/tcp/443',ip='192.0.2.5',port=443)
    for label,expected,template,times in (
        ('mismatch',True,positive,['10:00:20','10:00:30']),
        ('approved',False,benign,['10:00:20','10:00:30']),
        ('expired',False,positive,['09:00:20','09:00:30']),
        ('insufficient',False,positive,['10:00:20'])):
        rows=[dict(copy.deepcopy(template),observed_at='2026-04-17T'+time+'Z') for time in times]
        cases.append(dict(case_id=rule['id']+':'+label,rule_id=rule['id'],expected_alert=expected,observations=rows))
scenario=dict(format='atlas-controlled-demo/v1',synthetic=True,
              description='Invented observations and reviewed expectation labels, not hardware or field accuracy.',
              wifi_source='synthetic:android-wifi:office',ble_source='synthetic:android-ble:lab',
              wifi_training=bundle('examples/wifi/training.atlas.json'),
              wifi_evaluation=bundle('examples/wifi/evaluation.atlas.json'),
              ble_training=ble[:4],ble_evaluation=ble[4:],policy=policy,policy_observations=policy_rows,
              network_observations=network,clock='2026-04-17T10:01:00Z',ble_since='2026-04-16T10:03:00Z',
              expected_wifi_rules={'unknown-bssid':4,'unseen-ssid':2,'unexpected-security-change':1,
                                   'unusual-channel-change':1,'suspicious-ssid-duplication':1},
              expected_ble_rules=['new-advertising-services','unexpected-advertisement-configuration',
                                  'advertised-capabilities-added','known-gatt-capabilities-changed'],
              expected_policy_rules=[r['id'] for r in policy['rules']],accuracy_cases=cases)
(ROOT/'atlas/fixtures/prototype.json').write_text(json.dumps(scenario,indent=2,sort_keys=True)+'\n')
