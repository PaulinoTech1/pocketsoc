"""Explainable bounded-window detection rules."""
import datetime as dt
from itertools import islice
from atlas.wifi.schema import eligibility

def security_level(value):
    value = value.upper()
    if value in {'OPEN', '--', 'NONE'}:
        return 0
    if 'WEP' in value:
        return 1
    if 'WPA2' in value or 'WPA3' in value or 'OWE' in value or 'RSN' in value:
        return 3
    if 'WPA' in value:
        return 2
    return None


def analyze(observations):
    findings, previous, ssids = [], {}, {}
    def finding(rule, o, detail, severity='info'):
        findings.append(dict(rule=rule, severity=severity, identity=o['id'], source=o['source'],
                             observed_at=o['observed_at'], evidence=detail))
    for o in sorted(observations, key=lambda o: o['observed_at']):
        if o['kind'] == 'wifi' and ('scan_freshness' in o or 'scan_age_ms' in o) and eligibility(o) != 'fresh':
            continue
        key = (o['kind'], o['id'], o['source'])
        old = previous.get(key)
        if o['kind'] == 'wifi':
            level = security_level(o['security'])
            if level is not None and level <= 2 and (not old or old.get('security') != o['security']):
                finding('wifi-weak-security', o, f"Advertised security: {o['security']}. Verify configuration; this is not proof of compromise.", 'medium')
            if old:
                old_level = security_level(old['security'])
                if level is not None and old_level is not None and level < old_level:
                    finding('wifi-security-downgrade', o, f"Security changed from {old['security']} at {old['observed_at']} to {o['security']}; verify with the network owner.", 'high')
            if o.get('name'):
                ssid_key = (o['source'], o['name'])
                seen = ssids.setdefault(ssid_key, {})
                if seen and o['id'] not in seen:
                    sample = ', '.join(islice(seen, 8))
                    finding('wifi-new-bssid', o, f"SSID {o['name']} also observed on {len(seen)} BSSID(s), including {sample}. Mesh/roaming is normal; a new BSSID alone does not establish an evil twin.")
                seen[o['id']] = None
        if old and 'rssi' in o and 'rssi' in old:
            seconds = (dt.datetime.fromisoformat(o['observed_at']) - dt.datetime.fromisoformat(old['observed_at'])).total_seconds()
            if 0 < seconds <= 300 and abs(o['rssi'] - old['rssi']) >= 25:
                finding('rapid-rssi-change', o, f"RSSI changed {old['rssi']} to {o['rssi']} dBm in {seconds:g}s. Movement, interference or sensor conditions may explain it.")
        if o['kind'] == 'service' and not old and o['port'] in {21, 23, 445, 3389, 5900}:
            finding('review-sensitive-port', o, f"TCP {o['port']} accepted a connection. Protocol and vulnerability are unverified; review access policy.", 'medium')
        previous[key] = o
    return findings


