"""Optional guest NetworkManager Wi-Fi adapter."""
from pathlib import Path
from atlas.core.events import now
from atlas.core.process import run

def interfaces():
    return sorted(p.name for p in Path("/sys/class/net").glob("*") if (p / "wireless").exists())

def split_nm(line):
    fields, field, escaped = [], '', False
    for c in line:
        if escaped:
            field += c
            escaped = False
        elif c == '\\':
            escaped = True
        elif c == ':':
            fields.append(field)
            field = ''
        else:
            field += c
    fields.append(field)
    return fields


def wifi():
    if not interfaces():
        raise ValueError('no guest Wi-Fi interface; import authorized sensor/Android export JSONL')
    data = run(['nmcli', '-t', '-e', 'yes', '-f', 'BSSID,SSID,SECURITY', 'device', 'wifi', 'list', '--rescan', 'yes'], 25)
    when, observations = now(), []
    for line in data.splitlines():
        fields = split_nm(line)
        if len(fields) != 3:
            raise ValueError('unexpected nmcli output')
        bssid, ssid, security = fields
        observations.append(dict(kind='wifi', id=bssid, name=ssid, security=security or 'OPEN',
                                 source='guest:nmcli', observed_at=when))
    return observations


