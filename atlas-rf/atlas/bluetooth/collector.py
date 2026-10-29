"""Optional guest BlueZ LE adapter."""
from pathlib import Path
import re
from atlas.core.events import now
from atlas.core.process import run

def controllers():
    return sorted(p.name for p in Path("/sys/class/bluetooth").glob("hci*"))

def ble():
    if not controllers():
        raise ValueError('no guest Bluetooth controller; import authorized sensor/Android export JSONL')
    data = run(['bluetoothctl', '--timeout', '8', 'scan', 'le'], 12)
    data = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', data)
    found = {}
    when = now()
    for line in data.splitlines():
        match = re.search(r'Device ((?:[\da-fA-F]{2}:){5}[\da-fA-F]{2}) (.*)', line)
        if not match:
            continue
        identity, info = match.groups()
        o = found.setdefault(identity, dict(kind='ble', id=identity, source='guest:bluez', observed_at=when))
        if info.startswith('RSSI: '):
            try:
                o['rssi'] = int(info[6:].split()[0])
            except ValueError:
                pass
        elif info.startswith('Name: '):
            o['name'] = info[6:]
        elif line.startswith('[NEW]'):
            o['name'] = info
    return list(found.values())


