"""Read-only capability checks; distinguish tool presence from usable access."""
from pathlib import Path
import platform
import shutil
import socket
import sqlite3
import sys
from importlib.metadata import PackageNotFoundError, version
from atlas.wifi.collector import interfaces
from atlas.bluetooth.collector import controllers
from atlas.bridge.importer import status as bridge_status
from .resources import values

TOOLS = ('ip', 'ss', 'iw', 'nmcli', 'rfkill', 'bluetoothctl', 'btmgmt', 'ping', 'curl',
         'tcpdump', 'nmap', 'bwrap', 'rustc', 'cargo', 'node')


def legacy_doctor():
    return dict(tools={x: bool(shutil.which(x)) for x in TOOLS},
                guest_wifi_interfaces=interfaces(), guest_bluetooth_controllers=controllers(),
                radio_note='Guest visibility only; Android radio access is not implied.',
                network_note='Guest routes may reflect NAT, not the Android LAN.')


def capabilities():
    try:
        text = Path('/proc/self/status').read_text()
    except OSError:
        return dict(status='UNVERIFIED', note='procfs status unavailable')
    fields = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    masks = {name: fields[name].strip() for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb') if name in fields}
    return dict(status='SUPPORTED', masks=masks, no_new_privileges=fields.get('NoNewPrivs', '').strip(),
                seccomp=fields.get('Seccomp', '').strip(),
                note='Capability masks belong to this process. Debian root does not grant Android radio access.')


def tcp_socket_check():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        return dict(status='UNSUPPORTED', note='TCP socket creation denied or unavailable', errno=exc.errno)
    sock.close()
    return dict(status='SUPPORTED', note='Socket creation only; LAN and internet reachability remain UNVERIFIED.')


def netlink_check():
    return dict(status='UNSUPPORTED',
                note='Host netlink inspection requires access outside the offline subprocess profile; not executed. Import explicit telemetry.')


def shared_storage():
    mounts = []
    try:
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            before, after = line.split(' - ', 1)
            fields = before.split()
            if fields[4] == '/mnt/shared':
                mounts.append(dict(filesystem=after.split()[0], options=fields[5].split(',')))
    except (OSError, ValueError, IndexError):
        pass
    effective = next((m for m in reversed(mounts) if m['filesystem'] != 'autofs'), None)
    visible = Path('/mnt/shared').is_dir()
    return dict(status='SUPPORTED' if visible else 'UNSUPPORTED', path='/mnt/shared', visible=visible,
                mount=effective, write_status=('UNSUPPORTED' if 'ro' in effective['options'] else 'UNVERIFIED') if effective else 'UNVERIFIED',
                note='No write attempted; document export propagation remains UNVERIFIED.')


def diagnose(config):
    wifi, ble = interfaces(), controllers()
    phy = sorted(p.name for p in Path('/sys/class/ieee80211').glob('phy*'))
    try:
        yaml_version = version('PyYAML')
    except PackageNotFoundError:
        yaml_version = None
    return dict(python=dict(status='SUPPORTED', version=platform.python_version(),
                            virtual_environment=sys.prefix != sys.base_prefix),
                platform=dict(architecture=platform.machine(), kernel=platform.release(),
                              system=platform.system(), phone_identity='UNVERIFIED'),
                sqlite=dict(status='SUPPORTED', version=sqlite3.sqlite_version),
                yaml=dict(status='SUPPORTED' if yaml_version else 'UNSUPPORTED', version=yaml_version),
                tools={name: shutil.which(name) for name in TOOLS},
                wifi=dict(status='UNVERIFIED' if wifi or phy else 'UNSUPPORTED', interfaces=wifi, phys=phy,
                          note='Visible adapter is not a successful scan; no Android passthrough assumed.'),
                bluetooth=dict(status='UNVERIFIED' if ble else 'UNSUPPORTED', controllers=ble),
                netlink=netlink_check(), tcp_socket=tcp_socket_check(),
                capabilities=capabilities(), shared_storage=shared_storage(),
                bridge=bridge_status(config.bridge.inbox))
