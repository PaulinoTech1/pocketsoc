"""Refuse elevated CLI execution instead of requiring or requesting privilege."""
import ctypes
import os
from pathlib import Path


def enforce_unprivileged():
    if os.geteuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise ValueError('run ATLAS as an ordinary user, without root or setuid privileges')
    fields = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if int(fields.get('CapEff', '0').strip(), 16):
        raise ValueError('run ATLAS without effective Linux capabilities')
    if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) != 0:
        raise ValueError('cannot enforce no_new_privs; execution refused')
