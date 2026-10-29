"""Fail-closed offline Bubblewrap subprocess profile."""
import ctypes
import math
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import tempfile

OUTPUT_LIMIT = 2 * 1024 * 1024
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': '/work'}


def trusted_tool(name):
    # 65534 represents unmapped host root on this rootless execution host.
    # Never accept an executable owned by the current user or a writable system tool.
    for directory in ('/usr/bin', '/bin'):
        path = Path(directory, name)
        if path.is_file():
            info = path.stat()
            if info.st_uid in (0, 65534) and info.st_uid != os.geteuid() and not info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID) and os.access(path, os.X_OK):
                return str(path.resolve())
    raise ValueError(f'trusted {name} executable unavailable')


def limits():
    for kind, value in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, OUTPUT_LIMIT),
                        (resource.RLIMIT_CPU, 30), (resource.RLIMIT_AS, 256*1024*1024),
                        (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, 64)):
        resource.setrlimit(kind, (value, value))
    if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) != 0:
        raise OSError('cannot set no_new_privs')


def bounded(args, timeout):
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                                 env=ENV, cwd='/', close_fds=True, start_new_session=True,
                                 preexec_fn=limits)
        try:
            code = child.wait(timeout=timeout)
        except BaseException:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if code:
            errors.seek(0)
            if b'NETLINK_ROUTE' in errors.read(2048):
                raise ValueError('isolation unavailable: required NETLINK_ROUTE socket denied')
            raise ValueError(f'isolation or subprocess failed (exit {code}); execution refused')
        output.seek(0)
        data = output.read(OUTPUT_LIMIT + 1)
        if len(data) >= OUTPUT_LIMIT:
            raise ValueError('subprocess output limit reached')
        return data.decode('utf-8', errors='strict')


def command(args):
    result = [trusted_tool('bwrap'), '--unshare-all', '--unshare-user', '--disable-userns',
              '--assert-userns-disabled', '--die-with-parent', '--new-session', '--cap-drop', 'ALL', '--clearenv']
    for key, value in ENV.items():
        result += ['--setenv', key, value]
    for path in ('/usr', '/bin', '/lib', '/lib64'):
        if Path(path).exists():
            result += ['--ro-bind', path, path]
    return result + ['--proc', '/proc', '--dev', '/dev', '--size', '16777216', '--tmpfs', '/tmp',
                     '--dir', '/work', '--remount-ro', '/',
                     '--chdir', '/work', '--', *args]


def run(args, timeout=15):
    if (not isinstance(args, (list, tuple)) or not args or len(args) > 64 or
        any(not isinstance(a, str) or '\0' in a or len(a) > 4096 for a in args)):
        raise ValueError('subprocess requires bounded argument strings')
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError('subprocess timeout must be greater than zero and at most 30 seconds')
    if Path(args[0]).name in {'ip', 'nmcli', 'bluetoothctl'}:
        raise ValueError('guest collector needs host network or D-Bus; offline isolation cannot support it; import telemetry instead')
    executable = trusted_tool(Path(args[0]).name)
    if '/' in args[0] and str(Path(args[0]).resolve()) != executable:
        raise ValueError('executable must be a trusted system utility')
    try:
        return bounded(command([executable, *args[1:]]), timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError('required isolation unavailable or timed out; no unsandboxed fallback') from exc


def probe():
    checks = {}
    for name, flags in {'user': ['--user', '--map-root-user'],
                        'required_namespaces': ['--user', '--map-root-user', '--mount', '--pid',
                                                '--fork', '--net', '--ipc', '--uts']}.items():
        try:
            bounded([trusted_tool('unshare'), *flags, trusted_tool('true')], 5)
            checks[name] = {'status': 'SUPPORTED'}
        except (ValueError, OSError, subprocess.SubprocessError):
            checks[name] = {'status': 'UNSUPPORTED', 'reason': 'runtime namespace creation failed'}
    script = """import os,socket
assert all(not os.path.exists(p) for p in ('/home/droid','/mnt/shared','/run/dbus/system_bus_socket','/etc/passwd'))
assert set(os.environ) <= {'PATH','LANG','HOME','LC_CTYPE'}
status=open('/proc/self/status').read()
assert 'NoNewPrivs:\\t1' in status and 'CapEff:\\t0000000000000000' in status
try: open('/usr/atlas-isolation-write-test','w')
except OSError: pass
else: raise AssertionError('writable system mount')
s=socket.socket();s.settimeout(.2)
try: s.connect(('192.0.2.1',9))
except OSError: pass
else: raise AssertionError('network reachable')
print('isolation_verified')
"""
    try:
        if run(['/usr/bin/python3', '-I', '-c', script], 5).strip() != 'isolation_verified':
            raise ValueError('probe marker missing')
        checks['bubblewrap_profile'] = {'status': 'SUPPORTED', 'verified': [
            'private namespaces', 'read-only runtime', 'hidden home/shared storage/system bus',
            'cleared environment', 'no new privileges', 'zero effective capabilities', 'network denied']}
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        checks['bubblewrap_profile'] = {'status': 'UNSUPPORTED', 'reason': str(exc)[:256], 'fallback': 'refuse_execution'}
    return dict(checks=checks, usable=all(v['status']=='SUPPORTED' for v in checks.values()),
                scope='This execution host only; repeat on the Android Debian guest.', fallback='refuse_execution')
