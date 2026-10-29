#!/usr/bin/env python3
"""Development validation harness: real unit/integration tests and a real PTY, no radio scans."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from atlas.ui.console import write_report


def terminal_test(database,output,include_cellular=False):
    before=hashlib.sha256(database.read_bytes()).hexdigest()
    master,slave=pty.openpty()
    child=None;transcript=bytearray();states=[]
    try:
        env=dict(os.environ,TERM='xterm-256color')
        child=subprocess.Popen([sys.executable,'-m','atlas','--db',str(database),'dashboard'],
                               cwd=ROOT,stdin=slave,stdout=slave,stderr=slave,env=env,
                               start_new_session=True,close_fds=True)
        os.close(slave);slave=None
        def collect(seconds):
            deadline=time.monotonic()+seconds
            while time.monotonic()<deadline:
                ready,_,_=select.select([master],[],[],min(.05,max(0,deadline-time.monotonic())))
                if ready:
                    try: chunk=os.read(master,65536)
                    except OSError as exc:
                        if exc.errno==errno.EIO: break
                        raise
                    if not chunk: break
                    transcript.extend(chunk)
        for _ in range(50):
            collect(.1)
            if b'ATLAS RF' in transcript: break
        if b'ATLAS RF' not in transcript: raise AssertionError('curses initial frame missing')
        states.append('initial_all')
        # Curses sends differential updates, so a full header need not be contiguous.
        cases = [(b'2f',(b'wifi',b'finding'),'wifi_findings'),
                 (b'3o',(b'ble',b'observation'),'ble_observations'),
                 (b'4',(b'service',),'tcp_observations')]
        if include_cellular:
            cases.append((b'5f',(b'cellular',b'finding'),'cellular_findings'))
        for keys,markers,state in cases:
            start=len(transcript);os.write(master,keys)
            for _ in range(30):
                collect(.1)
                if all(marker in transcript[start:] for marker in markers): break
            if not all(marker in transcript[start:] for marker in markers): raise AssertionError('curses view missing: '+state)
            states.append(state)
        os.write(master,b'q');collect(.2)
        code=child.wait(timeout=5)
        after=hashlib.sha256(database.read_bytes()).hexdigest()
        if code or before!=after: raise AssertionError('dashboard exit or read-only invariant failed')
        fd=os.open(output/'dashboard-pty.bin',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream: stream.write(transcript)
        return dict(status='PASSED',real_pty=True,states=states,exit_code=code,database_unchanged=before==after,
                    transcript_bytes=len(transcript),transcript='dashboard-pty.bin')
    finally:
        if child is not None and child.poll() is None:
            os.killpg(child.pid,signal.SIGKILL);child.wait()
        os.close(master)
        if slave is not None: os.close(slave)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--demo',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cellular',action='store_true',help='use cellular.sqlite3 and exercise cellular dashboard key 5')
    args=parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(mode=0o700,parents=True)
    start=time.perf_counter()
    log=io_buffer=__import__('io').StringIO()
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'))
    result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
    write_report(args.output/'unittest.txt',io_buffer.getvalue(),'markdown')
    try: terminal=terminal_test(args.demo.resolve()/('cellular.sqlite3' if args.cellular else 'demo.sqlite3'),args.output,args.cellular)
    except (OSError,AssertionError,subprocess.SubprocessError) as exc:
        terminal=dict(status='FAILED',reason=type(exc).__name__,real_pty=False)
    summary=dict(tests_run=result.testsRun,passed=result.testsRun-len(result.skipped)-len(result.failures)-len(result.errors),
                 skipped=[dict(test=str(test),reason=reason) for test,reason in result.skipped],
                 failures=len(result.failures),errors=len(result.errors),
                 wall_seconds=time.perf_counter()-start,dashboard=terminal,
                 all_discovered_tests_executed=True,pytest_required=False)
    write_report(args.output/'validation.json',summary,'json')
    print(json.dumps(summary,indent=2))
    return 0 if result.wasSuccessful() and terminal['status']=='PASSED' else 1

if __name__=='__main__': raise SystemExit(main())
