"""ATLAS application entry point and process-level exception boundary."""
import argparse
import logging
import os
from pathlib import Path
import signal
import sqlite3
import sys
import threading
from . import __version__
from .core.application import Application
from .core.config import load_config, validate_paths, LoggingConfig
from .core.errors import AtlasError, ResourceLimitError
from .core.logging import configure, event
from .ui.console import emit, write_report
from .bridge.bundle import read_bundle, verify_probe


def parser():
    p = argparse.ArgumentParser(prog='atlas', description='ATLAS RF local orchestration and diagnostics')
    p.add_argument('--version', action='version', version=__version__)
    p.add_argument('--config', type=Path, help='validated YAML file; relative paths resolve against this file')
    p.add_argument('--db', type=Path, help='override configured observation database')
    commands = p.add_subparsers(dest='command', required=True)
    commands.add_parser('status', help='read local state and process resource usage; never initializes a database')
    commands.add_parser('doctor', help='inspect actual capabilities without radio scanning or network connections')
    monitor = commands.add_parser('monitor', help='stream bounded resource snapshots, without scanning')
    group = monitor.add_mutually_exclusive_group()
    group.add_argument('--once', action='store_true', help='emit one sample and exit')
    group.add_argument('--samples', type=int, default=0, help='number of samples; 0 continues until Ctrl-C/SIGTERM')
    report = commands.add_parser('report', help='analyze the configured existing SQLite history')
    report.add_argument('--format', choices=('json', 'markdown'), default='json')
    report.add_argument('--output', type=Path, help='new private report file; never overwrites')
    bridge = commands.add_parser('bridge', help='verify/import explicit finalized Android file exports')
    actions = bridge.add_subparsers(dest='bridge_action', required=True)
    for name in ('verify', 'import', 'verify-probe'):
        action = actions.add_parser(name)
        action.add_argument('file', type=Path)
        if name in ('verify', 'import'):
            action.add_argument('--key', type=Path)
            action.add_argument('--nonce')
        if name == 'verify-probe':
            action.add_argument('--nonce', required=True, help='exact nonce displayed by Android app')
    watch = actions.add_parser('watch', help='automatically ingest authenticated exports; no radio access')
    watch.add_argument('--inbox', type=Path, help='default: configured bridge.inbox')
    watch.add_argument('--key', type=Path, required=True)
    watch.add_argument('--nonce', required=True, help='expected current Debian challenge')
    watch.add_argument('--once', action='store_true', help='one bounded inbox pass and exit')
    wifi = commands.add_parser('wifi', help='source-scoped Wi-Fi observation intelligence')
    actions = wifi.add_subparsers(dest='wifi_action', required=True)
    scan = actions.add_parser('scan', help='ingest an explicit Android/export file; no direct radio access')
    scan.add_argument('--input', type=Path, required=True, help='Wi-Fi JSONL or finalized .atlas.json export')
    baseline = actions.add_parser('baseline', help='freeze a reviewed training-history snapshot')
    baseline.add_argument('--source', required=True)
    baseline.add_argument('--through', help='inclusive ISO 8601 measurement-time training cutoff')
    baseline.add_argument('--show', action='store_true', help='read the latest saved baseline without changing it')
    anomalies = actions.add_parser('anomalies', help='review fresh post-baseline observations')
    anomalies.add_argument('--source', required=True)
    anomalies.add_argument('--baseline-id', help='saved snapshot id; default latest for this source')
    anomalies.add_argument('--limit', type=int, default=500, help='1..5000 distinct findings; explicit truncation')
    cellular = commands.add_parser('cellular', help='public Android cellular telemetry; no VM modem access')
    actions = cellular.add_subparsers(dest='cellular_action', required=True)
    scan = actions.add_parser('ingest', help='import JSONL or finalized Android export')
    scan.add_argument('--input', type=Path, required=True)
    scan.add_argument('--key', type=Path)
    scan.add_argument('--nonce')
    scan.add_argument('--synthetic', action='store_true', help='explicitly allow labeled synthetic fixtures')
    verify = actions.add_parser('verify', help='verify authenticated challenge response without importing')
    verify.add_argument('--input', type=Path, required=True)
    verify.add_argument('--key', type=Path, required=True)
    verify.add_argument('--nonce', required=True)
    keygen = actions.add_parser('bridge-key', help='create new private shared bridge key; never prints secret')
    keygen.add_argument('--output', type=Path, required=True)
    challenge = actions.add_parser('challenge', help='create new expected Android export challenge')
    challenge.add_argument('--output', type=Path, required=True)
    baseline = actions.add_parser('baseline', help='freeze explicitly reviewed cellular history')
    baseline.add_argument('--source', required=True)
    baseline.add_argument('--through', help='required training cutoff when creating a baseline')
    baseline.add_argument('--show', action='store_true')
    performance = actions.add_parser('performance-request', help='create endpoint-scoped Android Wi-Fi/cellular HTTPS request')
    performance.add_argument('--endpoint', required=True)
    performance.add_argument('--authorized', action='store_true')
    performance.add_argument('--output', type=Path, required=True)
    inspect = actions.add_parser('inspect', help='source-scoped history and deterministic descriptive rules')
    inspect.add_argument('--source', required=True)
    inspect.add_argument('--limit', type=int, default=2000)
    inspect.add_argument('--baseline', action='store_true', help='compare post-training cells to latest reviewed baseline')
    ble = commands.add_parser('ble', help='BLE advertisements and authorized GATT evidence')
    actions = ble.add_subparsers(dest='ble_action', required=True)
    scan = actions.add_parser('scan', help='import explicit Android BLE telemetry; no radio access here')
    scan.add_argument('--input', type=Path, required=True)
    inspect = actions.add_parser('inspect', help='inspect address history or create an authorized GATT request')
    inspect.add_argument('--address', required=True)
    inspect.add_argument('--source', help='exact source required for passive history')
    inspect.add_argument('--limit', type=int, default=100)
    inspect.add_argument('--gatt', action='store_true', help='create a request; requires confirmation in Android')
    inspect.add_argument('--authorized', action='store_true', help='affirm authorization for this exact target and discovery-only scope')
    inspect.add_argument('--output', type=Path, help='new private GATT request file')
    anomalies = actions.add_parser('anomalies', help='read-only BLE analysis; --save explicitly retains findings')
    anomalies.add_argument('--save', action='store_true')
    anomalies.add_argument('--source', required=True)
    anomalies.add_argument('--since', required=True, help='UTC/reference cutoff; earlier history supplies context')
    anomalies.add_argument('--limit', type=int, default=500)
    detect = commands.add_parser('detect', help='deterministic YAML policy detection and retained evidence')
    actions = detect.add_subparsers(dest='detect_action', required=True)
    run = actions.add_parser('run', help='evaluate policy and save anomalies without scanning')
    run.add_argument('--save', action='store_true', help='explicitly persist findings; default is read-only preview')
    run.add_argument('--rules', type=Path, required=True)
    run.add_argument('--at', help='ISO 8601 assessment clock; default current UTC time')
    explain = actions.add_parser('explain', help='read retained rule and observations for a finding')
    explain.add_argument('finding')
    history = actions.add_parser('history', help='read saved anomaly index')
    history.add_argument('--limit', type=int, default=100)
    history.add_argument('--rule-id')
    security = commands.add_parser('security', help='local security checks and explicit retention maintenance')
    actions = security.add_subparsers(dest='security_action', required=True)
    actions.add_parser('isolation', help='test actual user namespaces and offline Bubblewrap profile')
    verify = actions.add_parser('verify', help='read-only evidence verification')
    verify.add_argument('--manifest', type=Path, help='compare with independently retained snapshot')
    seal = actions.add_parser('seal', help='write a new private evidence manifest')
    seal.add_argument('--output', required=True, type=Path)
    retention = actions.add_parser('retention', help='preview expiration; --apply explicitly deletes data')
    retention.add_argument('--apply', action='store_true')
    purge = commands.add_parser('purge', help='explicitly delete old observations and invalidate derived copies')
    purge.add_argument('--before', required=True)
    collect = commands.add_parser('collect', help='legacy host collectors are unavailable under strict offline isolation')
    collect.add_argument('source', choices=('wifi','ble','network'))
    ingest = commands.add_parser('ingest', help='validate and import explicit observation JSONL; no collection')
    ingest.add_argument('file', type=Path)
    history = commands.add_parser('history', help='read existing observation history')
    history.add_argument('--id')
    history.add_argument('--limit', type=int, default=100)
    graph = commands.add_parser('topology', help='read multi-protocol evidence graph')
    graph.add_argument('--limit', type=int, default=2000)
    graph.add_argument('--output', type=Path)
    view = commands.add_parser('dashboard', help='read-only terminal dashboard; no collection')
    view.add_argument('--once', action='store_true', help='print one plain terminal frame without curses')
    view.add_argument('--protocol', choices=('all','wifi','ble','service','cellular'), default='all')
    view.add_argument('--view', choices=('observations','findings'), default='observations')
    ip = commands.add_parser('ip', help='scoped imported evidence analysis or explicit authorized TCP probing')
    actions = ip.add_subparsers(dest='ip_action', required=True)
    analyze = actions.add_parser('analyze', help='read-only scope analysis; does not connect')
    analyze.add_argument('--source', required=True)
    analyze.add_argument('--scope', action='append', required=True)
    analyze.add_argument('--limit', type=int, default=2000)
    probe = actions.add_parser('probe', help='bounded TCP connects; exact scope authorization required')
    probe.add_argument('--authorized', action='store_true')
    probe.add_argument('--scope', action='append', required=True)
    probe.add_argument('--ports', required=True)
    probe.add_argument('--timeout', type=float, default=0.7)
    probe.add_argument('--concurrency', type=int, default=16)
    demo = commands.add_parser('demo', help='controlled synthetic end-to-end demonstration, no scanning or sockets')
    demo.add_argument('--output', type=Path, required=True, help='new private directory; never overwrites')
    demo.add_argument('--events', type=int, default=10000, help='100..50000 synthetic benchmark events')
    return p


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    logger = configure(LoggingConfig())
    previous = {}
    stop = threading.Event()
    try:
        from .core.privilege import enforce_unprivileged
        enforce_unprivileged()
        config = load_config(args.config)
        if args.db is not None:
            from dataclasses import replace
            config = replace(config, storage=replace(config.storage, path=args.db.expanduser().absolute()))
        validate_paths(config)
        if args.command == 'monitor' and not 0 <= args.samples <= 100000:
            raise AtlasError('monitor samples must be between 0 and 100000')
        logger = configure(config.logging)
        application = Application(config)
        event(logger, 'command.started', 'Command started', command=args.command)
        if args.command == 'collect':
            raise AtlasError('host-network/D-Bus collectors require unavailable isolation; import explicit telemetry')
        elif args.command == 'purge':
            from .storage.sqlite import Store
            from .core.events import timestamp
            before=timestamp(args.before)
            if not config.storage.path.exists():
                raise AtlasError('purge requires existing storage')
            store=Store(config.storage.path)
            try: emit(dict(deleted=store.purge(before),derived_copies_invalidated=True))
            finally: store.close()
        elif args.command == 'demo':
            from .demo import demonstrate
            if args.db is not None:
                raise AtlasError('demo uses a new isolated output database; omit --db')
            emit(demonstrate(args.output,args.events))
        elif args.command == 'ingest':
            from .storage.ingest import ingest_file
            from .core.resources import enforce
            enforce(application.resources.sample(config.storage.path),config.monitor)
            emit(ingest_file(config.storage.path,args.file))
        elif args.command in ('history','topology'):
            from .storage.reader import reader
            with reader(config.storage.path) as store:
                rows=store.observations(args.limit,getattr(args,'id',None))
                if args.command=='history':
                    result=rows
                else:
                    from .topology.graph import topology
                    result=topology(rows)
                    result['coverage']=dict(analyzed=len(rows),total=sum(store.stats().values()),limit=args.limit,
                                            truncated=sum(store.stats().values())>len(rows))
            if getattr(args,'output',None):
                write_report(args.output,result,'json')
            else:
                emit(result)
        elif args.command == 'dashboard':
            from .ui.dashboard import dashboard, snapshot
            if args.once:
                print('\n'.join(snapshot(config.storage.path,args.protocol,args.view)['lines']))
            else:
                if not sys.stdin.isatty() or not sys.stdout.isatty():
                    raise AtlasError('dashboard requires a terminal; use --once for a plain frame')
                if args.protocol!='all' or args.view!='observations':
                    raise AtlasError('--protocol/--view select --once snapshots; interactive views use keys')
                dashboard(config.storage.path)
        elif args.command == 'ip':
            if args.ip_action=='analyze':
                from .network.analysis import assess
                emit(assess(config.storage.path,args.source,args.scope,args.limit))
            else:
                if not args.authorized:
                    raise AtlasError('TCP probing requires --authorized and exact scope')
                import asyncio
                from .network.collector import probe
                from .storage.sqlite import Store
                ports=[int(value) for value in args.ports.split(',')]
                rows,result=asyncio.run(probe(args.scope,ports,args.timeout,args.concurrency))
                store=Store(config.storage.path)
                try: result['inserted']=store.add(rows)
                finally: store.close()
                emit(result)
        elif args.command == 'security':
            if args.security_action == 'isolation':
                from .core.isolation import probe
                result = probe()
                emit(result)
                if not result['usable']:
                    return 2
            elif args.security_action == 'retention':
                from .security.retention import retain
                emit(retain(config.storage.path, config.storage.retention_days, args.apply))
            else:
                from .security.evidence import verify
                result = verify(config.storage.path, getattr(args, 'manifest', None))
                if args.security_action == 'seal':
                    write_report(args.output, result, 'json')
                emit(result)
        elif args.command in ('status', 'doctor'):

            emit(getattr(application, args.command)())
        elif args.command == 'report':
            result = application.report(args.format)
            if args.output:
                write_report(args.output, result, args.format)
                emit(dict(event='report.written', path=str(args.output)))
            elif args.format == 'markdown':
                print(result, end='')
            else:
                emit(result)
        elif args.command == 'monitor':
            if threading.current_thread() is threading.main_thread():
                for sig in (signal.SIGINT, signal.SIGTERM):
                    previous[sig] = signal.getsignal(sig)
                    signal.signal(sig, lambda signum, frame: stop.set())
            for sample in application.monitor(1 if args.once else args.samples, stop=stop):
                emit(sample)
        elif args.command == 'bridge':
            if args.bridge_action == 'watch':
                from .bridge.inbox import poll
                from .core.resources import enforce
                if threading.current_thread() is threading.main_thread():
                    for sig in (signal.SIGINT, signal.SIGTERM):
                        previous[sig] = signal.getsignal(sig)
                        signal.signal(sig, lambda signum, frame: stop.set())
                seen = {}
                while not stop.is_set():
                    enforce(application.resources.sample(config.storage.path), config.monitor)
                    result = poll(args.inbox or config.bridge.inbox, config.storage.path,
                                  args.key, args.nonce, seen)
                    emit(result)
                    if args.once:
                        if result['rejected'] or result['transport'] in {'INBOX_UNAVAILABLE', 'INBOX_LIMIT_EXCEEDED'}:
                            return 2
                        break
                    stop.wait(config.monitor.interval_seconds)
            elif args.bridge_action == 'verify':
                emit(read_bundle(args.file, args.key, args.nonce).summary())
            elif args.bridge_action == 'verify-probe':
                emit(verify_probe(args.file, args.nonce))
            else:
                emit(application.import_bridge(args.file, args.key, args.nonce))
        elif args.command == 'wifi':
            from .wifi.intelligence import build_baseline, load_baseline, detect
            from .wifi.ingest import scan_file
            from .storage.reader import reader
            from .storage.sqlite import Store
            from .core.resources import enforce
            enforce(application.resources.sample(config.storage.path), config.monitor)
            if args.wifi_action == 'scan':
                emit(scan_file(config.storage.path, args.input))
            elif args.wifi_action == 'baseline' and not args.show:
                store = Store(config.storage.path)
                try:
                    emit(build_baseline(store, args.source, args.through))
                finally:
                    store.close()
            else:
                if args.wifi_action == 'baseline' and args.through:
                    raise AtlasError('--through cannot be used with --show')
                with reader(config.storage.path) as store:
                    result = load_baseline(store, args.source) if args.wifi_action == 'baseline' else detect(store, args.source, args.baseline_id, args.limit)
                emit(result)
        elif args.command == 'cellular':
            from .cellular.engine import ingest, inspect
            from .core.resources import enforce
            enforce(application.resources.sample(config.storage.path), config.monitor)
            if args.cellular_action == 'ingest':
                emit(ingest(config.storage.path, args.input, args.key, args.nonce, args.synthetic))
            elif args.cellular_action == 'inspect':
                emit(inspect(config.storage.path, args.source, args.limit, args.baseline))
            elif args.cellular_action == 'verify':
                bundle = read_bundle(args.input, args.key, args.nonce)
                if not bundle.authenticated:
                    raise AtlasError('cellular verify requires an authenticated challenge response')
                emit(dict(bundle.summary(), challenge_verified=True,
                          transport_delivery='Operator must confirm the file was exported from the paired Android app; local fixtures do not prove device delivery'))
            elif args.cellular_action in ('bridge-key', 'challenge'):
                from .cellular.transport import generate_key, challenge
                emit((generate_key if args.cellular_action == 'bridge-key' else challenge)(args.output))
            elif args.cellular_action == 'performance-request':
                from .cellular.performance import request
                emit(request(args.endpoint, args.authorized, args.output))
            else:
                from .cellular.baseline import build, load
                from .storage.sqlite import Store
                from .storage.reader import reader
                if args.show:
                    if args.through:
                        raise AtlasError('--through cannot be combined with --show')
                    with reader(config.storage.path) as store:
                        emit(load(store, args.source))
                else:
                    if not args.through:
                        raise AtlasError('creating a cellular baseline requires reviewed --through cutoff')
                    store = Store(config.storage.path)
                    try:
                        emit(build(store, args.source, args.through))
                    finally:
                        store.close()
        elif args.command == 'ble':
            from .bluetooth.engine import scan_file, inspect, analyze_and_store
            from .bluetooth.gatt import request
            from .storage.reader import reader
            from .core.resources import enforce
            enforce(application.resources.sample(config.storage.path), config.monitor)
            if args.ble_action == 'scan':
                emit(scan_file(config.storage.path,args.input))
            elif args.ble_action == 'anomalies':
                if args.save:
                    emit(analyze_and_store(config.storage.path,args.source,args.since,args.limit))
                else:
                    from .bluetooth.engine import analyze
                    with reader(config.storage.path) as store:
                        emit(dict(analyze(store,args.source,args.since,args.limit), evidence_saved=0, preview=True))
            elif args.gatt:
                emit(request(args.address,args.authorized,args.output))
            else:
                if not args.source or args.authorized or args.output:
                    raise AtlasError('passive inspect requires --source; --authorized/--output require --gatt')
                with reader(config.storage.path) as store:
                    emit(inspect(store,args.source,args.address,args.limit))
        elif args.command == 'detect':
            from .detection.engine import run, explain, history
            from .core.resources import enforce
            enforce(application.resources.sample(config.storage.path), config.monitor)
            if args.detect_action == 'run':
                if args.save:
                    emit(run(config.storage.path,args.rules,args.at))
                else:
                    from .detection.engine import evaluate
                    from .detection.policy import load_policy
                    from .core.events import now, timestamp
                    from .storage.reader import reader
                    policy = load_policy(args.rules)
                    at = timestamp(args.at or now())
                    with reader(config.storage.path) as store:
                        findings, coverage = evaluate(store.db, policy, at)
                    emit(dict(findings=findings, coverage=coverage, saved=0, preview=True,
                              evaluated_at=at, policy_sha256=policy['sha256'], confirmed_incidents=0))
            elif args.detect_action == 'explain':
                emit(explain(config.storage.path,args.finding))
            else:
                emit(history(config.storage.path,args.limit,args.rule_id))
        event(logger, 'command.completed', 'Command completed', command=args.command)
        return 0
    except BrokenPipeError:
        return 0
    except ResourceLimitError as exc:
        event(logger, 'resource.limit', str(exc), level=logging.ERROR)
        return 3
    except (AtlasError, OSError, ValueError, sqlite3.Error) as exc:
        event(logger, 'command.failed', 'Command failed; check input schema, paths, permissions and documented limits', level=logging.ERROR, error_type=type(exc).__name__)
        return 2
    except KeyboardInterrupt:
        event(logger, 'command.interrupted', 'Interrupted', level=logging.WARNING)
        return 130
    except Exception as exc:
        # Do not expose imported data, config text or exception payloads on unexpected failures.
        event(logger, 'command.unexpected', 'Unexpected application error', level=logging.ERROR, error_type=type(exc).__name__)
        return 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    raise SystemExit(main())
