"""Synchronous orchestration with bounded history and resource snapshots."""
from dataclasses import asdict
import time
from atlas import __version__
from atlas.bridge.importer import status as bridge_status
from atlas.reporting.reports import report, markdown
from atlas.storage.reader import database_status, reader
from atlas.storage.sqlite import Store
from atlas.bridge.bundle import read_bundle
from .diagnostics import capabilities, diagnose
from .events import now
from .resources import ResourceMonitor, enforce


class Application:
    def __init__(self, config):
        self.config = config
        self.resources = ResourceMonitor()

    def status(self):
        return dict(schema_version=1, project='ATLAS RF', version=__version__, timestamp=now(),
                    database=database_status(self.config.storage.path),
                    resources=self.resources.sample(self.config.storage.path),
                    bridge=bridge_status(self.config.bridge.inbox),
                    limits=asdict(self.config.monitor),
                    note='Local state only; no collectors or Android API sessions started.')

    def doctor(self):
        return dict(schema_version=1, project='ATLAS RF', timestamp=now(),
                    checks=diagnose(self.config), resources=self.resources.sample(self.config.storage.path))

    def monitor(self, samples=0, stop=None):
        count = 0
        while not stop or not stop.is_set():
            snapshot = self.resources.sample(self.config.storage.path)
            enforce(snapshot, self.config.monitor)
            yield dict(schema_version=1, timestamp=now(), event='resource.snapshot', data=snapshot)
            count += 1
            if samples and count >= samples:
                break
            if stop:
                if stop.wait(self.config.monitor.interval_seconds):
                    break
            else:
                time.sleep(self.config.monitor.interval_seconds)

    def report(self, format='json'):
        enforce(self.resources.sample(self.config.storage.path), self.config.monitor)
        # Read-only open: a missing or incompatible DB is an actionable error, not an empty assessment.
        with reader(self.config.storage.path) as store:
            result = report(store, self.config.storage.report_limit)
        enforce(self.resources.sample(self.config.storage.path), self.config.monitor)
        return markdown(result) if format == 'markdown' else result

    def import_bridge(self, path, key_path=None, nonce=None):
        enforce(self.resources.sample(self.config.storage.path), self.config.monitor)
        bundle = read_bundle(path, key_path, nonce)
        enforce(self.resources.sample(self.config.storage.path), self.config.monitor)
        store = Store(self.config.storage.path)
        try:
            inserted = store.add_radio_bundle(bundle)
        finally:
            store.close()
        return dict(bundle.summary(), inserted=inserted)
