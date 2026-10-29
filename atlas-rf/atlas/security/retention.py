"""Explicit retention maintenance; preview is read-only, derived copies expire too."""
import datetime as dt
from pathlib import Path
from atlas.core.events import now, timestamp
from atlas.storage.reader import reader
from atlas.storage.sqlite import Store

TIMES = {'observations': 'observed_at', 'wifi_baselines': 'created_at', 'cellular_baselines': 'created_at', 'cellular_sessions': 'created_at',
         'ble_findings': 'observed_at', 'detection_findings': 'timestamp'}


def retain(path, days=7, apply=False, at=None):
    if type(days) is not int or not 1 <= days <= 3650:
        raise ValueError('retention days must be 1..3650')
    if not Path(path).exists():
        raise ValueError('retention requires an existing observation database')
    clock = dt.datetime.fromisoformat(timestamp(at or now()))
    before = (clock - dt.timedelta(days=days)).isoformat(timespec='microseconds')
    store = Store(path) if apply else None
    context = None if apply else reader(path)
    if context:
        store = context.__enter__()
    try:
        db = store.db
        if apply:
            db.execute('PRAGMA secure_delete=ON')
            db.execute('BEGIN IMMEDIATE')
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        counts = {}
        expired = db.execute('SELECT COUNT(*) FROM observations WHERE observed_at < ?', (before,)).fetchone()[0]
        for name, column in TIMES.items():
            if name not in tables:
                continue
            # Derived evidence embeds old observations; invalidate all copies if raw evidence expires.
            where, args = ('', ()) if name != 'observations' and expired else (f' WHERE {column} < ?', (before,))
            counts[name] = db.execute(f'SELECT COUNT(*) FROM {name}' + where, args).fetchone()[0]
            if apply:
                db.execute(f'DELETE FROM {name}' + where, args)
        if apply:
            db.commit()
            db.execute('VACUUM')
        return dict(applied=apply, retention_days=days, before=before, rows=counts,
                    derived_policy='invalidate all derived copies when any raw evidence expires',
                    note='Explicit maintenance only. Exported files, logs, backups, filesystem snapshots and physical flash erasure are outside this operation.')
    except BaseException:
        if apply:
            store.db.rollback()
        raise
    finally:
        if context:
            context.__exit__(None, None, None)
        elif store:
            store.close()
