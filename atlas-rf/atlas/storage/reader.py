"""Read-only access to existing v1 observation databases; never initializes one."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from .sqlite import Store
from atlas.core.errors import StorageError


class ReadStore(Store):
    def __init__(self, path):
        self.path = Path(path).expanduser().absolute()
        if self.path.is_symlink():
            raise StorageError('database symlinks are unsupported')
        self.db = sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True, timeout=1)
        try:
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('PRAGMA query_only=ON')
            self.db.execute('PRAGMA cache_size=-4096')
            self.db.execute('BEGIN')
            if self.db.execute('PRAGMA user_version').fetchone()[0] != 1:
                raise StorageError('database schema must be version 1')
            self.db.execute('SELECT kind,identity,observed_at,source,body FROM observations LIMIT 0')
        except BaseException:
            self.db.close()
            raise


@contextmanager
def reader(path):
    store = ReadStore(path)
    try:
        yield store
    finally:
        store.close()


def database_status(path):
    path = Path(path).expanduser()
    if path.is_symlink():
        raise StorageError('database symlinks are unsupported')
    if not path.exists():
        return dict(state='uninitialized', path=str(path), observations=0, counts={})
    with reader(path) as store:
        stats = store.stats()
        latest = store.db.execute('SELECT MAX(observed_at) FROM observations').fetchone()[0]
    return dict(state='ready', path=str(path), schema_version=1, observations=sum(stats.values()), counts=stats,
                latest_observed_at=latest, file_bytes=path.stat().st_size)
