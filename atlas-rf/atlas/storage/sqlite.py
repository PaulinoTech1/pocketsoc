"""Private, transactional SQLite observation history."""
import json
import os
from pathlib import Path
import sqlite3
import stat
from atlas.core.events import MAX_LINE, encoded, fingerprint, validate

MAX_IMPORT = 32 * 1024 * 1024
MAX_ROWS = 50_000


class Store:
    def __init__(self, path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise ValueError("database symlinks are not supported")
        parent = self.path.parent.stat()
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise ValueError('database parent must be owned and not group/world writable')
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                raise ValueError('database must be an owned regular file with one link')
            if info.st_size > 256 * 1024 * 1024:
                raise ValueError('database exceeds 256 MiB size budget')
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        for suffix in ('-journal', '-wal', '-shm'):
            sidecar = Path(str(self.path) + suffix)
            if sidecar.is_symlink() or (sidecar.exists() and (not sidecar.is_file() or sidecar.stat().st_nlink != 1)):
                raise ValueError('unsafe SQLite sidecar')
        self.db = sqlite3.connect(self.path)
        self.db.execute('PRAGMA trusted_schema=OFF')
        self.db.execute('PRAGMA busy_timeout=1000')
        page_size = self.db.execute('PRAGMA page_size').fetchone()[0]
        self.db.execute(f'PRAGMA max_page_count={256 * 1024 * 1024 // page_size}')
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1):
            self.db.close()
            raise ValueError(f"unsupported database schema {version}")
        self.db.executescript("""
            PRAGMA journal_mode=DELETE;
            PRAGMA cache_size=-4096;
            CREATE TABLE IF NOT EXISTS observations (
                seq INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL,
                kind TEXT NOT NULL, identity TEXT NOT NULL, observed_at TEXT NOT NULL,
                source TEXT NOT NULL, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS history ON observations(kind,identity,observed_at);
            CREATE INDEX IF NOT EXISTS chronological ON observations(observed_at);
            PRAGMA user_version=1;
        """)

    def close(self):
        self.db.close()

    def add(self, observations):
        count = 0
        with self.db:
            for number, raw in enumerate(observations, 1):
                if number > MAX_ROWS:
                    raise ValueError('batch exceeds 50000 observations')
                o = validate(raw)
                if len(encoded(o).encode()) > MAX_LINE:
                    raise ValueError('observation exceeds 16 KiB')
                cur = self.db.execute("INSERT OR IGNORE INTO observations(fingerprint,kind,identity,observed_at,source,body) VALUES(?,?,?,?,?,?)",
                                      (fingerprint(o), o["kind"], o["id"], o["observed_at"], o["source"], encoded(o)))
                count += cur.rowcount
            if self.db.execute('SELECT COUNT(*) FROM observations').fetchone()[0] > 200_000:
                raise ValueError('database exceeds 200000 observations; apply retention maintenance')
        return count

    def add_radio_bundle(self, bundle):
        """Retain cellular availability/drop metadata alongside the canonical observations."""
        import hashlib
        from atlas.core.events import now
        cells = [o for o in bundle.observations if o['kind'] == 'cellular']
        from atlas.bridge.bundle import has_cellular_session
        cellular_session = has_cellular_session(bundle.metadata, bundle.observations)
        if not cellular_session:
            return self.add(bundle.observations)
        metadata = {k: bundle.metadata[k] for k in ('session_id', 'synthetic', 'statuses', 'drops',
                    'rows', 'bytes', 'clock_wall_ms', 'clock_elapsed_ns', 'queue_capacity', 'app_version',
                    'bridge_nonce') if k in bundle.metadata}
        sources = sorted({o['source'] for o in cells})
        source = sources[0] if len(sources) == 1 else ('synthetic:' if bundle.metadata['synthetic'] else 'android:') + 'cellular-session'
        if not sources and 'sensor_id' in bundle.metadata:
            import uuid
            try:
                sensor = str(uuid.UUID(bundle.metadata['sensor_id']))
                source = ('synthetic:' if bundle.metadata['synthetic'] else 'android:') + sensor + ':cellular'
            except (ValueError, TypeError, AttributeError):
                pass
        value = dict(source=source, sources=sources, metadata=metadata, payload_sha256=bundle.digest,
                     authenticated=bundle.authenticated, created_at=now())
        # Replay key excludes local import time; importing the same export cannot duplicate metadata.
        identity = dict(value); identity.pop('created_at')
        value['id'] = hashlib.sha256(encoded(identity).encode()).hexdigest()
        self.db.execute('CREATE TABLE IF NOT EXISTS cellular_sessions (id TEXT PRIMARY KEY, source TEXT NOT NULL, created_at TEXT NOT NULL, body TEXT NOT NULL)')
        try:
            self.db.execute('INSERT OR IGNORE INTO cellular_sessions VALUES(?,?,?,?)',
                            (value['id'], source, value['created_at'], encoded(value)))
            # add() commits the metadata and all events together or rolls both back.
            return self.add(bundle.observations)
        except BaseException:
            self.db.rollback()
            raise

    def ingest(self, path):
        def rows():
            total = 0
            count = 0
            from atlas.bridge.bundle import parse
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError('import requires a regular file')
                while True:
                    line = stream.readline(MAX_LINE + 1)
                    if not line:
                        break
                    total += len(line)
                    count += 1
                    if len(line) > MAX_LINE or total > MAX_IMPORT or count > MAX_ROWS:
                        raise ValueError("import limit exceeded (16 KiB line, 32 MiB file, 50000 lines)")
                    if not line.strip():
                        continue
                    try:
                        row = validate(parse(line))
                        if row['kind'] == 'cellular' and not row['source'].startswith('synthetic:'):
                            raise ValueError('real cellular imports require authenticated cellular ingest')
                        yield row
                    except (ValueError, UnicodeError, RecursionError) as exc:
                        raise ValueError(f"invalid observation at line {count}") from exc
        return self.add(rows())

    def observations(self, limit=10000, identity=None):
        if type(limit) is not int or not 1 <= limit <= 50000:
            raise ValueError('history limit must be 1..50000')
        where, args = ("WHERE identity=?", [identity]) if identity else ("", [])
        rows = self.db.execute(f"SELECT body FROM observations {where} ORDER BY observed_at DESC, seq DESC LIMIT ?", args + [limit]).fetchall()
        return [json.loads(r[0]) for r in reversed(rows)]

    def stats(self):
        return dict(self.db.execute("SELECT kind,COUNT(*) FROM observations GROUP BY kind"))

    def purge(self, before):
        from atlas.core.events import timestamp
        before = timestamp(before)
        with self.db:
            self.db.execute("PRAGMA secure_delete=ON")
            count = self.db.execute("DELETE FROM observations WHERE observed_at < ?", (before,)).rowcount
            if count:
                tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                for table in ('wifi_baselines', 'ble_findings', 'detection_findings', 'cellular_baselines', 'cellular_sessions'):
                    if table in tables:
                        self.db.execute(f'DELETE FROM {table}')
        self.db.execute("VACUUM")
        return count
