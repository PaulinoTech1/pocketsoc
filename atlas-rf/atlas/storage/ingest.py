"""Validate an explicit bounded observation file before opening writable storage."""
from atlas.bridge.bundle import read_limited, parse
from atlas.core.events import MAX_LINE, validate
from .sqlite import Store, MAX_IMPORT, MAX_ROWS


def ingest_file(database, path):
    rows=[]
    for number,line in enumerate(read_limited(path,MAX_IMPORT).splitlines(),1):
        if number>MAX_ROWS or len(line)+1>MAX_LINE:
            raise ValueError('observation import limit exceeded')
        if line.strip():
            row = validate(parse(line))
            if row['kind'] == 'cellular' and not row['source'].startswith('synthetic:'):
                raise ValueError('real cellular imports require authenticated cellular ingest')
            rows.append(row)
    store=Store(database)
    try:
        inserted=store.add(rows)
    finally:
        store.close()
    return dict(observations=len(rows),inserted=inserted,replayed=len(rows)-inserted,
                collection_performed=False,sources=sorted({r['source'] for r in rows}))
