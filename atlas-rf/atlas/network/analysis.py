"""Explicitly scoped, read-only analysis of imported IP evidence."""
from atlas.core.events import validate
from atlas.storage.reader import reader
from atlas.topology.graph import topology
from atlas.detection.rules import analyze
from .collector import targets


def assess(path,source,scopes,limit=2000):
    if not isinstance(source,str) or not source or len(source)>256:
        raise ValueError('exact source required')
    if type(limit) is not int or not 1<=limit<=10000:
        raise ValueError('IP analysis limit must be 1..10000')
    hosts=set(targets(scopes))
    if not hosts:
        raise ValueError('nonempty literal scope required')
    rows=[]
    with reader(path) as store:
        import json
        total=0
        for (body,) in store.db.execute("SELECT body FROM observations WHERE source=? AND kind IN ('neighbor','route','service') ORDER BY observed_at,seq",(source,)):
            o=validate(json.loads(body))
            if o.get('ip',o.get('gateway')) in hosts:
                total+=1
                if len(rows)<limit:
                    rows.append(o)
    return dict(mode='read_only_stored_evidence',source=source,scope=scopes,observations=rows,
                coverage=dict(matched=total,returned=len(rows),truncated=total>limit),
                findings=analyze(rows),topology=topology(rows),network_connections_performed=0,
                note='Supplied reachability evidence is unauthenticated; no live reachability or protocol identity is established.')
