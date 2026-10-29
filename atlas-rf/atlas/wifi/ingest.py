"""Explicit file ingestion; this does not call Android radio APIs from Debian."""
from collections import Counter
from pathlib import Path
from atlas.bridge.bundle import MAX_PAYLOAD, MAX_EVENTS, parse, read_bundle, read_limited
from atlas.core.errors import AtlasError
from atlas.core.events import MAX_LINE, validate
from atlas.storage.sqlite import Store
from .schema import band, eligibility


def scan_file(database, path):
    path = Path(path)
    transport = 'jsonl'
    if path.name.endswith('.atlas.json'):
        bundle = read_bundle(path)
        observations = [o for o in bundle.observations if o['kind'] == 'wifi']
        transport = 'finalized-bundle'
    else:
        data = read_limited(path, MAX_PAYLOAD)
        observations = []
        for number, line in enumerate(data.splitlines(), 1):
            if number > MAX_EVENTS or len(line) + 1 > MAX_LINE:
                raise AtlasError('Wi-Fi input exceeds 10000 lines or 16 KiB per line')
            if not line.strip():
                continue
            try:
                o = validate(parse(line))
            except (ValueError, TypeError, OverflowError) as exc:
                raise AtlasError(f'Wi-Fi input line {number} is invalid') from exc
            if o['kind'] != 'wifi':
                raise AtlasError('standalone wifi scan JSONL must contain only wifi records')
            observations.append(o)
    store = Store(database)
    try:
        inserted = store.add(observations)
    finally:
        store.close()
    return dict(mode='import', transport=transport, radio_scan_performed=False,
                observations=len(observations), inserted=inserted,
                sources=sorted({o['source'] for o in observations}),
                freshness=dict(Counter(eligibility(o) for o in observations)),
                bands=dict(Counter(band(o.get('frequency_mhz')) for o in observations)),
                note='Measurements came from the explicit input file; missing fields are not synthesized. No Android radio was accessed by Debian.')
