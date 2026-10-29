"""Operator-started bounded authenticated inbox; no radios, sockets or share writes."""
from itertools import islice
from pathlib import Path
import os
import stat
from atlas.bridge.bundle import read_bundle, BridgeError
from atlas.cellular.transport import key_bytes, AuthenticationError
from atlas.storage.sqlite import Store

MAX_ENTRIES = 1024


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def poll(inbox, database, key_path, nonce, seen):
    """One bounded pass. `seen` is caller-owned and retains only current filenames.

    Invalid/partial content is retried when its stat changes. All files are read
    through the existing bounded, no-follow verifier before storage is opened.
    MAC verification is not Android hardware attestation.
    """
    key_bytes(key_path)  # Fail before polling on an unsafe/missing local key.
    if not isinstance(nonce, str) or len(nonce) != 64 or any(c not in '0123456789abcdef' for c in nonce):
        raise ValueError('expected challenge must be 64 hexadecimal characters')
    result = dict(transport='WAITING_FOR_EXPORT', accepted=0, rejected=0, unchanged=0,
                  inserted=0, measurement_rows=0, hardware_access='UNVERIFIED',
                  collection_performed=False, errors=[])
    inbox = Path(inbox)
    try:
        with os.scandir(inbox) as entries:
            paths = list(islice(entries, MAX_ENTRIES + 1))
    except OSError:
        result['transport'] = 'INBOX_UNAVAILABLE'
        return result
    if len(paths) > MAX_ENTRIES:
        result['transport'] = 'INBOX_LIMIT_EXCEEDED'
        return result
    names = {p.name for p in paths if p.name.endswith('.atlas.json')}
    for old in set(seen) - names:
        del seen[old]
    for entry in sorted(paths, key=lambda p: p.name):
        if entry.name not in names:
            continue
        version = None
        try:
            info = entry.stat(follow_symlinks=False)
            version = stamp(info)
            if seen.get(entry.name) == version:
                result['unchanged'] += 1
                continue
            if not stat.S_ISREG(info.st_mode):
                raise BridgeError('export must be a regular file')
            bundle = read_bundle(inbox/entry.name, key_path, nonce)
            if not bundle.authenticated or bundle.metadata['synthetic']:
                raise BridgeError('automatic inbox requires real-format authenticated envelopes')
            if stamp(os.stat(inbox/entry.name, follow_symlinks=False)) != version:
                raise BridgeError('export changed during verification')
        except (OSError, ValueError, BridgeError) as exc:
            result['rejected'] += 1
            category = ('AUTHENTICATION_FAILED' if isinstance(exc, AuthenticationError) else
                        'EXPORT_READ_FAILED' if isinstance(exc, OSError) else 'INVALID_EXPORT')
            result['errors'].append(dict(category=category,
                                         error_type=type(exc).__name__))
            # Do not expose untrusted filenames, contents or key material in logs.
            if version is not None:
                seen[entry.name] = version
            continue
        store = Store(database)
        try:
            inserted = store.add_radio_bundle(bundle)
        finally:
            store.close()
        result['accepted'] += 1
        result['inserted'] += inserted
        result['measurement_rows'] += sum(o['kind'] == 'cellular' and o['cellular_event'] in {'cell', 'signal'}
                                          and bool({'cell_id', 'pci', 'arfcn', 'lte_rsrp', 'lte_rsrq',
                                                    'lte_rssi', 'lte_rssnr', 'nr_ss_rsrp', 'nr_ss_rsrq',
                                                    'nr_ss_sinr'} & o.keys())
                                          for o in bundle.observations)
        seen[entry.name] = version
    if result['accepted']:
        result['transport'] = 'AUTHENTICATED_EXPORT_INGESTED'
    elif result['rejected']:
        result['transport'] = 'EXPORT_REJECTED'
    return result
