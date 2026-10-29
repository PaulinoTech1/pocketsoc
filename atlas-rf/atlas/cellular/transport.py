"""HMAC file transport. No assumption about Android/VM networking or shared localhost."""
import hashlib
import hmac
import os
import stat
import re
import secrets
from atlas.bridge.bundle import read_limited, parse
from atlas.ui.console import write_report

DOMAIN = b'ATLAS-RF authenticated export v1\n'


def key_bytes(path):
    # Keys must remain in owned private storage, never the shared export directory.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError('bridge key must be an owned private regular file (0600)')
        raw = stream.read(66).strip()
    if len(raw) != 64:
        raise ValueError('bridge key must contain 64 hexadecimal characters')
    try:
        return bytes.fromhex(raw.decode('ascii'))
    except (UnicodeError, ValueError) as exc:
        raise ValueError('invalid bridge key') from exc


def generate_key(path):
    write_report(path, secrets.token_hex(32) + '\n', 'markdown')
    return dict(key_created=True, secret_displayed=False,
                instruction='Import this key into the Android companion through a trusted document transfer; delete transfer copies. Keep the Debian key private.')


def challenge(path):
    value = dict(kind='atlas-cellular-challenge', schema_version=1, nonce=secrets.token_hex(32))
    write_report(path, value, 'json')
    return value


def unwrap(doc, key_path, nonce):
    if set(doc) != {'kind', 'schema_version', 'signed_json', 'hmac_sha256'} or type(doc.get('schema_version')) is not int or doc.get('schema_version') != 1:
        raise ValueError('invalid authenticated envelope')
    signed = doc.get('signed_json')
    claimed = doc.get('hmac_sha256')
    if not isinstance(signed, str) or not isinstance(claimed, str) or not re.fullmatch('[0-9a-f]{64}', claimed):
        raise ValueError('invalid authentication fields')
    if key_path is None or not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{64}', nonce):
        raise ValueError('authenticated export requires private --key and expected --nonce')
    digest = hmac.new(key_bytes(key_path), DOMAIN + signed.encode('utf-8'), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(digest, claimed):
        raise ValueError('export authentication failed')
    inner = parse(signed)
    if not isinstance(inner, dict) or not isinstance(inner.get('metadata'), dict) or inner['metadata'].get('bridge_nonce') != nonce:
        raise ValueError('export does not answer expected challenge')
    return inner
