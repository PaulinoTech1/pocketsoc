"""Explicit endpoint-scoped Android test request; Debian never substitutes a VM probe."""
import datetime as dt
import uuid
from urllib.parse import urlsplit
from atlas.core.events import now
from atlas.ui.console import write_report


def request(endpoint, authorized, output):
    url = urlsplit(endpoint)
    if not authorized or url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment or len(endpoint) > 256:
        raise ValueError('explicit authorization and HTTPS endpoint without credentials/query/fragment required')
    value = dict(kind='atlas-cellular-performance-request', schema_version=1, test_id=str(uuid.uuid4()),
                 endpoint=endpoint, authorized=True, max_bytes=65536, timeout_ms=5000,
                 created_at=now(), expires_at=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=10)).isoformat())
    write_report(output, value, 'json')
    return value
