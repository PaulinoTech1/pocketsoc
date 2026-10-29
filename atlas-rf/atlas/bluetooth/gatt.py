"""Explicit one-target authorization request; no network, GATT connection or pairing here."""
import datetime as dt
import uuid
from atlas.core.errors import AtlasError
from atlas.core.events import mac
from atlas.ui.console import write_report


def request(address,authorized,output):
    if not authorized:
        raise AtlasError('GATT request requires --authorized for the exact target and enumeration-only scope')
    if output is None:
        raise AtlasError('GATT request requires --output for a new private request file')
    address=mac(address)
    if address in ('00:00:00:00:00:00','ff:ff:ff:ff:ff:ff','02:00:00:00:00:00') or int(address[:2],16)&1:
        raise AtlasError('invalid or redacted target address')
    now=dt.datetime.now(dt.timezone.utc)
    body=dict(kind='atlas-gatt-request',schema_version=1,authorization_id=str(uuid.uuid4()),
              address=address,created_at=now.isoformat().replace('+00:00','Z'),expires_at=(now+dt.timedelta(minutes=15)).isoformat().replace('+00:00','Z'),
              authorized=True,operation='discover_services',writes_allowed=False,pairing_allowed=False)
    write_report(output,body,'json')
    return dict(request=body,output=str(output),connection_performed=False,
                note='Transfer via an approved user-mediated path and confirm in Android. Already-bonded target required; no automatic VM-to-Android channel exists.')
