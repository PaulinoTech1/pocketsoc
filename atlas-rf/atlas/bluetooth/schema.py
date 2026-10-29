"""Bounded BLE evidence contracts; identifiers refer to observed addresses, not devices."""
import re
import uuid

BLE_FIELDS = {'advertisement_hex', 'service_uuids', 'manufacturer_data', 'connectable',
              'advertisement_complete', 'evidence_confidence'}
GATT_FIELDS = {'gatt_services', 'gatt_status', 'authorization_id', 'operation', 'writes_performed', 'pairing_initiated'}
GATT_STATUSES = {'complete', 'failed', 'timeout', 'cancelled', 'permission_denied', 'not_bonded',
                 'authentication_required', 'unavailable', 'truncated'}


def normalize_uuid(value):
    if not isinstance(value, str):
        raise ValueError('service UUID must be a string')
    value = value.lower()
    if re.fullmatch('[0-9a-f]{4}',value):
        value = '0000'+value+'-0000-1000-8000-00805f9b34fb'
    elif re.fullmatch('[0-9a-f]{8}',value):
        value += '-0000-1000-8000-00805f9b34fb'
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise ValueError('invalid BLE UUID') from exc


def hex_bytes(value, maximum):
    if not isinstance(value, str) or len(value) % 2 or len(value) > maximum*2 or not re.fullmatch('[0-9a-fA-F]*',value):
        raise ValueError('BLE bytes must be bounded, even-length hexadecimal')
    return value.lower()


def validate_ble(o):
    if 'evidence_confidence' in o and o['evidence_confidence'] not in ('reported','synthetic','unknown'):
        raise ValueError('evidence_confidence must be reported, synthetic or unknown')
    for field in ('connectable','advertisement_complete'):
        if field in o and type(o[field]) is not bool:
            raise ValueError(f'{field} must be boolean')
    if 'advertisement_hex' in o:
        o['advertisement_hex'] = hex_bytes(o['advertisement_hex'],1650)
    if 'service_uuids' in o:
        values=o['service_uuids']
        if not isinstance(values,list) or len(values)>64:
            raise ValueError('service_uuids must be a list of at most 64 UUIDs')
        o['service_uuids']=sorted({normalize_uuid(v) for v in values})
    if 'manufacturer_data' in o:
        values=o['manufacturer_data']
        if not isinstance(values,dict) or len(values)>16:
            raise ValueError('manufacturer_data must have at most 16 company IDs')
        normalized={}
        for key,value in values.items():
            if not isinstance(key,str) or not re.fullmatch(r'0|[1-9][0-9]{0,4}',key) or int(key)>65535:
                raise ValueError('manufacturer company IDs must be decimal strings 0..65535')
            normalized[key]=hex_bytes(value,256)
        o['manufacturer_data']=normalized
    if o['kind']=='ble':
        if GATT_FIELDS & set(o):
            raise ValueError('GATT fields require ble_gatt kind')
        return
    if (BLE_FIELDS-{'evidence_confidence'}) & set(o):
        raise ValueError('advertisement fields do not describe GATT discovery')
    if o.get('operation')!='discover_services' or o.get('writes_performed') is not False or o.get('pairing_initiated') is not False:
        raise ValueError('GATT evidence must attest enumeration only, no writes and no pairing')
    try:
        o['authorization_id']=str(uuid.UUID(o['authorization_id']))
    except (KeyError,ValueError,TypeError,AttributeError) as exc:
        raise ValueError('GATT evidence requires a UUID authorization_id') from exc
    if not isinstance(o.get('gatt_status'),str) or o['gatt_status'] not in GATT_STATUSES:
        raise ValueError('invalid gatt_status')
    if o['gatt_status'] == 'complete' and 'gatt_services' not in o:
        raise ValueError('complete GATT discovery requires an explicit gatt_services list')
    services=o.get('gatt_services',[])
    if not isinstance(services,list) or len(services)>64:
        raise ValueError('gatt_services must be a list of at most 64 services')
    normalized=[]
    count=0
    for service in services:
        if not isinstance(service,dict) or set(service)!={'uuid','characteristics'} or not isinstance(service['characteristics'],list):
            raise ValueError('GATT services require uuid and characteristics list')
        chars=[]
        for char in service['characteristics']:
            count+=1
            if count>128 or not isinstance(char,dict) or set(char)!={'uuid','properties'}:
                raise ValueError('GATT characteristics require uuid/properties; maximum 128 total')
            if type(char['properties']) is not int or not 0<=char['properties']<=255:
                raise ValueError('GATT properties must be an integer 0..255')
            chars.append(dict(uuid=normalize_uuid(char['uuid']),properties=char['properties']))
        normalized.append(dict(uuid=normalize_uuid(service['uuid']),characteristics=sorted(chars,key=lambda c:(c['uuid'],c['properties']))))
    o['gatt_services']=sorted(normalized,key=lambda s:(s['uuid'],str(s['characteristics'])))
