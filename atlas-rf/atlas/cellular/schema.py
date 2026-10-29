"""Flat, bounded Android cellular contract. Omission means unavailable, never zero."""
import re
import datetime as dt

RANGES = {
    'duration_ms': (0, 60000), 'bytes_received': (0, 65536), 'http_status': (100, 599),
    'subscription_id': (0, 2147483646), 'slot_index': (0, 7), 'sim_state': (0, 11),
    'network_type': (0, 20), 'display_override': (0, 10), 'service_state': (0, 3),
    'data_state': (-1, 5), 'cell_id': (0, 68719476735), 'pci': (0, 1007),
    'tac': (0, 16777215), 'arfcn': (0, 3279165), 'cell_age_ms': (0, 2**53-1),
    'measurement_elapsed_ms': (1, 2**53-1),
    'lte_rsrp': (-140, -43), 'lte_rsrq': (-34, 3), 'lte_rssi': (-113, -51),
    'lte_rssnr': (-20, 30), 'nr_ss_rsrp': (-156, -31),
    'nr_ss_rsrq': (-43, 20), 'nr_ss_sinr': (-23, 40),
}
ENUMS = {
    'subscription_scope': {'default_radio'},
    'cellular_event': {'cell', 'signal', 'subscription', 'service', 'technology', 'connectivity', 'performance'},
    'technology': {'LTE', 'NR', 'OTHER', 'UNKNOWN'},
    'cell_freshness': {'recent', 'cached', 'unknown'},
    'cell_origin': {'cached_read', 'update', 'callback'},
    'connection_status': {'primary', 'secondary', 'none', 'unknown'},
    'subscription_status': {'active', 'inactive'},
    'test_transport': {'wifi', 'cellular'},
    'test_status': {'success', 'failed', 'unavailable', 'cancelled'},
    'default_transport': {'cellular', 'wifi', 'vpn', 'other', 'none'},
}
STRINGS = {'carrier', 'mcc', 'mnc', 'collection_session', 'received_at', 'test_id', 'test_endpoint', 'test_failure'}
BOOLEANS = {'registered', 'roaming', 'network_validated', 'cellular_available', 'bound_network', 'authorized'}
CELLULAR_FIELDS = set(RANGES) | set(ENUMS) | STRINGS | BOOLEANS | {'bands'}
LTE = {k for k in RANGES if k.startswith('lte_')}
NR = {k for k in RANGES if k.startswith('nr_')}
IDENTITY = {'cell_id', 'pci', 'tac', 'arfcn', 'bands', 'mcc', 'mnc', 'registered', 'connection_status'}


def validate_cellular(o):
    if not {'cellular_event', 'collection_session', 'cell_freshness'} <= o.keys():
        raise ValueError('cellular event, session and freshness are required')
    for key in CELLULAR_FIELDS & o.keys():
        value = o[key]
        if key in RANGES:
            low, high = RANGES[key]
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f'invalid {key}')
        elif key in ENUMS:
            if not isinstance(value, str) or value not in ENUMS[key]:
                raise ValueError(f'invalid {key}')
        elif key in BOOLEANS:
            if type(value) is not bool:
                raise ValueError(f'invalid {key}')
        elif key in STRINGS:
            if not isinstance(value, str) or not 1 <= len(value) <= 256:
                raise ValueError(f'invalid {key}')
        elif key == 'bands':
            if not isinstance(value, list) or len(value) > 64 or any(type(b) is not int or not 1 <= b <= 1024 for b in value) or len(set(value)) != len(value):
                raise ValueError('invalid bands')
    for key, pattern in (('mcc', r'\d{3}'), ('mnc', r'\d{2,3}')):
        if key in o and not re.fullmatch(pattern, o[key], re.ASCII):
            raise ValueError(f'invalid {key}')
    event = o['cellular_event']
    default_radio = o.get('subscription_scope') == 'default_radio'
    if default_radio and ('subscription_id' in o or event not in {'cell', 'signal', 'service', 'technology'}):
        raise ValueError('default radio scope cannot claim a subscription')
    if event not in {'connectivity', 'performance'} and 'subscription_id' not in o and not default_radio:
        raise ValueError('telephony events require a subscription scope')
    if event in {'cell', 'signal'} and o.get('technology') not in {'LTE', 'NR'}:
        raise ValueError('cell/signal requires LTE or NR')
    if IDENTITY & o.keys() and event != 'cell':
        raise ValueError('cell identity fields require cell events')
    if (LTE | NR) & o.keys() and event not in {'cell', 'signal'}:
        raise ValueError('signal fields require cell/signal events')
    if (LTE & o.keys() and o.get('technology') != 'LTE') or (NR & o.keys() and o.get('technology') != 'NR'):
        raise ValueError('signal metric technology mismatch')
    if o.get('technology') == 'LTE':
        for key, maximum in (('cell_id', 268435455), ('pci', 503), ('tac', 65535), ('arfcn', 262143)):
            if key in o and o[key] > maximum:
                raise ValueError(f'invalid LTE {key}')
    if event == 'cell':
        if o.get('registered') is False and o.get('connection_status') in {'primary', 'secondary'}:
            raise ValueError('nonregistered cell cannot claim serving connection')
        if 'cell_origin' not in o:
            raise ValueError('cell requires origin')
        freshness = o['cell_freshness']
        if ('cell_age_ms' in o) != ('measurement_elapsed_ms' in o):
            raise ValueError('measurement time and age must be supplied together')
        age = o.get('cell_age_ms')
        if freshness != 'unknown' and ('measurement_elapsed_ms' not in o or age is None):
            raise ValueError('known freshness requires measurement time and age')
        if freshness == 'unknown' and age is not None:
            raise ValueError('known age requires recent/cached classification')
        if freshness == 'recent' and (age > 10000 or o['cell_origin'] == 'cached_read'):
            raise ValueError('cached/old measurements cannot be recent')
        if freshness == 'cached' and age is not None and age <= 10000 and o['cell_origin'] != 'cached_read':
            raise ValueError('inconsistent cached classification')
    elif o['cell_freshness'] != 'unknown' or {'cell_age_ms', 'measurement_elapsed_ms', 'cell_origin'} & o.keys():
        raise ValueError('callbacks without modem timestamps have unknown freshness')

    specific = {
        'subscription': {'subscription_status', 'slot_index', 'carrier', 'sim_state'},
        'service': {'service_state', 'roaming'},
        'technology': {'network_type', 'display_override', 'data_state'},
        'connectivity': {'default_transport', 'network_validated', 'cellular_available'},
    }
    for owner, fields in specific.items():
        if owner != event and fields & o.keys():
            raise ValueError(f'{owner} fields require corresponding event type')
    if {'rssi', 'security', 'ip', 'mac', 'interface', 'gateway', 'port'} & o.keys():
        raise ValueError('cellular uses explicit metric fields, not Wi-Fi/IP fields')

    if 'received_at' in o:
        from atlas.core.events import timestamp
        o['received_at'] = timestamp(o['received_at'])
        if o['received_at'] < o['observed_at']:
            raise ValueError('measurement timestamp cannot follow receipt')
        if 'cell_age_ms' in o:
            age = (dt.datetime.fromisoformat(o['received_at']) - dt.datetime.fromisoformat(o['observed_at'])).total_seconds()*1000
            if abs(age - o['cell_age_ms']) > 2:
                raise ValueError('cell age conflicts with original measurement/receipt times')
    performance = {'test_transport', 'test_status', 'test_id', 'test_endpoint', 'test_failure',
                   'duration_ms', 'bytes_received', 'http_status', 'bound_network', 'authorized'}
    if event == 'performance':
        if not {'test_transport', 'test_status', 'test_id', 'test_endpoint', 'bound_network', 'authorized'} <= o.keys():
            raise ValueError('performance event lacks attribution/authorization')
        if o['authorized'] is not True:
            raise ValueError('performance tests require authorization')
        from urllib.parse import urlsplit
        url = urlsplit(o['test_endpoint'])
        if url.scheme != 'https' or not url.hostname or url.username or url.password or url.fragment or url.query:
            raise ValueError('test endpoint must be HTTPS without credentials/query/fragment')
        if o['test_status'] == 'success' and (o['bound_network'] is not True or not {'duration_ms', 'bytes_received', 'http_status'} <= o.keys() or not 200 <= o['http_status'] < 300):
            raise ValueError('success requires bound network and measured response')
    elif performance & o.keys():
        raise ValueError('performance fields require performance event')
