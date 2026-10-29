"""Strict bounded YAML policies. Rules select fixed predicates, never executable expressions."""
import hashlib
import ipaddress
import re
import yaml
from atlas.bluetooth.schema import normalize_uuid
from atlas.core.config import mapping, integer
from atlas.core.errors import ConfigurationError
from atlas.core.events import encoded, mac

TYPES = {'ap-security-downgrade', 'unrecognized-bssid', 'ble-service-change',
         'unknown-management-interface', 'unexpected-network-exposure'}
COMMON = {'id','type','enabled','severity','confidence','sources','investigation',
          'min_observations','window_seconds','max_age_seconds','cooldown_seconds'}
PARAMETERS = {
    'ap-security-downgrade': {'ssid','expected_security'},
    'unrecognized-bssid': {'ssid','approved_bssids'},
    'ble-service-change': {'address','expected_services','evidence_kind'},
    'unknown-management-interface': {'ports','allowed_networks'},
    'unexpected-network-exposure': {'allowed_networks','allowed_ports'},
}
DEFAULTS = dict(min_observations=2, window_seconds=300, max_age_seconds=300, cooldown_seconds=3600)


def strings(value, name, maximum=256):
    if not isinstance(value,list) or not value or len(value)>256 or any(not isinstance(v,str) or not v or len(v)>maximum for v in value):
        raise ConfigurationError(f'{name} requires 1..256 nonempty strings')
    return sorted(set(value))


def load_policy(path):
    from atlas.bridge.bundle import BridgeError, read_limited
    try:
        raw = read_limited(path, 65536)
    except (OSError, BridgeError) as exc:
        raise ConfigurationError('detection policy requires a regular non-symlink file of at most 64 KiB') from exc
    if not raw or len(raw)>65536:
        raise ConfigurationError('detection policy must be nonempty and at most 64 KiB')
    try:
        depth=0
        for n,token in enumerate(yaml.scan(raw),1):
            if n>10000 or isinstance(token,(yaml.tokens.AliasToken,yaml.tokens.AnchorToken,yaml.tokens.TagToken)):
                raise ConfigurationError('detection YAML token bound exceeded or unsupported alias/tag')
            if isinstance(token,(yaml.tokens.BlockMappingStartToken,yaml.tokens.BlockSequenceStartToken,yaml.tokens.FlowMappingStartToken,yaml.tokens.FlowSequenceStartToken)):
                depth+=1
            if isinstance(token,(yaml.tokens.BlockEndToken,yaml.tokens.FlowMappingEndToken,yaml.tokens.FlowSequenceEndToken)):
                depth-=1
            if depth>8:
                raise ConfigurationError('detection YAML nesting exceeds eight levels')
        class Loader(yaml.SafeLoader):
            pass
        def pairs(loader,node):
            result={}
            for key_node,value_node in node.value:
                key=loader.construct_object(key_node)
                if not isinstance(key,str) or key in result:
                    raise ConfigurationError('detection YAML keys must be unique strings')
                result[key]=loader.construct_object(value_node)
            return result
        Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,pairs)
        root=mapping(yaml.load(raw,Loader=Loader),{'version','defaults','rules'},'detection policy')
    except (yaml.YAMLError,ValueError,RecursionError) as exc:
        raise ConfigurationError('invalid detection YAML') from exc
    if type(root.get('version')) is not int or root['version']!=1:
        raise ConfigurationError('detection policy version must be 1')
    defaults=mapping(root.get('defaults',{}),DEFAULTS,'detection defaults')
    defaults={k:integer(defaults.get(k,v),1 if k!='cooldown_seconds' else 0,20 if k=='min_observations' else 86400,k) for k,v in DEFAULTS.items()}
    rules=root.get('rules')
    if not isinstance(rules,list) or not 1<=len(rules)<=64:
        raise ConfigurationError('detection policy requires 1..64 rules')
    normalized=[]
    ids=set()
    for value in rules:
        if not isinstance(value,dict) or not isinstance(value.get('type'),str) or value['type'] not in TYPES:
            raise ConfigurationError('unknown detection rule type')
        kind=value['type']
        r=dict(mapping(value,COMMON|PARAMETERS[kind],'detection rule'))
        identity=r.get('id')
        if not isinstance(identity,str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',identity) or identity in ids:
            raise ConfigurationError('rule IDs must be unique and contain 1..64 letters, digits, dots, dashes or underscores')
        ids.add(identity)
        r.setdefault('enabled',True)
        if type(r['enabled']) is not bool:
            raise ConfigurationError('enabled must be boolean')
        if r.get('severity') not in ('info','low','medium','high','critical') or r.get('confidence') not in ('low','medium','high'):
            raise ConfigurationError('each rule requires severity and confidence labels')
        if not isinstance(r.get('investigation'),str) or not 1<=len(r['investigation'])<=1024:
            raise ConfigurationError('each rule requires investigation text up to 1024 characters')
        r['sources']=strings(r.get('sources'),'sources')
        for key,default in defaults.items():
            r[key]=integer(r.get(key,default),0 if key=='cooldown_seconds' else 1,20 if key=='min_observations' else 86400,key)
        for key in PARAMETERS[kind]:
            if key not in r:
                raise ConfigurationError(f'{kind} requires {key}')
        if kind.startswith('ap-') or kind=='unrecognized-bssid':
            if not isinstance(r['ssid'],str) or not 1<=len(r['ssid'])<=256:
                raise ConfigurationError('ssid must be a nonempty string')
        if kind=='ap-security-downgrade':
            if r['expected_security'] not in ('WPA','WPA2','WPA3','OWE'):
                raise ConfigurationError('expected_security must be WPA, WPA2, WPA3 or OWE')
        if kind=='unrecognized-bssid':
            r['approved_bssids']=sorted({mac(v) for v in strings(r['approved_bssids'],'approved_bssids')})
        if kind=='ble-service-change':
            r['address']=mac(r['address'])
            r['expected_services']=sorted({normalize_uuid(v) for v in strings(r['expected_services'],'expected_services')})
            if r['evidence_kind'] not in ('advertisement','gatt'):
                raise ConfigurationError('evidence_kind must be advertisement or gatt')
        for key in ('ports','allowed_ports'):
            if key in r:
                if not isinstance(r[key],list) or len(r[key])>256 or (key=='ports' and not r[key]):
                    raise ConfigurationError(f'{key} must be a bounded port list')
                r[key]=sorted({integer(v,1,65535,key) for v in r[key]})
        if 'allowed_networks' in r:
            networks=r['allowed_networks']
            if not isinstance(networks,list) or len(networks)>256:
                raise ConfigurationError('allowed_networks must be a bounded CIDR list')
            try:
                if any(not isinstance(v,str) for v in networks):
                    raise ConfigurationError('allowed_networks requires CIDR strings')
                r['allowed_networks']=sorted({str(ipaddress.ip_network(v,strict=True)) for v in networks})
            except ValueError as exc:
                raise ConfigurationError('allowed_networks requires canonical literal CIDRs') from exc
        normalized.append(r)
    policy=dict(version=1,rules=sorted(normalized,key=lambda r:r['id']))
    policy['sha256']=hashlib.sha256(encoded(policy).encode()).hexdigest()
    return policy
