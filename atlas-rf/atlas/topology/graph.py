"""Multi-protocol evidence graph; addresses and co-observation never prove identity."""

def topology(observations):
    nodes,edges={},{}
    wifi_addresses={}
    neighbors=[]
    def node(identity,kind,label,**data):
        nodes[identity]=dict(id=identity,kind=kind,label=label,**data)
    def edge(a,b,relation,o,**data):
        edges[(a,b,relation,o['source'])]=dict(source=a,target=b,relation=relation,
            evidence_source=o['source'],observed_at=o['observed_at'],**data)
    for o in observations:
        sensor='source:'+o['source']
        node(sensor,'source',o['source'])
        # Scope addresses to their source to avoid merging unrelated networks/devices.
        scoped=o['source']+':'+o['id']
        if o['kind'] in {'wifi','ble','ble_gatt'}:
            kind='wifi' if o['kind']=='wifi' else 'ble'
            target=kind+':'+scoped
            node(target,kind,o.get('name') or o['id'],observed_address=o['id'],
                 source_scope=o['source'],physical_identity_confidence='unverified')
            edge(sensor,target,'gatt-metadata-observed' if o['kind']=='ble_gatt' else 'observed-radio',o)
            if kind=='wifi': wifi_addresses.setdefault(o['id'],set()).add(target)
        elif o['kind']=='cellular':
            from atlas.cellular.analysis import identity
            from atlas.core.events import encoded
            cell = identity(o) if o['cellular_event'] == 'cell' else None
            if cell is not None:
                target = 'cellular:' + o['source'] + ':' + str(o.get('subscription_id')) + ':' + encoded(cell)
                node(target, 'cellular', encoded(cell), physical_identity_confidence='unverified')
                edge(sensor, target, 'reported-serving-cell' if o.get('registered') else 'reported-neighbor-cell', o, freshness=o['cell_freshness'])
        elif o['kind']=='service':
            host,service='ip:'+o['source']+':'+o['ip'],'tcp:'+scoped
            node(host,'host',o['ip'],source_scope=o['source'])
            node(service,'service',f"TCP {o['port']}",source_scope=o['source'])
            edge(sensor,host,'tcp-reachable',o)
            edge(host,service,'accepted-connection',o)
        elif o['kind']=='neighbor':
            host,target='ip:'+o['source']+':'+o['ip'],'mac:'+o['source']+':'+o['mac']
            node(host,'host',o['ip'],source_scope=o['source'])
            node(target,'mac',o['mac'],source_scope=o['source'])
            edge(sensor,host,'neighbor-cache',o)
            edge(host,target,'reported-address-binding',o)
            neighbors.append((target,o))
        elif o['kind']=='route':
            gateway='ip:'+o['source']+':'+o['gateway']
            node(gateway,'host',o['gateway'],source_scope=o['source'])
            edge(sensor,gateway,'route-via',o)
    # A literal address match is a reviewable cross-protocol hint, not device correlation.
    # Bound combinations even if many untrusted sources repeat one Wi-Fi address.
    matches=0; truncated=False
    for target,o in neighbors:
        for radio in sorted(wifi_addresses.get(o['mac'],())):
            if matches>=4096:
                truncated=True;break
            edge(target,radio,'address-equality-unverified',o,confidence='low',
                 caveat='Literal MAC/BSSID equality across supplied records; spoofing, reuse and source trust remain unresolved. No BLE identity linkage.')
            matches+=1
        if truncated: break
    return dict(nodes=list(nodes.values()),edges=list(edges.values()),
                cross_protocol_hints=matches,cross_protocol_truncated=truncated,
                caveat='Historical source-scoped evidence graph, not physical topology. Co-observation implies no connectivity; address equality does not authenticate identity.')
