"""Deterministic, descriptive cellular rules. No attack attribution."""
import datetime as dt
import hashlib
import statistics
from collections import Counter, defaultdict
from atlas.core.events import encoded, fingerprint

RULE_VERSION = 'cellular/v1'
METRICS = ('lte_rsrp', 'lte_rsrq', 'lte_rssi', 'lte_rssnr', 'nr_ss_rsrp', 'nr_ss_rsrq', 'nr_ss_sinr')


def identity(o):
    fields = ('technology', 'mcc', 'mnc', 'cell_id')
    return tuple(o[f] for f in fields) if all(f in o for f in fields) else None


def fresh_cell(o):
    return o['cellular_event'] == 'cell' and o['cell_freshness'] == 'recent'


def serving(o):
    # A default-manager observation has no stable subscription attribution.
    # Preserve it as evidence; do not train/compare it as a subscribed serving cell.
    return fresh_cell(o) and o.get('registered') is True and 'subscription_id' in o


def seconds(a, b):
    return (dt.datetime.fromisoformat(a['observed_at']) - dt.datetime.fromisoformat(b['observed_at'])).total_seconds()


def analyze(rows, baseline=None):
    rows = sorted((o for o in rows if o['kind'] == 'cellular'), key=lambda o: (o['observed_at'], o['id']))
    findings, previous, signals = [], {}, defaultdict(list)
    seen_measurements = set()
    baseline_cells = defaultdict(set)
    if baseline:
        for profile in baseline['profiles']:
            baseline_cells[profile['subscription_id']].update(tuple(c) for c in profile['cells'])
    novelty_seen = set()

    def finding(rule, old, o, detail, severity='info'):
        value = dict(rule=rule, rule_version=RULE_VERSION, severity=severity, confidence='reported',
                     identity=o['id'], source=o['source'], observed_at=o['observed_at'],
                     subscription_id=o.get('subscription_id'), collection_session=o['collection_session'],
                     evidence=detail, evidence_ids=[fingerprint(v) for v in (old, o) if v is not None],
                     interpretation='Operational observation requiring context; no IMSI-catcher or attack attribution')
        value['id'] = hashlib.sha256(encoded(value).encode()).hexdigest()
        findings.append(value)

    def compare(o, series, field, callback):
        if field not in o:
            return
        key = (*series, field)
        old = previous.get(key)
        if old and 0 < seconds(o, old) <= 300 and old[field] != o[field]:
            callback(old)
        if old is None or seconds(o, old) > 0:
            previous[key] = o

    for o in rows:
        series = (o['source'], o['collection_session'], o.get('subscription_id'))
        event = o['cellular_event']
        if event == 'cell':
            if not serving(o):
                continue
            role = o.get('connection_status', 'unknown')
            # Same modem sample re-exported/callbacked is one observation for comparisons/trends.
            measured = (*series, role, o.get('technology'), o.get('measurement_elapsed_ms'), identity(o), o.get('pci'))
            if measured in seen_measurements:
                continue
            seen_measurements.add(measured)
            cell_series = (*series, event, role, o['technology'])
            full = identity(o)
            if full is not None:
                old = previous.get((*cell_series, 'serving_identity'))
                if old and 0 < seconds(o, old) <= 300 and identity(old) != full:
                    finding('serving-cell-change', old, o, dict(before=identity(old), after=full, role=role))
                if old is None or seconds(o, old) > 0:
                    previous[(*cell_series, 'serving_identity')] = o
                if baseline and o['observed_at'] > baseline['through_at'] and baseline_cells[o.get('subscription_id')] and full not in baseline_cells[o['subscription_id']]:
                    key = (*series, full)
                    if key not in novelty_seen:
                        finding('cell-not-in-reviewed-baseline', None, o, dict(cell=full, baseline_id=baseline['id']))
                        novelty_seen.add(key)
            # Compare channel/PCI/TAC/band changes only within the same known logical cell.
            if full is not None:
                for field in ('pci', 'tac', 'arfcn', 'bands'):
                    compare(o, (*cell_series, full), field,
                            lambda old, field=field: finding('cell-identity-frequency-change', old, o,
                                                           dict(field=field, before=old[field], after=o[field])))
                for metric in METRICS:
                    if metric in o:
                        signals[(*cell_series, full, metric)].append(o)
        elif event == 'technology':
            def radio_change(old):
                pair = (old['network_type'], o['network_type'])
                if pair in {(13, 20), (20, 13)}:
                    finding('lte-nr-transition', old, o, dict(before=pair[0], after=pair[1],
                                                           basis='reported data network type, not display icon'))
            compare(o, (*series, event), 'network_type', radio_change)
            compare(o, (*series, event), 'display_override',
                    lambda old: finding('network-display-change', old, o,
                                        dict(before=old['display_override'], after=o['display_override'],
                                             caveat='Display override does not prove NR attachment or active NR traffic')))
            compare(o, (*series, event), 'data_state',
                    lambda old: finding('cellular-data-interruption', old, o, dict(before=old['data_state'], after=o['data_state']), 'review')
                    if old['data_state'] == 2 and o['data_state'] in {0, 3, 4} else None)
        elif event == 'service':
            compare(o, (*series, event), 'service_state',
                    lambda old: finding('cellular-registration-interruption', old, o,
                                        dict(before=old['service_state'], after=o['service_state'],
                                             scope='aggregate ServiceState; not separate PS/CS registration'), 'review')
                    if old['service_state'] == 0 and o['service_state'] != 0 else None)
        elif event == 'connectivity':
            compare(o, (*series, event), 'cellular_available',
                    lambda old: finding('cellular-connectivity-interruption', old, o,
                                        dict(before=True, after=False, scope='INTERNET-capable cellular Network lost; not proof of radio deregistration'), 'review')
                    if old['cellular_available'] and not o['cellular_available'] else None)
    trends = []
    for key, samples in sorted(signals.items(), key=lambda item: str(item[0])):
        metric = key[-1]
        # Split on gaps, and never combine disconnected observations more than 5 min apart.
        runs = [[]]
        for o in samples:
            if runs[-1] and seconds(o, runs[-1][-1]) > 300:
                runs.append([])
            if not runs[-1] or seconds(o, runs[-1][-1]) > 0:
                runs[-1].append(o)
        for run in runs:
            if len(run) < 3:
                continue
            first, last = run[0], run[-1]
            elapsed = seconds(last, first)
            delta = last[metric] - first[metric]
            trends.append(dict(source=first['source'], subscription_id=first['subscription_id'],
                               collection_session=first['collection_session'], cell=identity(first), metric=metric,
                               samples=len(run), start=first['observed_at'], end=last['observed_at'],
                               median=statistics.median(o[metric] for o in run), delta=delta,
                               endpoint_slope_per_minute=delta*60/elapsed,
                               availability='only recent cell-specific modem-timestamped samples'))
            threshold = 10 if metric in {'lte_rsrp', 'lte_rssi', 'nr_ss_rsrp'} else 5
            if elapsed <= 300 and delta <= -threshold and all(b[metric] <= a[metric] for a, b in zip(run, run[1:])):
                finding('sustained-signal-degradation', first, last,
                        dict(metric=metric, samples=len(run), delta=delta, seconds=elapsed, threshold=threshold), 'review')
    return dict(rule_version=RULE_VERSION, observations=len(rows),
                events=dict(Counter(o['cellular_event'] for o in rows)),
                freshness=dict(Counter(o['cell_freshness'] for o in rows)), findings=findings, trends=trends,
                performance=performance(rows),
                limitations=['Unfamiliar cells, handovers, signal changes and NR/LTE fallback are not IMSI-catcher findings.',
                             'Cell comparisons require recent registered measurements; callback signal timestamps are unknown and excluded from trends.',
                             'Comparisons never cross source, session, subscription, RAT or serving role; gaps >300s reset comparisons.',
                             '5G display overrides, data RAT and NR cell reports have distinct meanings; NSA may retain LTE data RAT.',
                             'Missing identity/metrics do not become zeros; incomplete identities do not establish serving-cell changes.',
                             'No location, physical tower authenticity, exhaustive neighbor inventory or per-SIM connectivity attribution is established.'])


def performance(rows):
    groups = defaultdict(list)
    for o in rows:
        if o['cellular_event'] == 'performance':
            groups[(o['source'], o['collection_session'], o['test_id'], o['test_endpoint'])].append(o)
    comparisons = []
    for (source, session, test_id, endpoint), values in sorted(groups.items()):
        transports = {}
        for transport in ('wifi', 'cellular'):
            samples = [o for o in values if o['test_transport'] == transport]
            good = [o for o in samples if o['test_status'] == 'success' and o['bound_network'] and o.get('duration_ms', 0) > 0]
            transports[transport] = dict(attempts=len(samples), successes=len(good),
                                         median_duration_ms=statistics.median(o['duration_ms'] for o in good) if good else None,
                                         median_bytes_per_second=statistics.median(o['bytes_received']*1000/o['duration_ms'] for o in good) if good else None,
                                         bytes_received=[o.get('bytes_received') for o in good])
        comparable = all(transports[t]['successes'] for t in transports)
        byte_counts = {b for t in transports.values() for b in t['bytes_received']}
        comparisons.append(dict(source=source, collection_session=session, test_id=test_id, endpoint=endpoint,
                                transports=transports, comparable=bool(comparable and len(byte_counts) == 1),
                                caveat='Sequential bound HTTPS samples include DNS/TLS/server/scheduling; not link capacity, packet RTT or controlled simultaneous conditions. Capped at 64 KiB/test.'))
    return comparisons
