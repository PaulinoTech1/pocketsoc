"""Radio metadata validation; classify supplied frequencies without synthesizing measurements."""
FRESHNESS = {'fresh', 'cached', 'stale', 'unknown'}
RADIO_FIELDS = {'frequency_mhz', 'channel', 'scan_freshness', 'scan_age_ms'}
MAX_FRESH_AGE_MS = 30_000


def band(frequency):
    if frequency is None:
        return 'unknown'
    if 2400 <= frequency <= 2500:
        return '2.4GHz'
    if 4900 <= frequency < 5925:
        return '5GHz'
    if 5925 <= frequency <= 7125:
        return '6GHz'
    return 'unknown'


def expected_channel(frequency):
    # Consistency check only. Never fill a missing observed channel.
    if frequency == 2484:
        return 14
    if 2412 <= frequency <= 2472 and (frequency - 2407) % 5 == 0:
        return (frequency - 2407) // 5
    if 4900 <= frequency < 5000 and frequency % 5 == 0:
        return (frequency - 4000) // 5
    if 5000 < frequency <= 5885 and frequency % 5 == 0:
        return (frequency - 5000) // 5
    if frequency == 5935:
        return 2
    if 5955 <= frequency <= 7115 and (frequency - 5950) % 5 == 0:
        return (frequency - 5950) // 5
    return None


def validate_radio(o):
    if 'frequency_mhz' in o and (type(o['frequency_mhz']) is not int or not 2400 <= o['frequency_mhz'] <= 7125):
        raise ValueError('frequency_mhz must be an integer from 2400 to 7125')
    if 'channel' in o and (type(o['channel']) is not int or not 1 <= o['channel'] <= 233):
        raise ValueError('channel must be an integer from 1 to 233')
    if 'frequency_mhz' in o and 'channel' in o:
        expected = expected_channel(o['frequency_mhz'])
        if expected is not None and expected != o['channel']:
            raise ValueError('channel conflicts with supplied frequency_mhz')
    if 'scan_freshness' in o and (not isinstance(o['scan_freshness'], str) or o['scan_freshness'] not in FRESHNESS):
        raise ValueError('scan_freshness must be fresh, cached, stale or unknown')
    if 'scan_age_ms' in o and (type(o['scan_age_ms']) is not int or not 0 <= o['scan_age_ms'] <= 2**63 - 1):
        raise ValueError('scan_age_ms must be a nonnegative integer')


def eligibility(o):
    state = o.get('scan_freshness', 'unknown')
    if state != 'fresh':
        return state
    if o.get('scan_age_ms', 0) > MAX_FRESH_AGE_MS:
        return 'stale'
    return 'fresh'
