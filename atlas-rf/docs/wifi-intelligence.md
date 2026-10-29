# Wi-Fi intelligence subsystem

The subsystem ingests explicit Android/export observations, stores complete history in SQLite, freezes source-specific historical baselines and produces review hints against fresh later measurements. It never generates live radio measurements or assumes guest radio access.

## Commands

From the activated virtual environment with `scripts/` on PATH, or substitute `./scripts/atlas`:

```sh
# A finalized Android .atlas.json export, or standalone Wi-Fi-only JSONL:
atlas wifi scan --input /path/to/session.atlas.json
atlas wifi scan --input /path/to/wifi.jsonl

# Freeze reviewed history from exactly one sensor/source:
atlas wifi baseline --source 'android:INSTALL_UUID:wifi' --through 2026-10-29T12:00:00Z
atlas wifi baseline --source 'android:INSTALL_UUID:wifi' --show

# Review later measurements without modifying history or baseline:
atlas wifi anomalies --source 'android:INSTALL_UUID:wifi'
atlas wifi anomalies --source 'android:INSTALL_UUID:wifi' --baseline-id SAVED_UUID --limit 500
```

Global `--db` and `--config` precede `wifi`. `scan` requires `--input`: this Debian prototype imports an explicit file, reports `radio_scan_performed: false` and does not launch Android scans. It does not silently inspect an inbox or start networking. For radio collection, use the source collector and verified-file procedure in [the Android guide](../android/collector/README.md). APK compilation, hardware operation and real shared-file delivery remain unverified in this environment.

`baseline` creates a new immutable snapshot. Without `--through`, it includes the source's current measurement history through the maximum observed timestamp. Use a reviewed cutoff before the evaluation period; training on suspect data can normalize it. `--show` reads the most recent saved snapshot and cannot be combined with `--through`. `anomalies` defaults to that latest source snapshot or accepts an explicit saved ID. No automatic retraining or approval is implied.

## Observation fields

Canonical records reuse the existing schema; the Android-facing names map as follows:

| Wi-Fi concept | JSON field | Meaning |
| --- | --- | --- |
| SSID | `name` | Optional actual observed SSID; hidden/unavailable names may be empty/omitted |
| BSSID | `id` | Actual observed MAC, normalized to lowercase |
| Frequency | `frequency_mhz` | Optional measured primary-channel center frequency, integer MHz |
| Channel | `channel` | Optional channel supplied by Android's supported frequency conversion API |
| RSSI | `rssi` | Optional actual dBm, existing range -127..0 |
| Advertised security | `security` | Required advertisement label; UNKNOWN for unavailable/ambiguous data |
| Observation timestamp | `observed_at` | Actual measurement time converted to UTC; never replaced with import time |
| Scan freshness | `scan_freshness` | `fresh`, `cached`, `stale` or `unknown` |
| Age at callback | `scan_age_ms` | Optional nonnegative age computed from Android's monotonic clocks, not age at import |
| Sensor/provenance | `source` | Stable exact collector/sensor label; baseline scope |

No missing frequency, channel, RSSI, timestamp age or freshness state is filled in as a measurement. Band labels are classifications of supplied frequency, not new measurements. The reader labels 2.4 GHz, 5 GHz (including supplied 4.9 GHz-range values), and 6 GHz observations. Channel numbers are always paired with frequency in comparisons because channel 1, for example, belongs to more than one band. This is not a claim about supported hardware or regional regulatory permissions.

Integer frequency metadata is accepted from 2400 through 7125 MHz and channel metadata from 1 through 233. Known frequency/channel combinations are checked for consistency, including 2484 MHz / channel 14 and 5935 MHz / channel 2. Unknown combinations within the supported metadata bounds are preserved rather than assigned a made-up channel; band is unknown outside the classified ranges. These checks are not a regulatory channel allowlist. Android's public conversion method is available from API 31. [Android ScanResult API](https://developer.android.com/reference/android/net/wifi/ScanResult#convertFrequencyMhzToChannelIfSupported(int)).

Older observations without the new fields remain valid and readable. Missing freshness is treated as unknown by the new baseline/anomaly subsystem; it is never assumed fresh. New fields are Wi-Fi-only and flow through both direct import and the finalized bridge verifier.

## Freshness and cached data

The Kotlin source now exports frequency, channel, callback age and freshness. A failed/unsuccessful scan broadcast may expose cached results, but those are explicitly marked cached. Even after a successful broadcast, a result last observed before session start is marked cached, and a result older than thirty seconds at callback is marked stale. Stale and cached Wi-Fi records are retained within the existing bounded session queue instead of being dropped as measurements; BLE retains its existing age exclusion. An unchanged measurement does not receive a fresh timestamp when returned from a cache. [Android Wi-Fi scan result behavior](https://developer.android.com/develop/connectivity/wifi/wifi-scan).

The analysis eligibility rule requires `scan_freshness: fresh`. A supplied `scan_age_ms` above 30,000 overrides that declaration and excludes the sample. If age is missing, freshness relies on the collector's explicit label; age is not fabricated or independently proven. Importing a historical fresh record months later does not turn it into a stale capture: freshness is about the acquisition callback, while analysis retains the original measurement time.

Cached/stale/unknown records remain in SQLite, appear in ingestion coverage and never update the new baseline or trigger its anomaly rules. Multiple fresh deliveries of the same source/BSSID/measurement timestamp count once for baseline statistics and each anomaly run, even if callback age differs. Their full event records remain in history. Conflicting deliveries at one timestamp are not resolved as independent measurements; deterministic first eligible row wins. Exact canonical replays continue to insert zero rows.

Legacy report/dashboard rules now skip Wi-Fi rows that explicitly carry nonfresh metadata. Their preexisting behavior for old rows with no freshness metadata is retained for compatibility; use `atlas wifi anomalies` for the strict frozen-baseline workflow.

## Historical baseline and SQLite

The full observation JSON, including new metadata, is stored in the existing v1 `observations` table. New additive `wifi_baselines` rows store snapshot ID, source, creation time and aggregate JSON; no existing observations are rewritten and no destructive migration is needed. An index on `(kind, source, observed_at, seq)` supports chronological streaming.

A baseline stores each BSSID's actual seen SSIDs, recognized security signatures, supplied frequency/channel pairs, unique-measurement counts, first/last observation times and actual RSSI extrema. Unknown security is tracked as missing evidence rather than treated as OPEN. Hidden SSIDs are not learned as names. Whitespace/token order normalization prevents `WPA2 WPA3` versus `WPA3 WPA2` from becoming an artificial change; different parsers/labels may still need review.

Training and snapshot insertion share a transaction. A failed/oversized retraining rolls back and leaves earlier saved snapshots available. Sources are never merged. New imports do not change a snapshot; late pre-cutoff observations remain historical rows and are counted separately, excluded from post-cutoff assessment. Measurement-time ordering, rather than file order, supports delayed/out-of-order imports.

History retention uses explicit maintenance. Purging expired observations invalidates all baseline snapshots and derived findings to avoid retaining sensitive copies. See [security.md](security.md). There is no trust establishment from a source string: imported sensor labels and advertised configuration are operator-supplied evidence.

## Rules

Every finding has `classification: review_hint`, `confirmed_attack: false`, source, timestamp, BSSID/SSID, supplied radio metadata and evidence.

| Rule | Trigger | Interpretation |
| --- | --- | --- |
| `unknown-bssid` | Fresh BSSID absent from that source's frozen baseline | Informational novelty; new APs or identifiers are possible |
| `unseen-ssid` | Fresh nonempty SSID absent from the frozen source history | Informational novelty; hidden names do not qualify |
| `unexpected-security-change` | Known BSSID advertises a recognized security signature not previously observed | Review configuration changes; downgrade is medium severity, other changes informational; UNKNOWN does not establish a change |
| `unusual-channel-change` | Known BSSID has at least three eligible channel samples and now supplies a new frequency/channel pair | Informational review; DFS, channel selection, maintenance and band changes can be legitimate |
| `suspicious-ssid-duplication` | An unfamiliar BSSID/SSID association claims a known SSID and advertises OPEN/WEP while all known security evidence for that SSID is stronger | Medium review hint requiring two signals; unknown/incomplete or mixed weak baseline security prevents the strong-security assumption |

Duplicate SSIDs alone are not attacks. An unfamiliar BSSID with the same SSID/security produces only the novelty hint. Roaming, mesh, multiple bands and infrastructure growth are ordinary cases. Findings do not prove an evil twin, a compromised AP, physical-device identity or exact location. RSSI is preserved as evidence, not converted into distance or used alone as an attack classifier.

## Bounds and coverage

Inputs: at most 8 MiB standalone JSONL, 10,000 lines, 16 KiB per line, or existing bounded finalized bundle. All input validation precedes writing, and inserts are transactional. Standalone JSONL must contain only Wi-Fi records; finalized bundles may contain BLE, which this command leaves for the general bridge importer rather than inserting into Wi-Fi history.

Training streams SQLite history with at most 4,096 BSSIDs, 32 variants per BSSID/field and an 8 MiB snapshot bound. It fails explicitly instead of silently truncating learning. There is no automatic training-time window that would hide older accepted history. Anomaly output defaults to 500 distinct findings (`--limit 1..5000`), deduplicates repeated rule/evidence combinations, caps its working identity map and reports truncation/coverage if a bound is reached. A partial result is not a complete scan. No Rust implementation or new Python dependency is introduced.

## Synthetic fixture walkthrough

The deterministic generator at `examples/wifi/generate.py` never accesses hardware. Its fixtures model a mixed-band office, a normal open guest SSID, printer infrastructure, an added legitimate AP, changed security, changed channel, a weaker-security SSID claimant, a nearby new SSID, hidden names and cached/stale/unknown results.

```sh
wifi_demo=$(mktemp -d)
atlas --db "$wifi_demo/atlas.sqlite3" wifi scan --input examples/wifi/training.atlas.json
atlas --db "$wifi_demo/atlas.sqlite3" wifi baseline --source synthetic:android-wifi:office
atlas --db "$wifi_demo/atlas.sqlite3" wifi scan --input examples/wifi/evaluation.atlas.json
atlas --db "$wifi_demo/atlas.sqlite3" wifi anomalies --source synthetic:android-wifi:office
.venv/bin/python -m unittest discover -s tests -v
```

Expected training: 18 stored records, 15 eligible samples, five BSSIDs, with one each cached/stale/unknown excluded. Expected evaluation: nine distinct hints across all five rules; one cached, one stale and one duplicate measurement excluded. All fixture sources explicitly start with `synthetic:`. Values are plausible test inputs, never presented as real measurements. Kotlin source remains uncompiled because the previously recorded Android toolchain blocker persists.
