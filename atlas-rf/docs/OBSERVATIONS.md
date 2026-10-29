# Observation integration contract (v1)

UTF-8 JSON Lines: one JSON object per line. Blank lines are ignored. No envelope or version field. Export only data you are authorized to collect. Import never executes source strings. Do not put credentials or location coordinates in exports. BLE advertisement bytes are supported as bounded, sensitive evidence.

Every observation requires:

| Field | Meaning |
| --- | --- |
| `kind` | `wifi`, `ble`, `ble_gatt`, `neighbor`, `route`, or `service` |
| `id` | Nonempty identity, at most 256 characters; kind-specific rules below |
| `observed_at` | ISO 8601 timestamp including timezone, no more than five minutes in the future; canonicalized to UTC |
| `source` | Nonempty collector/sensor label, at most 256 characters; use stable unique labels per sensor |

Optional text fields `name`, `interface`, and `security` allow at most 256 characters. `rssi` is a finite number from -127 to 0 dBm, not a percentage. `ip` and `gateway` must be literal IPv4/IPv6 without zone identifiers. `mac` is a six-octet colon-separated address. `port` is an integer from 1 to 65535. Unknown fields are rejected. Missing measurements must be omitted, never fabricated.

Wi-Fi additionally supports `frequency_mhz` (integer 2400–7125), `channel` (integer 1–233), `scan_freshness` (`fresh`, `cached`, `stale`, `unknown`) and `scan_age_ms` (nonnegative integer). These fields are Wi-Fi-only. Known frequency/channel pairs must agree; missing values remain absent. Freshness/age describe the collection callback, not the import time. See [wifi-intelligence.md](wifi-intelligence.md) for exact eligibility, bands and baseline semantics; old records remain readable but cannot train the new baseline without explicit fresh metadata.

| Kind | Identity and extra required fields |
| --- | --- |
| `wifi` | `id`: BSSID MAC; `security`: advertised security text, `UNKNOWN` if unavailable; optional `name` SSID, `rssi` |
| `ble` | `id`: observed MAC (including randomized addresses); optional advertised `name`, `rssi` |
| `ble_gatt` | `id`: observed MAC; explicit authorization UUID, discovery status, service/characteristic metadata and no-write/no-pairing attestations; see [BLE contract](ble-intelligence.md) |
| `neighbor` | `id`: canonical IP; requires same `ip` plus `mac`; optional `interface` |
| `route` | `id`: route label such as `default@eth0`; requires `gateway`; optional `interface` |
| `service` | `id`: canonical `IP/tcp/port`; requires matching `ip` and integer `port`; records successful TCP connect only |

MAC identities normalize to lowercase. Times normalize to UTC with microseconds. Security labels normalize to uppercase. `OPEN`, `NONE`, `--`, `WEP`, WPA without WPA2/WPA3 trigger a weak-security review. `WPA2`, `WPA3`, `RSN`, `OWE` are considered stronger only for the downgrade heuristic, not a certification of configuration. Unknown security has no numeric rank. Mixed WPA2/WPA3 does not imply a downgrade when it becomes WPA2 alone; detailed negotiation is outside this schema.

Replay deduplication hashes the full normalized object, including source and observation time. Different timestamps are distinct sightings; different sources do not share anomaly baselines. Imports may arrive out of order: analysis sorts observation time, not ingestion order. Comparisons across long observation gaps are limited only for RSSI changes (five minutes). The analysis window can omit the actual first sighting or prior security baseline.

```json
{"kind":"wifi","id":"02:00:00:00:00:01","name":"Lab","security":"WPA2","rssi":-62,"source":"sensor:lab-1","observed_at":"2026-01-01T12:00:00Z"}
{"kind":"ble","id":"02:00:00:00:00:02","name":"Beacon","rssi":-71,"source":"sensor:lab-1","observed_at":"2026-01-01T12:00:00Z"}
```

An Android app can export these lines through a user-mediated file transfer after normal runtime permission checks and OS scan scheduling. Kotlin companion source is bundled; no built APK is supplied. Prefer files for the initial boundary: no inbound service, token setup or device security changes are needed. Do not label a companion export as a verified physical device identity.

The permission, lifecycle, timestamp and export behavior is specified in [android-bridge.md](android-bridge.md), based on the actual [environment inspection](environment.md). Kotlin source is now supplied, but compilation, installation and real Android-to-VM export remain unverified. The prototype embeds these JSONL records in a finalized `.atlas.json` envelope; use `atlas bridge verify/import` for that format, or the original import command for standalone JSONL.

BLE extended advertisement fields, GATT evidence requirements, bounds, normalization and conservative temporal rules are specified in [ble-intelligence.md](ble-intelligence.md). Extended fields remain optional for legacy advertisements.
