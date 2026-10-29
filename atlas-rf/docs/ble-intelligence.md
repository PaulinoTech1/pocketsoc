# Bluetooth Low Energy analysis engine

BLE telemetry is evidence about advertisements and authorized GATT snapshots. An address is not a persistent physical-device identity. ATLAS never merges different addresses using names, service UUIDs, manufacturer bytes or signal levels. Same-address comparisons also remain uncertain because addresses can be reused or spoofed.

## Commands

Use the virtual environment and tracked launcher as described in [installation.md](installation.md):

```sh
atlas ble scan --input /path/to/session.atlas.json
atlas ble scan --input /path/to/ble.jsonl
atlas ble inspect --source 'android:INSTALL_UUID:ble' --address c2:11:22:33:44:01
atlas ble anomalies --source 'android:INSTALL_UUID:ble' --since 2026-10-29T12:00:00Z
```

Global `--db` and `--config` precede `ble`. `scan` imports explicit Android/export telemetry; it reports `radio_scan_performed: false` and does not access phone radios from Debian. Standalone JSONL must contain only `ble` or `ble_gatt` events; finalized mixed-radio bundles are filtered to BLE. All validation completes before writing; inserts are atomic and exact replay is deduplicated.

`inspect` is passive by default. It returns bounded source/address history with timestamps, evidence confidence and `physical_identity_confidence: unverified`. It performs no connection. Records under an address can come from different devices; rotating addresses can split one device's history. Absence of linkage is intentional, not a claim that addresses identify separate devices.

`anomalies` uses earlier source history as reference and scans chronologically, emitting findings strictly after the required `--since` cutoff. This is a rolling temporal comparison, not the frozen Wi-Fi baseline. It previews read-only by default. Add `--save` to store findings with stable evidence IDs, source, observation timestamp and confidence; repeated saved analysis does not duplicate identical evidence.

## Telemetry contract

Existing `kind`, `id`, `source`, `observed_at`, optional `name` and `rssi` remain. `id` is the observed address, never a physical-device ID. New advertisement fields apply only to `ble`:

| Field | Available evidence and bound |
| --- | --- |
| `advertisement_hex` | Actual raw ScanRecord bytes, hex; maximum 1650 bytes |
| `service_uuids` | Up to 64 advertised UUIDs; normalize 16/32-bit or full UUID forms to full lowercase UUIDs |
| `manufacturer_data` | Up to 16 decimal company-ID keys (0–65535), each with up to 256 bytes of hex data |
| `connectable` | Optional actual Android connectability flag |
| `advertisement_complete` | Optional Android chain-completeness flag; false if local limits prevented full export |
| `evidence_confidence` | `reported`, `synthetic` or `unknown` provenance label, not cryptographic authentication |

Missing fields remain missing. An empty exported UUID list means none was parsed in that record, not that the device has no services. Company IDs describe advertised manufacturer namespaces; they are not unique device identifiers or proof of vendor identity. Raw payloads often contain counters, sensor readings or rotating identifiers. UUID/name/manufacturer evidence does not establish physical identity.

The Kotlin collector obtains these fields through `ScanRecord` and `ScanResult`, retaining the existing bounded event queue, BLE ten-second scan window and measurement timestamp conversion. Oversized fields are omitted with drop counters and the advertisement marked incomplete, rather than silently exporting a truncated field as complete. [Android ScanRecord API](https://developer.android.com/reference/android/bluetooth/le/ScanRecord), [ScanResult completeness](https://developer.android.com/reference/android/bluetooth/le/ScanResult#getDataStatus()).

Successful GATT discovery is a separate `ble_gatt` event with the same source namespace, observed address and callback observation timestamp. It requires:

- `authorization_id`: UUID matching the scoped request.
- `operation: discover_services`, `writes_performed: false`, `pairing_initiated: false`.
- `gatt_status`: `complete`, `failed`, `timeout`, `cancelled`, `permission_denied`, `not_bonded`, `authentication_required`, `unavailable` or `truncated`.
- `gatt_services`: at most 64 service objects, each with a UUID and characteristic UUID/property-bitmask list; at most 128 characteristics total. No values, descriptors or write instructions are allowed.

Failure/partial events can be retained as evidence but never erase a successful capability snapshot. Attestations in an imported file are operator-supplied, not proof of what an unauthenticated exporter actually did. Bridge hashes check payload integrity, not identity or authorization authenticity.

## Authorized GATT enumeration

Create a new private request only when authorized to assess that exact target:

```sh
atlas ble inspect --address c2:11:22:33:44:01 --gatt --authorized --output gatt-request.json
```

This command **does not connect**. Without `--authorized`, it fails before writing. The request is enumeration-only, expires after fifteen minutes and forbids pairing and writes. Output uses 0600 and refuses overwrite.

Transfer the request to Android using an already approved user-mediated path. The observed guest share is read-only; no reverse transfer or shared localhost channel is assumed. In the Android source app, select **Open authorized GATT request**, choose the file and explicitly confirm the displayed address/scope. Imported files never auto-connect. The app validates request size (4 KiB), fields, UUID, address, scope and expiration, then rechecks authorization lifetime before connection.

The prototype permits only an **already bonded** target. This conservative restriction avoids initiating pairing with unknown devices; no bonding, pairing, PIN/passkey or key-management API is invoked. If the target is unbonded, it exports `not_bonded` without connecting. ATLAS does not perform or instruct automatic pairing to satisfy this condition. Address rotation can make an old request unusable; this is not solved by guessing another address.

For the confirmed target, `connectGatt` uses `autoConnect=false` and LE transport. On successful connection, `discoverServices()` enumerates service and characteristic metadata only. It performs no characteristic-value reads, notifications/subscriptions, descriptor operations or writes. Authentication/encryption errors stop the attempt; there is no bonding retry. A ten-second timeout, disconnect/close on completion/error and activity-stop cancellation bound the operation. No capability-removal inference is made from failures or truncation. Android may cache service metadata; the app does not call hidden cache-refresh APIs. [Android GATT connection guide](https://developer.android.com/develop/connectivity/bluetooth/ble/connect-gatt-server), [service discovery API](https://developer.android.com/reference/android/bluetooth/BluetoothGatt#discoverServices()).

The app requires the normal `BLUETOOTH_CONNECT` runtime permission for inspection. Passive discovery retains its existing SCAN/location permission flow. No root, firmware change, Android security change or network transport is introduced. [Android Bluetooth permissions](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions).

The Kotlin source is implemented but remains **uncompiled/uninstalled** in the inspected environment: JDK, Gradle and Android SDK tools are unavailable. Actual GATT, lifecycle, permissions and request-transfer behavior require equipped-build and field acceptance. Python fixture tests are not proof of active GATT support on the phone.

## Review rules and confidence

| Rule | Trigger | Confidence / limitation |
| --- | --- | --- |
| `new-advertising-services` | Advertised UUIDs not yet seen in that source's recorded advertisement history, after reference data exists | Low; source-level novelty only, not a new-device assertion |
| `unexpected-advertisement-configuration` | Adjacent complete reports under the same source/address change a present name, connectability or manufacturer data | Low; medium after at least three consecutive stable prior reports. Payload counters and normal modes can explain changes |
| `advertised-capabilities-added` | Adjacent complete reports under that temporal address newly advertise a UUID | Low; alternating packets may explain new presence. Missing advertised UUIDs never establish capability removal |
| `known-gatt-capabilities-changed` | Two successful complete metadata enumerations differ in services or characteristic UUID/properties | Medium confidence about reported snapshots; physical identity and Android cache freshness remain unverified |

Per-address comparisons expire after five minutes. Different addresses are never linked, and a long gap resets comparison context. Even within the window, same-address comparisons do not prove the same device. Truncated/unknown-completeness advertisements cannot establish configuration changes. Failed, auth-required, cancelled or partial GATT sessions do not replace the last successful snapshot. Missing fields do not become empty capabilities.

All findings are `review_hint`, `confirmed_attack: false`, with prior/current timestamps, observed address, source, confidence, scope and concrete evidence. Manufacturer payload-change evidence includes hashes; raw bytes stay in observation history. Confidence describes evidence strength for a change, not identity, maliciousness or a statistical probability. Source labels and advertised data can be spoofed.

## SQLite, bounds and retention

The full validated records remain in v1 `observations`; additive `ble_findings` stores evidence ID, source, timestamp, confidence and body. No destructive database migration is required. `ble anomalies` is a write operation because it persists findings; `ble inspect` is read-only. Evidence insertion is transactional and idempotent.

Existing bridge limits apply. Direct BLE JSONL is bounded to 8 MiB, 10,000 lines and 16 KiB per line. Inspection returns the latest 100 records by default (`--limit 1..1000`) with truncation metadata. Analysis streams at most 100,000 chronological rows per run with explicit truncation, and bounds its per-address/type context at 4096 keys and global UUID set at 4096; output defaults to 500 distinct findings (`--limit 1..5000`). Hitting a bound reports partial coverage, not a complete assessment. No Rust extension or additional Python dependency is needed.

Retention remains explicit. Purging expired raw observations now invalidates saved BLE findings and other derived copies; see [security.md](security.md). Protect private guest storage and public exports: names, manufacturer bytes and characteristic metadata can be sensitive. No data is uploaded.

## Synthetic verification workflow

```sh
ble_demo=$(mktemp -d)
atlas --db "$ble_demo/atlas.sqlite3" ble scan --input examples/ble/telemetry.atlas.json
atlas --db "$ble_demo/atlas.sqlite3" ble inspect --source synthetic:android-ble:lab --address c2:11:22:33:44:01
atlas --db "$ble_demo/atlas.sqlite3" ble anomalies --source synthetic:android-ble:lab --since 2026-04-16T10:03:00Z
.venv/bin/python -m unittest discover -s tests -v
```

The deterministic generator in `examples/ble/generate.py` creates eleven explicitly synthetic advertisement/GATT records: a stable beacon, added advertised service/configuration, a different address that could reflect rotation or another device, partial advertisements, failed and changed complete GATT metadata, and a long-gap reused-address case. It produces four review hints; replay inserts no new observations and repeated analysis saves no duplicate evidence. It performs no radio or GATT operation and makes no physical-device linkage claim.

BLE findings are available through `ble anomalies`; they are not automatically included in the general legacy report rule list. The finding's `confidence` describes review strength, while `evidence_confidence` separately preserves reported/synthetic/unknown provenance, including the previous record's provenance where available.
