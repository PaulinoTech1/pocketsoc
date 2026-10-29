# Minimal ATLAS RF Android collector

**Kotlin source prototype, not a built or installed APK.** Build tools are unavailable in the inspected environment. Hardware behavior and real Android-to-VM export remain UNVERIFIED; see [transport investigation](../../docs/vm-transport.md).

## Contents

- `MainActivity`: explicit permission request, Start/Stop, 15-second session, document export and radio-free transport nonce export. No automatic restart, service, background collection or network listener.
- `WifiCollector`: `WifiManager`, scan-result broadcast, actual scan timestamps and advertised capabilities. At most one app scan request per session; a persisted 35-second request interval avoids bursts across activity recreation. Rejected/throttled requests are recorded separately while the app may observe later system scans. Unsuccessful broadcasts never become fresh observations. [Wi-Fi scanning documentation](https://developer.android.com/develop/connectivity/wifi/wifi-scan).
- `BleCollector`: `BluetoothLeScanner`, low-power ten-second window, callbacks and explicit failures. Passive discovery performs no pairing, GATT operation, advertising or privacy-address resolution; separately authorized GATT metadata inspection is described below. [BLE discovery documentation](https://developer.android.com/develop/connectivity/bluetooth/ble/find-ble-devices).
- `RadioSession`: 256-entry nonblocking queue, one disk writer, 10,000 accepted-event limit, 8 MiB JSONL spool, per-address deduplication/BLE one-second sampling and drop counters. Its in-memory identity map is capped at 10,000 entries. A separate I/O executor has one worker and a one-task bounded queue; no executor task per advertisement.
- `ObservationClock`: stable session wall/elapsed-realtime anchor; converts actual Wi-Fi microseconds/BLE nanoseconds since boot to UTC. Timestamp errors and wall-clock jumps over five seconds fail closed. [Wi-Fi timestamps](https://developer.android.com/reference/android/net/wifi/ScanResult#timestamp), [BLE timestamps](https://developer.android.com/reference/android/bluetooth/le/ScanResult#getTimestampNanos()).

Wi-Fi results now retain frequency, Android-derived channel, age at callback and freshness. Results before session start are labeled cached and results over 30 seconds old are labeled stale; unsuccessful scan callbacks may export explicitly cached results. These Wi-Fi records remain historical evidence and do not train the new baseline. BLE results before session start or over ten seconds old are still excluded. Invalid/future monotonic times are excluded. Duplicate sightings never receive a new measurement timestamp. The finalized payload retains its UTC strings; SQLite normalizes them to UTC microsecond precision. This is a phone-clock estimate, not externally synchronized evidence. See [Wi-Fi intelligence](../../docs/wifi-intelligence.md) for downstream eligibility and rules.

## Permissions and lifecycle

Minimum Android API 31; compile/target API 35 for this pinned prototype. Request fine/coarse location together and Bluetooth SCAN/CONNECT through the visible permission button. Wi-Fi requires precise location permission, required location-services state and enabled Wi-Fi. BLE address/adapter APIs are guarded by CONNECT plus SCAN and declare `neverForLocation`; optional Wi-Fi/cellular cell information uses separately requested location grants. Missing/denied/revoked permissions and disabled features become explicit states, not invented data. [Android Bluetooth permissions](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions).

The app never toggles radios, location services or scan throttling. Passive collection opens no IP connection. INTERNET and CHANGE_NETWORK_STATE support separately authorized bound HTTPS tests; there is no background-location, advertising, broad-storage, root or monitor-mode requirement. Collection stops when the activity leaves the foreground or after fifteen seconds; the BLE timer stops discovery after ten seconds. A background/rotated/destroyed activity can interrupt the workflow. There is no promise of collection or export recovery after process death: repeat a visible session if necessary.

Exports run only after the queue is drained and its writer has closed. Permission failures may legitimately produce a zero-row bundle with failure statuses. Passive collection does not list identifiers or log them to logcat. The GATT authorization dialog displays the exact target address for explicit confirmation. Raw observation payloads still contain sensitive names/identifiers; export only data authorized for assessment.

## File protocol

A single `<session>.atlas.json` document contains:

```text
kind: atlas-radio-export
schema_version: 1
complete: true
metadata: {session_id, synthetic, rows, bytes, statuses, drops, clock anchors, ...}
sha256: SHA-256 of exact UTF-8 payload_jsonl bytes
payload_jsonl: string containing newline-terminated observation records
```

Metadata and status objects are not mixed into the observation stream. The Android exporter marks live-source bundles `synthetic: false` and labels events `android:<random-install-uuid>:wifi|ble|cellular`. No fixture-generation mode is embedded in the APK source. Unpaired Wi-Fi/BLE exports hash exact finalized payload bytes without metadata authentication. Paired sessions wrap the complete inner envelope in HMAC-SHA256 authentication; real cellular ingestion requires this paired format and matching challenge. The guest verifier caps the envelope at 16 MiB, payload at 8 MiB, metadata at 64 KiB and rows at 10,000, checks complete/hash/counts and validates all observations before opening a writable database. Import is atomic and replays insert zero new rows.

The document picker uses user-selected local storage; Android content URIs are not guessed as filesystem paths. Export closes the stream before reporting success. Cancellation/failure can leave an incomplete external document; verification must reject it. Cache spools are app-private but not encrypted by this code. New sessions clean older completed directories down to the newest two before creating another, so up to three completed sessions may exist until the next start; abandoned partial spools older than a day are cleaned on a subsequent start. Android may also evict cache files. Keep the public export until import is confirmed; the guest share is read-only and cannot send an acknowledgment there.

## Build on an equipped machine

Pinned build configuration: Android Gradle Plugin 8.9.2, Kotlin plugin 2.1.20, JDK 17, Gradle 8.11.1, SDK platform 35 and Build Tools 35.0.0. No AndroidX or coroutine runtime is needed; JUnit 4.13.2 is test-only. AGP compatibility is documented by [Android's AGP 8.9 notes](https://developer.android.com/build/releases/agp-8-9-0-release-notes). These pins are an initial build configuration, not a claim that the current source has compiled.

With those tools/dependencies provisioned through approved channels:

```sh
cd android/collector
gradle :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
```

Expected debug artifact path: `app/build/outputs/apk/debug/app-debug.apk`. No wrapper JAR or APK is bundled; use the specified installed Gradle or generate a reviewed wrapper on the build machine. Official tool binaries may require building on a supported workstation rather than this ARM64 guest. Use an already approved Android deployment method; do not change Android security controls to bypass the current blocker.

Included JVM tests exercise timestamp preservation and invalid/clock-jump handling. They have **not run here**. After compilation, device tests must exercise permissions, lifecycle stop, stale/duplicate callbacks, queue overflow, output limits, export interruption and the nonce-file procedure. Static source checks and Python fixtures are not substitutes for these tests.

## Fixture workflow available now

From the project root:

```sh
./scripts/atlas bridge verify examples/bridge-fixture/session.atlas.json
fixture_dir=$(mktemp -d)
./scripts/atlas --db "$fixture_dir/atlas.sqlite3" bridge import examples/bridge-fixture/session.atlas.json
./scripts/atlas --db "$fixture_dir/atlas.sqlite3" report
./scripts/atlas bridge verify-probe examples/bridge-fixture/probe.json \
  --nonce b72fc58c-55d2-43cc-8c61-79a88f8b0a54
.venv/bin/python -m unittest discover -s tests -v
```

The fixture is synthetic: four radio observations, four expected findings, old fixed timestamps and explicit `synthetic:` sources. Fixture probe results must stay UNVERIFIED for Android-to-VM delivery. No fixture is represented as an actual phone scan. The runner/real-socket restrictions documented in [the development log](../../docs/development-log.md) still apply.

Once an actual export exists on the verified share, replace the fixture filename with that `.atlas.json` path. `atlas bridge verify` checks integrity without database writes; `bridge import` validates the full file and imports transactionally. All imports still represent operator-supplied evidence; hashes do not authenticate a collector.

## BLE metadata and authorized GATT source

BLE sessions export available raw advertisement bytes, advertised service UUIDs, bounded manufacturer data, connectability, completeness, RSSI and original observation times. Missing fields remain absent. Oversized fields mark the advertisement incomplete.

The **Open authorized GATT request** action reads a bounded request created by `atlas ble inspect --gatt --authorized --output PATH --address ADDRESS`, validates expiry and discovery-only scope, and asks for exact-target confirmation. Only already-bonded devices are accepted; no pairing or characteristic read/write APIs are invoked. Service/characteristic property enumeration times out after ten seconds and exports success or failure metadata. See [the BLE guide](../../docs/ble-intelligence.md) for transfer limitations, evidence schema and the complete workflow.

These additions are source only. Compilation, Android lifecycle behavior, actual Bluetooth operation and request/telemetry transfer remain unverified in this environment.

## Security update

Wi-Fi collection is off by default and has a separate optional location-permission button. BLE uses `neverForLocation`; no coordinates are collected. INTERNET/CHANGE_NETWORK_STATE support explicit bound HTTPS tests; no background-location/storage-wide permission is declared. Screenshots are restricted with `FLAG_SECURE`; actual device enforcement remains unverified. Private session cleanup bounds incomplete and completed previous spools together, and runs only when a session starts. Exported documents require separate deletion. See [security controls and limitations](../../docs/security.md).

## Cellular companion extension

`CellularCollector.kt` adds ordinary public TelephonyManager/SubscriptionManager/TelephonyCallback LTE/NR, signal/service/data/display and connectivity observations. It is opt-in and shares RadioSession clock/queue/spool/export limits. Detailed API mappings, permission checks, omission/sentinel rules, data freshness and unsupported capabilities appear in [cellular intelligence](../../docs/cellular.md). No subscriber/device identifiers, SIM authentication operations, privileged modem interfaces or raw signaling are collected.

Import a privately provisioned 32-byte hex bridge key and a new Debian challenge through the document picker before enabling cellular. Keys stay in MODE_PRIVATE preferences with app backup disabled; there is no application-level encryption/Keystore wrapping. Paired exports use `BridgeAuthentication.kt` over exact UTF-8 inner-envelope bytes including metadata. Source JVM test vectors match Python HMAC tests, but **JVM tests, lint and APK compilation have not run here**. These source changes retain compile/target SDK 35, min 31; Android 17 compatibility remains unverified.

`BoundedNetworkTest.kt` handles a separate expiring, endpoint-scoped request and explicit confirmation for one capped Wi-Fi HTTPS GET followed by one cellular HTTPS GET. It uses selected Android Network objects, normal TLS, no redirects or process binding, no unbound fallback, 4-second acquisition and 5-second operation watchdogs, and a 25-second visible-session limit. New permissions: READ_PHONE_STATE, ACCESS_NETWORK_STATE, INTERNET and CHANGE_NETWORK_STATE. Passive collection still sends no IP traffic. Device binding/routing, cancellation and actual performance have not been demonstrated.

The main screen scrolls to keep permission/import/session controls accessible. Activity stop removes cellular callbacks and cancels network tests before finalizing. Canceled tests may lack a final performance row; inspect session statuses/drop counters and do not count missing results as success. A real paired Android challenge response must be verified in Debian before claiming a functioning device bridge. No Android-produced cellular file was available during this completion.


## Optional folder delivery and no-active-subscription support

The [2026-10-29 pipeline repair](../../docs/cellular-pipeline-repair-20261029.md) adds a persistent user-selected SAF folder for automatic delivery after explicit paired sessions, `.partial` staging/rename and an optional Debian `atlas bridge watch` consumer. No background service or automatic session restart is added. CellularTargets selects the default TelephonyManager when there are no active subscriptions; exported default-radio scope contains no invented subscription ID. This attempts available public measurements without enabling any SIM/data/settings and does not guarantee measurements. New Kotlin tests and Android source remain uncompiled/unexecuted here.
