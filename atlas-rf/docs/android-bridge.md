# Android radio collector and Debian bridge

**Status: Kotlin source implemented; APK build, installation, hardware behavior and actual shared-file propagation UNVERIFIED.** The [transport investigation](vm-transport.md) was performed before implementation and records the available communication paths and missing build tools. The [collector guide](../android/collector/README.md) contains complete build, operation and fixture instructions.

Latest review: [cellular bridge findings, deployment workflow and prioritized blockers](cellular-bridge-review-20261029.md).

## Selected architecture

```text
Visible Android Activity (org.atlasrf.collector)
  WifiManager scan-result broadcast / BluetoothLeScanner callback
    → validate timestamps / identity / freshness
    → nonblocking bounded queue (256 events)
    → one private JSONL spool writer (10,000 events / 8 MiB)
    → close, hash and finalize single .atlas.json envelope
    → explicit user-selected local document export
    → Android virtiofs share, if nonce procedure verifies the chosen directory
    → atlas bridge verify / atlas bridge import
    → private Debian SQLite → existing analysis / topology / reporting
```

The guest cannot see a physical Wi-Fi PHY or Bluetooth HCI controller. Public Android APIs run inside an ordinary Android app, not inside Debian. No root, monitor mode, firmware change or security-setting modification is required by the implementation. No Android/VM shared-localhost assumption is made.

## Supported API boundary

The app uses `WifiManager`, scan-completion broadcasts, and real scan-result timestamps. It checks permissions/location-services/radio state, rate-limits app requests to no more than one per 35 seconds across sessions, and records rejected/throttled requests without treating cached results as new. There is one request per session and no retry loop. [Android Wi-Fi scanning](https://developer.android.com/develop/connectivity/wifi/wifi-scan).

BLE discovery uses `BluetoothLeScanner` with a callback and a ten-second low-power window. The app requests SCAN/CONNECT for BLE and declares `neverForLocation`; Wi-Fi and cellular have separate optional fine/coarse location permission requests. Passive discovery does not pair, connect to GATT, advertise or defeat private addresses; a separate authorized workflow enumerates GATT metadata on already-bonded devices. [Bluetooth permissions](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions), [BLE discovery](https://developer.android.com/develop/connectivity/bluetooth/ble/find-ble-devices).

No background services or boot receivers exist. Leaving the visible activity or reaching the fifteen-second session deadline stops callbacks/receivers and drains the spool. The app never toggles location, radios or scan throttling. Missing permissions and unavailable features are states in metadata, not devices. No VM network transport is included. INTERNET and CHANGE_NETWORK_STATE permissions support separately authorized Android-bound HTTPS tests.

## Time and resource contract

A stable wall-clock / elapsed-realtime anchor converts measurement timestamps to UTC. Wi-Fi microseconds and BLE nanoseconds since boot are handled separately. Invalid/future timestamps and clock jumps over five seconds are excluded. The Wi-Fi update now retains old/cache results with explicit freshness and age, supplied frequency and Android-derived channel; only fresh results qualify for the [historical Wi-Fi baseline](wifi-intelligence.md). BLE still excludes pre-session results or age over ten seconds. Deduplication and one-second BLE sampling never replace measurement time with callback/export/import time. Raw export UTC strings are retained; existing SQLite canonicalization uses microsecond precision. [Wi-Fi timestamp API](https://developer.android.com/reference/android/net/wifi/ScanResult#timestamp), [BLE timestamp API](https://developer.android.com/reference/android/bluetooth/le/ScanResult#getTimestampNanos()).

Callbacks use nonblocking queue insertion and count drops; one writer handles I/O. The event queue is 256 entries, identity map at most 10,000 entries, accepted-event count at most 10,000 and JSONL spool at most 8 MiB. A separate single I/O worker has a one-task queue. Finalization/export can allocate bounded whole-payload strings; phone memory behavior still requires measurement. This prototype does not claim a hard OS memory ceiling or proven Android queue-load behavior.

## Finalized file protocol

The earlier separate JSONL/metadata proposal has been replaced by one JSON document:

| Field | Meaning |
| --- | --- |
| `kind` | `atlas-radio-export` |
| `schema_version` | Integer 1 |
| `complete` | Boolean true, set only for finalized spool output |
| `metadata` | Session UUID, explicit synthetic flag, row/byte counts, clock anchors, statuses and drops |
| `sha256` | Hash of exact UTF-8 JSONL payload bytes |
| `payload_jsonl` | Newline-terminated observations using [OBSERVATIONS.md](OBSERVATIONS.md) |

Live-source records are labeled `android:<random-install-uuid>:wifi` or `:ble`. Fixtures use explicit `synthetic:` labels and `synthetic: true`. No fixture generator is built into the Android collector. The hash covers payload integrity against declared bytes; it does not authenticate the sender or metadata. Treat the public document as untrusted local evidence.

The guest limits input to a 16 MiB envelope, 8 MiB payload, 64 KiB metadata, 10,000 records and existing per-record bounds. It rejects partial/invalid exports, validates all records before opening a writer and imports transactionally. Replays insert zero new rows. File verification does not itself prove that radios were used.

## Transport acceptance

Android exports through the user-selected document picker to local storage. Debian's share is read-only; that is compatible with Android-side writing and guest-side reading. A chosen content URI might not map into the guest, especially for cloud providers. [Android document export](https://developer.android.com/training/data-storage/shared/documents-files).

First use the app's radio-free transport nonce export, compare its displayed nonce with `atlas bridge verify-probe FILE --nonce UUID` on the actual `/mnt/shared` path, then verify/import a real telemetry bundle. Mount visibility alone is not end-to-end verification. The exact procedure and trust limits are in [vm-transport.md](vm-transport.md).

If networking is introduced later, first verify actual endpoint addressing and require pinned TLS with client authentication, bounded framing/timeouts and replay protection. No plaintext or unauthenticated fallback is supplied.

## Current blocker and fixture continuation

The inspected environment has no JDK, Gradle, Kotlin compiler, Android SDK tools or adb. The offline Gradle build attempt fails with command-not-found. No APK or JVM/device test result is claimed. Build pins and equipped-machine commands are in [the collector guide](../android/collector/README.md).

The implemented Debian verifier/importer continues to work with `examples/bridge-fixture/session.atlas.json`, containing four synthetic radio observations and four expected findings. The local fixture path cannot establish Android-to-VM delivery. See [development-log.md](development-log.md) for commands, decisions, test results and remaining field acceptance work.

The separate [authorized BLE GATT source path](ble-intelligence.md) now accepts an expiring, bounded request document and requires visible confirmation for one already bonded target. It exports metadata-only `ble_gatt` evidence. Passive advertisements never initiate connections, pairing or writes; source compilation and device behavior remain unverified.
