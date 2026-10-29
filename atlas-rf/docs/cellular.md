# Cellular intelligence and authenticated Android file bridge

The target supplied by the operator is Pixel 10 Pro XL, Android 17, native Debian ARM64 VM. This execution establishes an aarch64 guest with a visible `/mnt/shared/Documents`, not the handset model, Android release, modem capabilities or a working companion APK. **No real cellular telemetry was available.** There is no `adb`, Java, Gradle, Kotlin compiler or Android SDK here. Companion compilation, permissions, real file delivery, subscription callbacks and Android-bound HTTPS tests remain **UNVERIFIED**. No localhost-sharing assumption is used.

## Validate transport before collecting real telemetry

ATLAS uses explicit finalized document exports. There is no guest/Android listener. A visible shared directory alone does not establish delivery or protection. Real cellular exports require HMAC-SHA256 over the exact UTF-8 inner envelope, covering metadata and payload. A new 256-bit Debian challenge must match the signed `metadata.bridge_nonce`. Unkeyed payload hashes alone are insufficient. Local synthetic protocol tests exercise successful verification, tampering, wrong/missing keys and challenges, and private shared-secret file enforcement; they do not prove an Android transfer.

1. On an equipped build machine, build/test/lint the [companion](../android/collector/README.md) using its pinned toolchain and install through an approved method. No APK was built here.
2. Create a private bridge key and challenge in Debian. Output files must not already exist:

```sh
mkdir -m 700 -p "$HOME/.local/share/atlas-rf/cellular-pairing"
./scripts/atlas cellular bridge-key --output "$HOME/.local/share/atlas-rf/cellular-pairing/phone.key"
./scripts/atlas cellular challenge --output "$HOME/.local/share/atlas-rf/cellular-pairing/challenge.json"
```

3. Provision the key to Android through a **trusted document transfer**. The read-only guest share cannot be assumed to support Debian-to-Android provisioning. Use an existing approved mechanism; confirm the document source rather than downloading an untrusted key. In the companion press **Import bridge key**, then **Import current Debian bridge challenge**. The key is app-private, backup disabled; delete temporary transfer/provider copies. Keep the original Debian key under private owned ancestors, file mode 0600. It must not reside in shared storage. Pairing/provisioning itself has not been demonstrated here. Re-importing a key clears the previous challenge.
4. For an initial delivery check, start a short explicit session without enabling cellular/Wi-Fi if desired, stop/finalize, and export to a local document provider known to map to the guest. A paired session signs even an empty export. Do not grant cellular permissions until this file path works. Compare the challenge from the Debian file (it is public) and verify the actual Android-exported file:

```sh
./scripts/atlas cellular verify \
  --input /mnt/shared/Documents/ATLAS-RF/ACTUAL_EXPORT.atlas.json \
  --key "$HOME/.local/share/atlas-rf/cellular-pairing/phone.key" \
  --nonce REPLACE_WITH_NONCE_FROM_CHALLENGE_JSON
```

5. Acceptance requires `challenge_verified: true`, `authenticity: SHARED_KEY_VERIFIED`, `synthetic: false`, the expected session/counts, and operator confirmation that this file came from the paired app's completed export. `hardware_access` remains `UNVERIFIED`: a valid MAC proves shared-secret possession, not truthful radios. A locally generated fixture cannot satisfy device acceptance. Retain the signed original alongside evidence. Generate/import a new challenge before a new assessment; using the same challenge accepts the same signed export again, with observation/session replay deduplication, rather than pretending to provide one-time nonce consumption.
6. Only after delivery succeeds, grant **READ_PHONE_STATE** and precise location using the optional cellular permission button, check the existing location-services state if cell identity is wanted; if disabled, record the limitation without changing device settings, check **Include cellular telemetry**, and run an explicit session. Export and import:

```sh
./scripts/atlas --db PRIVATE_DB cellular ingest --input ACTUAL_EXPORT.atlas.json \
  --key PRIVATE_KEY_FILE --nonce EXPECTED_CHALLENGE
./scripts/atlas --db PRIVATE_DB cellular inspect --source android:INSTALL_UUID:cellular
```

`atlas bridge verify/import FILE --key KEY --nonce NONCE` also supports signed mixed-radio exports. Generic raw imports cannot promote `android:` cellular JSONL into authenticated telemetry. Cellular JSONL is accepted only with `--synthetic` and `synthetic:` sources; synthetic bundles require `--synthetic`. A missing field stays absent. No data was silently replaced with fixtures during device integration.

### Envelope

The outer document is exactly `{kind: "atlas-authenticated-export", schema_version: 1, signed_json: STRING, hmac_sha256: HEX}`. Its MAC is `HMAC-SHA256(key, UTF8("ATLAS-RF authenticated export v1\n") || UTF8(signed_json))`. `signed_json` is the existing `atlas-radio-export/v1` envelope. The payload checksum, bounded unique-key JSON parsing, row counts, complete-record validation and atomic storage checks still apply after authentication. Metadata includes the challenge, session UUID, clock anchors, per-collector statuses and queue drops. The signing key is never exported with telemetry or logged. The 16 MiB outer/8 MiB payload bounds still apply; heavily escaped content may hit the outer bound earlier and be rejected.

The same 32-byte secret is used on Android to generate MACs and on Debian to verify them. There is no asymmetric private signing key/public verification key pair in this transport. Either holder can forge a valid export. APK signing uses separate asymmetric credentials and does not authenticate telemetry. HMAC is shared-key authentication, not encryption, forward secrecy, hardware attestation or nonrepudiation. An operator, compromised companion or stolen key can forge data. Challenge renewal prevents accepting an old response under a new expected challenge; exact re-import under the same challenge is intentionally idempotent. Keys are separate transport pairing secrets, **not SIM authentication material**. No SIM keys are accessed.

## Public Android API investigation

| API | Use and limitations |
| --- | --- |
| [TelephonyManager](https://developer.android.com/reference/android/telephony/TelephonyManager) | `createForSubscriptionId`, public SIM state, cached cell read and one `requestCellInfoUpdate` per subscription binding. Requests are rate-limited and not guaranteed to refresh; failures/empty lists are status, not proof of no cells. |
| [SubscriptionManager](https://developer.android.com/reference/android/telephony/SubscriptionManager) | Active subscriptions, carrier display label, slot and subscription-local ID; listener rebinding on subscription-set change. READ_PHONE_STATE is requested; no carrier privileges are assumed. No phone number or subscriber/device identifier call is used. At most 8 active subscriptions are processed. |
| [TelephonyCallback](https://developer.android.com/reference/android/telephony/TelephonyCallback) | Separate public cell callback from service, signal, data-connection and display callbacks, so a denied location/cell registration does not disable all state collection. Basic registration failures and missing services/features are reported. All registrations are removed at session stop. |
| [CellInfoLte](https://developer.android.com/reference/android/telephony/CellInfoLte), [CellInfoNr](https://developer.android.com/reference/android/telephony/CellInfoNr) | LTE/NR identity, registration flag and primary/secondary/none/unknown connection role. Other RAT cell types are reported unsupported. Serving and nonregistered neighboring observations remain distinct. At most 256 cells per callback. Neighbors may be omitted/redacted by modem/carrier/API. |
| [CellIdentityLte](https://developer.android.com/reference/android/telephony/CellIdentityLte), [CellIdentityNr](https://developer.android.com/reference/android/telephony/CellIdentityNr) | CI/NCI, PCI, TAC, MCC/MNC strings, EARFCN/NR-ARFCN and public bands. MNC leading zeroes are retained. ARFCN is the reported channel/frequency identifier, not a measured Hz value. No guessed band/frequency conversion or inferred tower identity. |
| [CellSignalStrengthLte](https://developer.android.com/reference/android/telephony/CellSignalStrengthLte), [CellSignalStrengthNr](https://developer.android.com/reference/android/telephony/CellSignalStrengthNr) | LTE RSRP/RSRQ/RSSI and `rssnr` in **public API dB**, not raw RIL tenths. NR SS-RSRP/SS-RSRQ/SS-SINR. Sentinel/out-of-range values are omitted, never zero-filled. Public LTE RSSNR is described as reference-signal SNR; it is not relabeled as a separately measured generic SINR. |
| [TelephonyDisplayInfo](https://developer.android.com/reference/android/telephony/TelephonyDisplayInfo) | Raw network-type and display-override codes are kept separately. A 5G icon/override is not proof of NR serving attachment; NSA may continue to report LTE data RAT. |
| [ConnectivityManager](https://developer.android.com/reference/android/net/ConnectivityManager) | Default transport/validation and passive availability/loss of INTERNET-capable cellular networks. Default Wi-Fi loss is not cellular deregistration. Cellular availability is device network state, not mapped to a SIM. ACCESS_NETWORK_STATE is required. |
| [Network.openConnection](https://developer.android.com/reference/android/net/Network#openConnection(java.net.URL)) | A separate opt-in network test requests Wi-Fi/cellular INTERNET-capable, non-VPN networks, then opens HTTPS through the selected `Network`. No process-wide binding or VM-interface substitution. INTERNET and CHANGE_NETWORK_STATE are declared for this explicit operation. |

READ_PHONE_STATE is a dangerous runtime permission. Detailed cell access additionally depends on precise ACCESS_FINE_LOCATION (requested with COARSE), Android location settings, feature support and runtime/carrier policy. Permission revocation and API restrictions are expected conditions. No background location, root, system UID, privileged phone permission, modem diagnostic device, raw modem signaling or SIM authentication operation is used. The pinned app still compiles/targets SDK 35 with minimum 31; **Android 17 runtime compatibility and target-SDK policy have not been validated**. It does not pretend that changing a version number establishes compatibility.

## Observation and storage semantics

`kind=cellular` uses the common event schema, SQLite `observations`, canonical fingerprints, structured CLI logging, bounded readers and resource checks. `cellular_event` is `subscription`, `cell`, `signal`, `service`, `technology`, `connectivity` or `performance`. Every event carries the original source, collection session and original observation instant. Telephony events carry a subscription-local ID. Identity is source-scoped; no geographic position is computed. Optional values preserve availability by omission; booleans, nulls and Android unavailable sentinels cannot masquerade as measurements.

CellInfo's boot-relative `timestampMillis` is converted using the existing fixed session wall/elapsed clock anchor. The modem-time estimate is `observed_at`; callback receipt is `received_at`. `measurement_elapsed_ms` and `cell_age_ms` retain modem-age evidence. A successful update/callback aged at most 10 seconds is `recent`; cached reads and older samples are `cached`; missing timestamps are `unknown` and use receipt time explicitly, never a claimed measurement time. Known pre-session measurements retain their original time. Wall-clock jumps over 5 seconds and invalid/future elapsed times are dropped by the existing clock policy. Duplicate modem samples do not inflate training/trend counts. UTC normalization preserves instants at microsecond precision; signed exports retain the original strings.

Signal-strength callbacks do not provide per-cell measurement timestamps or reliable cell association: they retain callback receipt time and `unknown` freshness and do not drive cell-specific trends. Service state is the public aggregate `ServiceState.state`, not a complete PS/CS/NAS registration trace. Data connection state and network type are separate callback fields.

`cellular_sessions` retains bounded exported status/drop/clock metadata and the original payload digest, authentication flag and sources. This preserves availability failures even for zero-row cellular sessions. Import metadata is deduplicated by content, excluding local import time. Keep the signed file for independent authentication; the database digest alone is not the original signed evidence. `cellular_baselines` freezes explicitly reviewed training history; neither later imports nor analysis retrain it. Both tables use the existing private SQLite file and evidence-verification/retention systems. Raw-data expiration invalidates derived baseline/session copies; external exports and key files require separate lifecycle management.

## Historical baselines and deterministic rules

```sh
./scripts/atlas --db PRIVATE_DB cellular baseline --source SOURCE --through ISO_UTC_CUTOFF
./scripts/atlas --db PRIVATE_DB cellular baseline --source SOURCE --show
./scripts/atlas --db PRIVATE_DB cellular inspect --source SOURCE --baseline --limit 2000
./scripts/atlas --db PRIVATE_DB dashboard --once --protocol cellular --view findings
./scripts/atlas --db PRIVATE_DB report --format json
```

Baseline creation requires recent registered cell samples with complete RAT/MCC/MNC/cell-ID identity. It deduplicates modem timestamps and freezes cells plus per-metric count/median/min/max by subscription. It is reviewed history, not a trusted tower list. Carrier/subscription reconfiguration may require a newly reviewed baseline. Training reads are bounded at 50,000 rows and fail rather than silently truncate; inspection defaults to latest 2,000 and reports truncation (maximum 5,000). Broad report/dashboard windows can omit older history, so absence of a hint is not proof of continuity.

Rules are versioned `cellular/v1`; findings contain stable hashes and supporting observation fingerprints. Comparisons never cross source, session or subscription; cell comparisons also separate RAT and primary/secondary/unknown role. Comparisons require strictly increasing observation times with gaps at most 300 seconds. Nonregistered neighbors and cached/unknown cell measurements are retained but excluded from serving comparisons/trends.

| Rule | Exact condition and interpretation |
| --- | --- |
| `serving-cell-change` | Two eligible complete cell identities differ within a RAT/role series. Informational reported cell change, not authenticated physical handover. |
| `cell-identity-frequency-change` | PCI, TAC, ARFCN or band list changes within the same complete logical cell identity. Informational. |
| `cell-not-in-reviewed-baseline` | Eligible complete post-cutoff serving identity absent from that subscription's reviewed cells; emitted once per identity/session. Informational novelty. |
| `lte-nr-transition` | Reported data `network_type` changes 13↔20. Both LTE→NR and NR→LTE are informational. No automatic NSA inference. |
| `network-display-change` | Supplied display override changes, retained independently from measured RAT. Informational. |
| `sustained-signal-degradation` | At least 3 strictly timed recent same-cell samples, monotonically nonincreasing, total duration ≤300s, drop ≥10 dB for RSRP/RSSI or ≥5 dB for RSRQ/RSSNR/SS-SINR. Review hint only. Trends also include median, endpoint delta and endpoint slope/minute. |
| `cellular-data-interruption` | Data state 2→0/3/4 within comparison window (disconnected/suspended/disconnecting). Review the reported transition; no proof of complete radio outage. |
| `cellular-registration-interruption` | Aggregate service state 0→nonzero within comparison window. Review hint, not NAS evidence. |
| `cellular-connectivity-interruption` | Previously available INTERNET-capable cellular network becomes unavailable. Review hint; not necessarily loss of registration. |

Sparse callback fields retain independent prior values; an intervening display callback cannot erase the previous data-connection state. Signal runs split at gaps over 300 seconds. **No rule classifies unfamiliar cells, changed signal, normal handover or NR fallback as an IMSI-catcher attack.** There is no confirmed-attack classifier or field accuracy claim.

## Explicit Wi-Fi versus cellular tests

```sh
./scripts/atlas cellular performance-request --authorized \
  --endpoint https://YOUR_AUTHORIZED_SERVER/atlas-test \
  --output NEW_REQUEST.json
```

Transfer this public request to Android, open **Open authorized Wi-Fi / cellular HTTPS test request**, and confirm the exact endpoint. Requests expire after 10 minutes. The companion uses a separate visible session, one Wi-Fi GET then one cellular GET. Each network request waits at most 4 seconds; each HTTPS operation has 5-second connect/read limits plus a disconnect watchdog. A session stops at 25 seconds or when the activity stops. There is no default endpoint and no automatic background test. Up to 64 KiB response payload per test (plus protocol/server overhead) may consume mobile data. No redirects, credentials, query/fragment tokens or cleartext HTTP are accepted. Normal system TLS certificate/hostname checks remain enabled. Tests do not send cellular observations or identifiers to the endpoint.

Successful records require verified requested transport, per-`Network` binding, HTTP 2xx, response bytes and completion duration. Denied/unavailable networks and HTTPS failures are distinct outcomes. There is no unbound fallback. Comparison groups only the same source, collection session, test ID and endpoint, with successful bound records and matching response byte counts. Reported bytes/second is a capped application transfer including DNS/TLS/server/scheduling time, **not radio link capacity or packet RTT**. Sequential tests do not control changing coverage/server load. The selected cellular network is not explicitly pinned to a subscription; VPN/enterprise/carrier policy may prevent direct access. Cancellation can omit an unfinished result; queue/session drop/status evidence must be consulted. No actual Wi-Fi/cellular traffic test ran here.

## Reproducible synthetic validation

```sh
./scripts/atlas --db NEW_PRIVATE_DB cellular ingest \
  --input examples/cellular/session.atlas.json --synthetic
./scripts/atlas --db NEW_PRIVATE_DB cellular baseline \
  --source synthetic:android:cellular-lab --through 2026-04-18T10:01:00Z
./scripts/atlas --db NEW_PRIVATE_DB cellular inspect --source synthetic:android:cellular-lab --baseline
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/verify_cellular.py --output NEW_DIRECTORY --events 10000
```

The [generator](../examples/cellular/generate.py) emits only `synthetic:` sources and `metadata.synthetic=true`. The example endpoint is `example.invalid`; no synthetic fixture test performs network I/O. The 25-record scenario yields 11 expected hints with a three-sample reviewed baseline and four metric trends. The HTTPS durations are invented comparison inputs, never hardware performance evidence. See [test results](../test-results.md) and [preflight evidence](../artifacts/cellular-transport-preflight.json).

**Unsupported/unverified:** actual Android 17 APK build/install; trusted key provisioning and phone-to-VM challenge response; physical modem/API availability; complete multi-SIM/NSA identity; exact measured Hz; full PS/CS/NAS registration; cell-specific callback timestamps; real bound IP tests, packet RTT, upload capacity, field anomaly accuracy and hardware event loss. IMSI, ICCID, IMEI, SIM authentication keys and raw modem signaling are neither queried nor accepted as event fields. Cell IDs are radio-network identifiers and can still reveal location context; treat exports as sensitive.
