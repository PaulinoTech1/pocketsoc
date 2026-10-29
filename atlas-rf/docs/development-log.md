# Development process record

This log records work performed, decisions made and verification limits. It is not a claim that planned integrations have been delivered.

## 2026-10-29 — Initial platform

1. Inspected the workspace and wrote [DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md) before implementation.
2. Chose Python standard-library SQLite, asynchronous bounded TCP probes, curses, JSONL file import and explicit optional guest radio adapters. No phone-radio passthrough or root requirement was introduced.
3. Implemented normalized observations, atomic import and replay handling, source-aware anomaly rules, evidence graph, report generation and the original `atlas-rf` CLI.
4. Verified 19 unittest cases: 18 passed, one skipped because this execution environment denies real TCP socket creation. Exercised synthetic CLI import/replay/history/report/topology/purge and pseudo-terminal dashboard.
5. Measured an initial 10,000-observation synthetic workload: 53,436 KiB peak RSS; see [VALIDATION.md](VALIDATION.md). This was not a Pixel hardware-access or battery benchmark.

## 2026-10-29 — Environment compatibility investigation

1. Used `uname`, `lscpu`, `/proc/meminfo`, `free`, `df`, `lsblk`, sysfs, `ip`, `ss`, mount inspection, capability masks and version/PATH checks.
2. Found Debian 13.7 ARM64, about 5.9 GiB RAM, no exposed Wi-Fi PHY or Bluetooth HCI, zero process capabilities, restricted netlink/socket access, and read-only Android virtiofs storage at `/mnt/shared`.
3. Distinguished broader mounted sysfs visibility from current-process networking. Did not treat a visible virtio interface as confirmed usable networking.
4. Recorded all nine requested inspection areas with SUPPORTED / UNSUPPORTED / UNVERIFIED classifications in [environment.md](environment.md).
5. Designed [android-bridge.md](android-bridge.md): an ordinary Android app using public APIs and runtime permissions, finalized document export and explicit guest import. No APK, live bridge or simulated hardware access was implemented.

## 2026-10-29 — Modular application architecture

### Inspection and dependency decisions

Read existing CLI, collectors, observation model, analysis and SQLite implementation before making changes. Checked Python package availability:

```text
python3: 3.13.5
PyYAML: 6.0.2, Debian system package
pip: unavailable
ensurepip: unavailable (normal `python3 -m venv .venv` failed)
setuptools: unavailable
pytest: unavailable
curl request to PyPI: failed DNS resolution in restricted execution environment
```

Created the environment without network or system changes:

```sh
python3 -m venv --without-pip --system-site-packages .venv
```

Declared PyYAML as the only runtime dependency, setuptools as the build backend and pytest as an optional development dependency. Added source-checkout launchers so missing build tools do not prevent running the actual venv application. No replacement/fake pytest runner was created.

### Implementation decisions and sequence

1. Moved canonical implementations into `atlas/core`, `wifi`, `bluetooth`, `network`, `detection`, `topology`, `storage`, `bridge`, `ui` and `reporting`. Retained thin compatibility imports for the original CLI and tests. Existing SQLite schema version remains 1.
2. Implemented immutable configuration dataclasses and bounded safe YAML parsing with duplicate/unknown key rejection, path resolution and type/range validation. Added [config/atlas.yaml](../config/atlas.yaml).
3. Implemented structured JSON stderr logging and optional private rotating file logs (1 MiB, two backups), with stable event identifiers and a versioned envelope.
4. Added the process exception boundary and distinct expected-error, unexpected-error, resource-limit and interruption outcomes. Avoided logging arbitrary unexpected exception payloads or YAML content.
5. Added procfs/resource-based memory, CPU and disk monitoring without psutil. Used cooperative RSS/reserve checks, bounded history windows and an interruptible loop; documented that these are not hard OS memory guarantees.
6. Added read-only SQLite reader transactions for status/reports; missing status does not initialize storage, and missing/corrupt report input fails explicitly.
7. Implemented `atlas status`, `atlas doctor`, `atlas monitor` and `atlas report`. Doctor exercises local inspection capabilities rather than treating utility presence as success. Monitor emits resource telemetry only; it does not start radio collection or TCP probes.
8. Added pytest-compatible unittest coverage and three fixture-based pytest workflows. Kept Rust out because no measured bottleneck justifies native code.
9. Updated installation/startup and architecture documentation, linked the environment and bridge design, and retained a record of blocked verification rather than reporting it as passed.

### Verification record

Commands run from the project root using the actual virtual environment:

```sh
.venv/bin/python -m atlas --config config/atlas.yaml status
.venv/bin/python -m atlas doctor
.venv/bin/python -m atlas monitor --once
.venv/bin/python -m unittest discover -s tests -v
```

At the initial modular application checkpoint: **44 unittest tests, 43 passed, one skipped** (real TCP integration blocked by socket restrictions). This includes all 19 original tests and 25 application tests. pytest fixture workflows are added in `tests/test_pytest_workflows.py`; they require the real pytest runner and are not executed by unittest. Subsequent final checks and measurements are appended below.

Coverage includes strict YAML parsing and limits, read-only/missing/corrupt/versioned SQLite, source-aware findings, log formatting/rotation, resource reserve failures, CLI stdout/log separation, error exit codes, live capability classification, finite monitoring and clean SIGTERM shutdown. Tests do not establish phone radio availability or a working Android bridge.

### Remaining external verification

- Run the full pytest suite after the declared development dependency can be installed; no network/security bypass is proposed.
- Run the real-socket integration test in a permitted target terminal.
- Build and field-test the proposed Android companion/export path separately.
- Measure sustained use and battery/thermal behavior on the target phone. Short command RSS measurements are not sustained deployment benchmarks.

### Final verification checkpoint

- Added a configuration guard preventing the log file from sharing the database path, including after a CLI database override. Otherwise file logging could corrupt an observation database before a read-only open.
- Verified log rotation recreates files with 0600 even under umask 0022, independently of the CLI's umask.
- Final offline suite: **45 tests, 44 passed, one skipped** for the denied real TCP socket. Three additional fixture-based pytest tests remain unexecuted by the unavailable runner.
- Explicit runner check: `.venv/bin/python -m pytest --version` reports `No module named pytest`. This is an environment limitation, not a successful pytest run.
- New CLI smoke workflow: imported seven synthetic observations through the preserved command, read them with `atlas status`, generated five findings through `atlas report`, refused output overwrite, and emitted exactly three resource samples at a configured 0.5-second interval.
- Three-sample monitor peak RSS: **24,698,880 bytes (about 23.6 MiB)** in the measured subprocess. This is a short local run, not an enforced hard ceiling or sustained device benchmark.
- Confirmed the source launcher works from `/tmp`, respects `XDG_DATA_HOME`, and does not create missing observation storage during status.
- Checked `atlas` and `atlas-rf` version launchers (both 0.2.0), compiled Python sources, validated local documentation links, and confirmed execution inside `.venv` with Debian PyYAML 6.0.2.

The process, architecture and startup paths are documented in this log, [architecture.md](architecture.md), and [installation.md](installation.md). No Android security changes, radio simulation or root escalation was used.

## 2026-10-29 — Minimal Kotlin collector and finalized file transport

### Investigation before implementation

Rechecked mount options, candidate device/communication paths, `/proc/net`, sysfs driver visibility and current tooling. Shared Android Documents remains visible through read-only virtiofs. AF_INET and AF_VSOCK socket creation fail with EPERM; AF_UNIX local socket creation succeeds but does not establish a host/VM channel. No shared-localhost, host endpoint or cross-VM Unix socket route was assumed. Recorded the full method/status matrix and operator nonce verification procedure in [vm-transport.md](vm-transport.md).

Java, Gradle, Kotlin compiler, Android SDK tools and adb are absent from PATH; conventional SDK/JDK/cache locations checked did not provide them. Attempted the offline Gradle test/build command; it failed with command-not-found exit 127. No APK build, signing, installation or Android radio exercise occurred. Consulted primary Android Wi-Fi, BLE, storage, timestamp and build-compatibility documentation before choosing supported APIs and pinned build configuration.

### Source implementation

Added `android/collector` with Gradle Kotlin build files, a minimal platform Activity and supported WifiManager / BluetoothLeScanner collectors. It uses explicit permission requests, no INTERNET permission, no background service or automatic startup, ten-second low-power BLE scanning and a fifteen-second visible session. The app does not change radio, location or security settings.

Added a 256-item nonblocking callback queue, one spool writer, 10,000-event / 8 MiB session limits, bounded identity history, drop counts and a separate bounded I/O executor. Timestamp conversion uses one stable wall/elapsed clock anchor, real platform measurement timestamps, stale-result exclusion and fail-closed clock-jump checks. Wi-Fi requests are rate-limited across sessions and unsuccessful broadcasts do not fabricate fresh sightings. A nonce-only export can test transport without requesting radio permissions.

Finalized exports are a single JSON envelope containing a complete marker, metadata, SHA-256 and exact JSONL bytes. The private bundle is renamed from a temporary file after close; user-selected document export reports success only after the destination stream closes. SHA-256 is integrity against declared payload, not authentication. Public exports remain sensitive; no keys/credentials are written into them.

### Debian integration and fixture fallback

Implemented `atlas bridge verify`, `atlas bridge import` and `atlas bridge verify-probe`. The parser rejects nonregular/symlink inputs, oversized/partial envelopes, duplicate keys, wrong versions, invalid counts/hashes, provenance conflicts, malformed observations and non-radio event kinds. Import validates the entire file before opening a writer and uses a transaction; replays remain deduplicated. Raw JSONL legacy import remains available separately.

Added an explicitly synthetic bundle with four radio observations and a synthetic nonce file. No fixture was written into the Android share or represented as Android data. The fixture establishes local verifier/importer behavior only. Real Android-to-VM file propagation remains UNVERIFIED until the app-displayed nonce is read from the actual shared path and a real telemetry export is checked.

### Verification and limits

At the initial bridge checkpoint, **58 offline tests: 57 passed, one skipped** (real TCP socket restrictions). Thirteen added tests cover fixture provenance, truncation/tamper/complete/count checks, duplicate keys, invalid events, timestamp retention, atomicity/replay, nonce mismatch and CLI integration. Three pytest-fixture workflows from the previous phase still require the unavailable pytest runner. Included Kotlin JVM timestamp tests are unexecuted because the JVM/Gradle toolchain is missing.

The source prototype is reviewable, but compilation, Android lifecycle/API behavior, actual bounded-queue load behavior and real file propagation are not claimed verified. Follow the equipped-build/device acceptance steps in [the collector guide](../android/collector/README.md). No root, monitor mode, custom firmware, adb enablement or Android security change was used. Future network transport would require verified addressing and mutually authenticated/pinned TLS; no unauthenticated fallback was added.

Final bridge smoke check: confirmed well-formed manifest XML with no INTERNET permission, service or manifest receiver; checked local documentation links; ran the source launcher with a temporary database, imported the synthetic bundle (four new rows), replayed it (zero new rows) and generated four findings. Fixture sources stayed synthetic throughout. No file was transferred from an Android app during this check.

## 2026-10-29 — Wi-Fi intelligence subsystem

### Contract and design

Inspected the existing event validator, SQLite writer/reader, CLI, bridge envelope, legacy rules and Kotlin source. Consulted the public Android ScanResult/channel conversion documentation and AOSP implementation before defining frequency/channel consistency checks. Kept canonical SSID/BSSID fields (`name`/`id`) and added optional `frequency_mhz`, `channel`, `scan_freshness` and `scan_age_ms`, without synthesizing absent measurements.

Chose immutable, explicitly trained baselines scoped by exact source, rather than automatic learning on each import. Snapshots are additive SQLite records; existing v1 history remains intact. Training streams measured-time history, excludes cached/stale/unknown records, deduplicates repeated measurement timestamps and fails explicitly at aggregate bounds. Anomaly assessment reads a saved baseline and later fresh measurements, reports late pre-cutoff data and never retrains implicitly.

### Implementation

Added `atlas/wifi/schema.py`, `ingest.py` and `intelligence.py`; wired `atlas wifi scan`, `baseline` and `anomalies`. Scan accepts explicit JSONL/finalized file exports and reports no radio scan performed. Baseline writes and inserts are transactional; read/show/anomaly paths use read-only SQLite transactions. Previous snapshots remain selectable by ID.

Implemented all five requested detections with evidence and conservative classification. Duplicate SSIDs alone never trigger the suspicious-duplication rule: an unfamiliar SSID/BSSID association must additionally advertise OPEN/WEP against consistently stronger known security. Unknown baseline security prevents this assumption. Channel changes require three supplied training measurements and remain informational because DFS/automatic selection can be legitimate. All output remains review hints, not confirmed attacks.

Updated Kotlin source to export supplied frequency, Android-derived channel, monotonic callback age and freshness. Wi-Fi cache/stale evidence is now retained and labeled rather than discarded; original measurement timestamps are preserved. BLE bounds remain unchanged. Kotlin compilation/device behavior remain unverified due the documented missing toolchain. Existing bridge bounds/hash/transaction behavior continue to apply to extended observation records.

### Fixtures and verification

Added deterministic, explicitly synthetic mixed 2.4/5/6 GHz fixtures and generator. Training has 18 rows, 15 eligible samples and five BSSIDs; excluded stale/cached/unknown data stays in history. Evaluation expects nine review hints across the five rules, with normal multi-AP duplication, hidden SSIDs, unknown security, stale/cached rows and repeated measurements handled separately.

Automated coverage includes field/type/range/pair validation, special channels, missing data, freshness contradictions, source separation, immutable/persistent snapshots, out-of-order/late imports, token-order normalization, duplicate-SSID safety, unknown-security caution, training rollback, output truncation, replay/atomicity, legacy compatibility and the complete CLI workflow.

A synthetic 10,000-observation / 200-BSSID streaming baseline benchmark measured **26,760 KiB peak RSS** (about 26.1 MiB), 0.175 seconds insertion and 0.069 seconds baseline construction on this execution host. It is not a Pixel radio or sustained battery benchmark. No Rust bottleneck was identified.

The current subsystem behavior, commands and caveats are documented in [wifi-intelligence.md](wifi-intelligence.md). No direct Android hardware access, radio measurement invention, security setting change or network bridge is introduced.

Final Wi-Fi verification: **79 offline tests, 78 passed and one skipped** for restricted real TCP socket creation. This includes 21 Wi-Fi-specific tests; the preexisting three pytest fixture functions remain unexecuted without pytest. Source compilation checks and local documentation-link checks passed. A separate launcher smoke workflow stored 18 training records, trained 15 fresh samples across five BSSIDs, stored 12 evaluation records, replayed with zero insertions and produced nine review hints. Evaluation exclusions were one cached row, one stale row and one repeated measurement. The scan result explicitly reported `radio_scan_performed: false`. No actual wireless observations were collected during verification.

## 2026-10-29 — BLE analysis completion and verification

Resumed the unfinished BLE engine task from existing advertisement/GATT source changes. Implemented and verified `atlas ble scan`, passive `atlas ble inspect`, explicit discovery-only GATT request generation, and `atlas ble anomalies`. Extended the observation contract and finalized bridge format for bounded BLE advertisement metadata and GATT service/characteristic-property evidence. SQLite retains original observation times and source labels; additive findings retain timestamps, heuristic confidence, imported provenance confidence and unverified physical identity confidence.

Review rules cover source-history advertising-service novelty, temporal advertisement configuration changes, added advertised capabilities and differences between successful GATT discovery snapshots. Comparisons never merge different addresses by name, UUID or payload. Incomplete advertisements cannot establish configuration changes or removed capabilities; unsuccessful GATT discovery never replaces a successful snapshot. Complete GATT results require an explicit service list, preventing absent metadata from falsely claiming zero services. History/address/service/finding bounds report incomplete coverage.

The Android source exports available advertisement bytes, names, RSSI, service UUIDs, manufacturer data and completeness. Explicit target requests expire in fifteen minutes, require Android confirmation and restrict discovery to already-bonded targets. No pairing or characteristic write/read APIs are invoked. Discovery closes on completion, timeout or cancellation. Oversized GATT records fall back to an explicit truncated result rather than silently dropping the only discovery outcome. Consulted primary Android ScanResult/ScanRecord/BluetoothGatt API documentation; references and operating instructions are in [ble-intelligence.md](ble-intelligence.md).

Verification on resumption:

- `.venv/bin/python -m unittest discover -s tests -v`: **100 tests, 99 passed, one skipped** for restricted TCP socket creation. Includes 21 BLE checks across `test_ble.py` and `test_ble_bounds.py`.
- Source-launcher smoke test: imported eleven synthetic BLE records, replay inserted zero, assessment saved four review hints, passive inspection returned ten records for the selected address without connecting. Scan output reported `radio_scan_performed: false`.
- Python compilation and local documentation-link checks passed; Android manifest XML parsed successfully.
- `.venv/bin/python -m pytest --version` still reports `No module named pytest`. Three existing pytest fixture workflows remain unexecuted by the offline unittest runner.
- Java, Gradle, Kotlin, adb and SDK manager remain absent from PATH. Android compilation, installation, lifecycle behavior, real radio/GATT operation and cross-boundary file delivery remain **UNVERIFIED**. No actual Bluetooth collection, GATT connection or Android security change occurred in these checks.

Synthetic fixtures and their generator are under `examples/ble`; use a separate demo database. BLE findings remain an additive audit table and are not included in legacy observation purge or the general report's rule list; detailed evidence is available through `ble anomalies`. The guide documents retention and transport limitations explicitly.

## 2026-10-29 — Bluetooth Low Energy analysis engine

Inspected the existing validators, bridge, CLI/storage, Android BLE callback path and Activity before implementation. Consulted Android ScanRecord/ScanResult, GATT discovery/connection and runtime-permission references. Kept Android radio access separate from Debian ingestion.

Added bounded advertisement bytes, advertised names/RSSI, service UUIDs, manufacturer data, connectability/completeness and evidence provenance to the schema. Added separate `ble_gatt` events for scoped enumeration metadata; characteristic values/write requests are not supported. Existing events remain readable and missing fields remain absent.

Implemented `atlas ble scan`, passive `atlas ble inspect` and `atlas ble anomalies`. Analysis streams source history, uses a five-minute address comparison window and never links addresses by shared names, bytes or UUIDs. It treats UUID novelty, advertisement configuration changes, advertised capability additions and complete GATT metadata changes as confidence-labeled review evidence. Partial/missing data and failed enumeration never establish capability loss. SQLite saves stable evidence IDs with timestamps/confidence transactionally; replay remains idempotent.

Implemented `atlas ble inspect --gatt --authorized --output FILE` as explicit creation of a fifteen-minute, exact-address discovery-only request. It does not connect from Debian. The Android source app opens that file through the document picker and requires a separate visible confirmation. The GATT inspector restricts connections to already bonded targets, uses LE/autoConnect=false, enumerates service/characteristic metadata, and stops on timeout/authentication failure/activity exit. It initiates no pairing, characteristic value reads, notifications, descriptor operations or writes. This restriction was chosen to avoid pairing unknown devices as a side effect of assessment.

Extended the Android advertisement collector using supported ScanRecord APIs, bounded its exported metadata, and added the enumeration-only source path. Existing read-only shared-file and missing-toolchain constraints remain: no automatic reverse request transfer, APK compilation, installation or actual GATT session was verified. No Android security change or root operation occurred.

Added deterministic synthetic beacon, possible address-rotation, partial advertisement and authorized GATT metadata fixtures. Initial verification: **97 offline tests, 96 passed, one skipped** for restricted TCP sockets; eighteen added BLE tests cover schema/bounds, exact authorization, no-write/no-pairing attestations, physical-identity caution, partial/failure handling, source separation, temporal expiry, persistent confidence/timestamps, replay and CLI operation. The preexisting three pytest fixture functions still require the unavailable pytest runner; Kotlin compilation/device tests remain unexecuted.

Detailed commands, contracts, confidence semantics, safety boundaries and field acceptance limits are documented in [ble-intelligence.md](ble-intelligence.md).

Final BLE checkpoint: **100 offline tests, 99 passed and one skipped** (real TCP sockets denied). This includes regression coverage for explicit complete-GATT service results, the 100,000-row analysis bound, provenance labels in findings and rejecting invalid imports before database creation. Three pytest fixture functions remain outside the offline unittest run; no Kotlin/Android test execution is claimed.

The final launcher smoke check imported eleven synthetic records, replayed with zero new rows, produced and saved four findings, and saved zero duplicate findings on repeated analysis. `radio_scan_performed` remained false. All local documentation links passed validation. A separate synthetic 10,000-record / 100-address run measured **29,760 KiB peak RSS** (about 29.1 MiB), 0.205 seconds insertion and 0.047 seconds streaming analysis with no configured change hints. These are local synthetic performance figures, not phone RF, GATT, battery or hardware measurements.

### BLE requirement recheck

Rechecked the repeated BLE request against the completed engine, Android source, schema, authorization flow and synthetic fixtures. Fixed a finding-limit accounting defect: duplicate review hints are now deduplicated before testing the output limit, so a repeated hint at the limit does not falsely mark complete coverage as truncated. Added a regression that failed before the correction.

Validation: **101 offline tests, 100 passed and one skipped** for restricted TCP socket creation; Python compilation passed. A fresh source-launcher workflow imported eleven synthetic records, replayed with zero insertions, passively inspected ten address-history records, returned four findings, saved four evidence records and saved zero duplicates on reassessment. No scan or connection was performed by Debian. Java, Gradle, Kotlin and SDK manager remain absent; Android build and real radio/GATT operation remain unverified. Existing pytest-only fixture workflows still require the unavailable pytest runner.

## 2026-10-29 — Deterministic YAML detection engine

Added `atlas/detection/policy.py` and `engine.py`, strict bounded YAML examples in `config/detection.yaml`, and the commands `atlas detect run`, `atlas detect explain FINDING_ID`, and `atlas detect history`. Policy specifies exact source scope and reviewed expectations for AP security, protected-SSID BSSIDs, monitored BLE UUIDs, management ports and permitted network exposure. There is no executable rule expression, LLM evaluation, automatic inventory approval or automatic incident confirmation.

Each saved anomaly includes a stable hash ID, rule ID, measurement timestamp, full supporting observation copies/hashes, severity/confidence labels, affected observed assets, investigation guidance, factual mismatch details, threshold arithmetic, normalized rule snapshot and policy digest. `detection_findings` stores evidence transactionally with a suppression index; history/explain are read-only. Observation purge leaves the additive evidence audit table intact. No legacy reporting behavior or existing Wi-Fi/BLE command contract was changed.

Thresholds count distinct measurement times per rule/source/asset/mismatch within explicit windows. Wi-Fi freshness exclusions, assessment-clock age limits, BLE completeness/success checks, unknown-security caution, and exact source scoping limit false positives. WPA3-to-WPA2 policy downgrades are recognized. Advertised UUID omissions never establish removed BLE capabilities; complete GATT evidence may differ from the configured service set, with address-identity and cache caveats. TCP acceptance on a configured port is never represented as verified protocol identity or Internet exposure.

Duplicate suppression uses canonical evidence IDs, within-run cooldowns and persisted last-alert times. Equal-time input ordering uses canonical fingerprints for repeatability. Configured rule revisions have a distinct suppression scope; late older measurements cannot override a later alert. Explicit row/group/finding/evidence limits fail atomically, preserving the prior audit history.

Verification:

- `.venv/bin/python -m unittest discover -s tests -v`: **130 tests, 129 passed, one skipped** (preexisting restricted TCP socket integration). Includes 29 detection tests for all five predicates, false positives, stale/cached/old/future observations, BLE rotation/partial/failure handling, GATT expected services, threshold counts/windows, cooldown expiry, replay at zero cooldown, IPv6 approvals, deterministic insertion-order behavior, policy validation, rollback, retained evidence and CLI operation.
- Documented source-launcher walkthrough: imported twelve synthetic observations; saved five anomalies spanning all five rule types; explained one with two supporting observations; listed five history records; repeated evaluation saved zero and suppressed five. No radio/network collection occurred.
- Python compilation and local documentation-link checks passed.
- `.venv/bin/python -m pytest --version` still reports `No module named pytest`. Three preexisting pytest fixture functions remain unexecuted by the offline unittest runner. No live radio, GATT or external network validation is claimed by deterministic fixture tests.

See [detection.md](detection.md) for full policy contracts, confidence/incident boundaries, threshold and retention semantics, and the synthetic walkthrough. The generator under `examples/detection` performs no collection and invents all measurements.

## 2026-10-29 — Security hardening and isolation validation

Hardened both CLI entry points: ordinary-user/no-effective-capabilities execution and no_new_privs; legacy history/report/topology/dashboard use read-only existing storage; detection and BLE analysis preview by default and require --save to retain evidence. TCP probe dispatch requires --authorized plus existing bounded scope. Expected errors omit private input/path payloads. No credential store or key material was introduced.

Tightened SQLite file/sidecar and batch validation, rejected duplicate-key/nonfinite JSON and nonregular/symlink legacy inputs, capped observation count at 200,000 and SQLite pages at 256 MiB. Added explicit configurable retention (seven-day default), read-only preview and --apply deletion. Raw deletion invalidates all derived evidence/baselines to remove embedded copies. Updated the previous purge-retention test to this intentional privacy contract. New snapshot/manifest commands verify observation, finding and supporting-evidence hashes and can compare all recognized table content with an independently retained digest. They do not authenticate origin or resist replacement of both evidence and manifest.

Android source separates optional Wi-Fi permission requests, defaults Wi-Fi off, declares BLE neverForLocation, protects screenshots and bounds both incomplete/completed cache leftovers. No coordinate collection, Internet/background/broad-storage permission, root workflow, pairing or GATT writes were added. Android source was not compiled or device-tested.

Actual isolation tests on this host: unprivileged user namespaces and combined mount/PID/network/IPC/UTS namespaces succeed. Bubblewrap 0.12.0 strict offline setup fails because NETLINK_ROUTE socket creation is denied. Isolation is unavailable; payload assertions therefore remain unverified. The wrapper refuses without unsandboxed/shared-network fallback. Host-network/D-Bus-dependent guest collectors and host netlink diagnostics are disabled; explicit Android/export import remains supported. Child limits and a 16 MiB private scratch profile are implemented; main-process/cgroup/kernel and per-user quota limitations are documented.

Validation: **158 unittest tests: 157 passed, one skipped** (real TCP socket creation denied), including **28 new security regressions**. Regressions exercise all derived tables, tampering/deletion/additions, manifest permissions/exclusive creation, retention rollback/boundaries/embedded copies, both CLI read-only paths, explicit probe authorization, hostile imports/files, credential/location-field rejection, redacted errors, resource limits, privilege refusal and real/failing isolation. Python compileall and documentation relative-link checks passed. Pytest remains unavailable, leaving three existing pytest fixture workflows unexecuted. Java/Gradle/Kotlin/adb/SDK manager remain absent. No radio scans, external TCP probes, settings changes or privilege escalation were performed. See [security.md](security.md) for operating instructions and remaining limitations. A separate source-backed threat model is retained through Codex Security's managed artifact store.

## 2026-10-29 — Integrated prototype completion

Integrated ingestion, history, topology, read-only stored IP analysis, explicit authorized probes and dashboard into the canonical atlas dispatcher; atlas-rf is now a compatibility argument adapter. Reports include retained baseline/BLE/policy evidence with row/record/total byte budgets. Dashboard takes fresh read snapshots, shows saved findings and signals oversized-result truncation. Source-scoped topology includes bounded low-confidence MAC/BSSID equality hints without BLE identity merging.

Added packaged controlled demo fixtures, explicit expected Wi-Fi/BLE/rule outcomes, 20 labelled policy decisions and a measured 10,000-event rolling workload. Demo stored all 55 scenario records and 10,000 benchmark events, replayed twelve records with zero inserts, produced 9/4/5 Wi-Fi/BLE/policy findings, and generated a 28-node/26-edge graph plus evidence/manifest/report/dashboard artifacts. Final recorded rolling measurement: peak RSS 34.09 MiB, CPU 81.35% of one core, event p95 53.64 ms (last 100 events), zero synthetic stored-event loss. Accuracy was 5 TP/15 TN/0 FP/0 FN on the small controlled case set only. The initial dense-history run missed its latency target and remains disclosed.

Final validation: 177 unittest cases, 176 passed, one skipped because actual TCP socket creation is denied; all three former pytest fixture workflows now run as unittest cases. The separate real PTY check switched all/Wi-Fi findings/BLE/TCP views and exited successfully with unchanged database bytes. Python compilation and documentation-link checks passed. No root/security bypass, live radio operation, external network probe, commit or push was performed. Unsupported adapters, denied sockets/full Bubblewrap profile, read-only shared storage and missing Android build/device proof remain explicit. Root README.md, architecture.md, threat-model.md and test-results.md are the maintained prototype documents.
