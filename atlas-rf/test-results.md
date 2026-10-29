# ATLAS RF prototype test results

Earlier Wi-Fi/BLE prototype revalidation recorded 2026-10-29 at 20:36 UTC on the actual execution host: Linux 6.12.93 Android kernel, aarch64, Python 3.13, ordinary UID 1000. Exact Pixel model, VM RAM assignment and deployed Android collector identity were not verified. These results describe this run, not certified hardware performance.

## Cellular extension validation — 2026-10-29

**Implemented:** shared CLI/event/storage/logging integration for cellular history; Kotlin public-API companion source; HMAC/challenge file verification; retained session availability/drop metadata; immutable reviewed cellular baselines; deterministic serving-cell/channel/RAT/display/interruption rules and signal trends; source-scoped topology; report/dashboard integration; separately authorized Android-bound Wi-Fi/cellular HTTPS test source. All cellular rules are descriptive operational hints, not IMSI-catcher classifications.

**Tested locally:** 30 cellular protocol/schema/rule/integration/resource cases, including the full authenticated **synthetic** export→SQLite→baseline→analysis→evidence workflow, tampering/wrong-key/nonce rejection, unsafe-key rejection, timestamp/availability preservation, raw-real-import refusal, normal control cases, sample deduplication, scope/gap isolation, metadata retention, derived-evidence tamper detection, retention invalidation, and bound-result comparison. Python source compilation passed. The final full suite ran **213 tests: 212 passed, 1 real-TCP test skipped, 0 failures/errors**. Actual curses PTY interaction exercised cellular key `5` alongside all prior views, exited cleanly and left the database unchanged. JVM/Android tests were not run.

**Incomplete/unverified on hardware:** Android 17 APK compilation/install/runtime, trusted key provisioning, Android-to-Debian challenge delivery, phone subscriptions/permissions/modem fields, live LTE/NR/neighbor callbacks, exact Hz and full registration details, Android network binding and real Wi-Fi/cellular traffic, field accuracy/false positives and over-air loss. `adb`, Java, Gradle, Kotlin compiler and Android SDK are absent. No real cellular export was present in the visible Documents directory; no shared-localhost assumption or network fallback was used. See [preflight](artifacts/cellular-transport-preflight.json) and [setup/unsupported capabilities](docs/cellular.md).

The [explicitly synthetic 25-event scenario](examples/cellular/README.md) stores all 25 observations, replays with zero new rows, freezes 3 reviewed eligible baseline samples and returns **11 expected hints**: 1 serving change, 1 frequency change, 2 baseline novelties, 2 LTE↔NR transitions, 1 display change, 1 data interruption, 1 registration interruption, 1 cellular-network loss and 1 sustained degradation. Four signal metric trends are available. The Wi-Fi/cellular durations (100/200 ms) in that fixture are invented, not measured traffic performance. Complete expected/control assertions live in [tests/test_cellular.py](tests/test_cellular.py).

A separate **stable serving LTE** workload inserts 10,000 bulk records followed by 100 individually timed insert+analysis operations over the latest 2,000-event window. [Raw measurements](artifacts/cellular-final-20261029/results.json):

| Measurement | Observed |
| --- | --- |
| Peak process lifetime RSS | 37,404,672 bytes / 35.67 MiB |
| CPU / wall time | 9.502 / 12.434 seconds |
| CPU utilization | 76.42% of one logical core |
| Tail event latency p50 / p95 / p99 | 88.95 / 104.73 / 110.89 ms |
| Tail maximum latency | 112.70 ms |
| Submitted / inserted / stored / lost | 10,100 / 10,100 / 10,100 / 0 |
| Review hints in the 100 overlapping normal windows | 0 |

Peak RSS includes earlier fixture processing; these are process/workload metrics, not device/battery/RF measurements. Zero normal-window hints is a synthetic regression result, not an independent false-positive-rate estimate. No field accuracy has been measured. The older `cellular-completion-20261029` exploratory artifact selected an unregistered neighbor template for its stress workload and is superseded by the registered-serving-cell workload above; it is not used for the reported benchmark.

Reproduce with new output directories:

```sh
.venv/bin/python scripts/verify_cellular.py --output NEW_CELLULAR_DEMO --events 10000
.venv/bin/python scripts/verify_prototype.py --cellular --demo NEW_CELLULAR_DEMO --output NEW_VALIDATION
```

The initial final-validation attempt retained at [cellular-acceptance-20261029](artifacts/cellular-acceptance-20261029/validation.json) encountered a 10-second timeout in an existing detection CLI subprocess test and a PTY capture assertion. The dashboard emitted differential terminal updates, so full-header byte matching was an invalid harness assumption. The harness now checks separately emitted view/mode tokens and bounded startup waits; its direct cellular PTY check passed with a clean exit and unchanged database. This does not hide the unsuccessful attempt or establish Android hardware behavior. Earlier runs with 207/210 passing cases precede the last added tests.

Final artifacts: [fixture/rule/resource results](artifacts/cellular-final-20261029/results.json), [analysis](artifacts/cellular-final-20261029/analysis.json), [report](artifacts/cellular-final-20261029/report.md), [manifest](artifacts/cellular-final-20261029/evidence-manifest.json), [test/PTY summary](artifacts/cellular-delivery-validation-20261029/validation.json), [complete test log](artifacts/cellular-delivery-validation-20261029/unittest.txt), [PTY capture](artifacts/cellular-delivery-validation-20261029/dashboard-pty.bin). The PTY capture contains terminal escape sequences.

## Earlier Wi-Fi/BLE prototype results

## Implemented features

The single `atlas` CLI integrates Wi-Fi/BLE discovery-file ingestion, generic IP/event ingestion, immutable historical Wi-Fi baselines, temporal BLE comparison, YAML policy detection, scoped IP analysis/authorized probing, cross-protocol evidence graph, integrated reports, evidence integrity/retention tools, terminal dashboard and a controlled end-to-end demo. `atlas-rf` delegates to the same implementation with legacy argument translations.

Android collector, BLE/GATT metadata handling and explicit request/permission flows exist in source. Their presence is implementation evidence only; build, installation and live API operation remain unverified.

## Tested features and reproduction

```sh
./scripts/atlas demo --output artifacts/my-demo --events 10000
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/verify_prototype.py --demo artifacts/my-demo --output artifacts/my-validation
./scripts/atlas --db artifacts/my-demo/demo.sqlite3 security verify --manifest artifacts/my-demo/evidence-manifest.json
./scripts/atlas --db artifacts/my-demo/demo.sqlite3 dashboard
```

Output directories must be new. Commands never overwrite prior demonstrations. Global `--db` is rejected by `demo`, which creates its own isolated data. No root, radio scans, network connections, OS security changes, package downloads, commits or pushes were used to complete the demo.

| Validation | Recorded result |
| --- | --- |
| Full unittest discovery | **183 run: 182 passed, 1 skipped; 0 failures/errors** |
| Former pytest fixture workflows | Converted into 3 portable unittest cases; all execute, no pytest/shim needed |
| Prototype integration/resource regressions | 16 cases, including fresh-process CLI demo and resource measurement |
| Security regressions | 34 hardening cases passed, including 6 file/log input regressions |
| Real TCP loopback test | Explicitly skipped: execution environment denies socket creation |
| Real curses PTY validation | Passed: initial/all, Wi-Fi findings, BLE observations, TCP observations, clean quit |
| Dashboard database mutation check | SHA-256 unchanged before/after actual PTY session |
| Retained evidence resource regression | Oversized records omitted with explicit truncation; report/dashboard serialized byte budgets enforced |
| Dashboard refresh regression | A newly committed event appears in a later fresh snapshot |
| Evidence verification | Internal consistency verified; saved manifest matches demo DB |
| Python source compilation | Passed for atlas/atlas_rf |
| Documentation links/source anchors | Checked locally |

The final validation harness took 6.05 seconds, including actual PTY interaction. A prior full-suite invocation under concurrent load took 42.42 seconds; elapsed test time is environment-dependent. The suite's denied-socket mocks test failure handling; they do not establish real network access. PTY testing uses a real terminal, not a mocked curses renderer. No Android compilation or device instrumentation is hidden behind a successful test label.

Recorded artifacts:

- [Controlled demo results and complete metric definitions](artifacts/revalidation-20261029/results.json)
- [Evidence bundle](artifacts/revalidation-20261029/evidence.json), [logical manifest](artifacts/revalidation-20261029/evidence-manifest.json), [verification result](artifacts/revalidation-20261029/verification.json)
- [Baseline](artifacts/revalidation-20261029/baseline.json), [assessment](artifacts/revalidation-20261029/report.md), [plain terminal frame](artifacts/revalidation-20261029/dashboard.txt)
- [Full test log](artifacts/revalidation-tests-20261029/unittest.txt), [test/PTY summary](artifacts/revalidation-tests-20261029/validation.json), [raw PTY capture](artifacts/revalidation-tests-20261029/dashboard-pty.bin)
- [Actual capability checks](artifacts/revalidation-20261029/hardware-capabilities.json); [earlier actual isolation check](artifacts/completion-20261029/isolation.json)

The raw PTY capture contains terminal control sequences. It is synthetic terminal-output evidence; the plain frame is easier to inspect. Database files remain in the demo directory but are not required to inspect the JSON/Markdown results.

## End-to-end controlled scenario

| Stage | Evidence/result |
| --- | --- |
| Wi-Fi training ingestion | 18 supplied records; 15 eligible fresh samples; 5 BSSID profiles |
| Historical baseline | Frozen snapshot persisted and reloaded; 1 stale, 1 cached and 1 unknown-freshness training record excluded |
| Wi-Fi evaluation ingestion | 12 supplied records, including stale/cached/repeated measurement controls |
| Wi-Fi review | 9 expected hints: 4 unknown BSSID, 2 unseen SSID, 1 security change, 1 channel change, 1 suspicious weak-security SSID duplication |
| BLE reference/evaluation ingestion | 4 reference + 7 evaluation records; advertisements and synthetic GATT metadata |
| BLE review | 4 expected hints: service novelty, advertisement configuration, capability addition, changed complete GATT metadata |
| Policy evidence | 12 supplied records produce 5 expected persisted anomalies across the five predicates |
| IP evidence | 2 additional invented neighbor/route records; scoped analysis returns 6 IP records; zero sockets/connections |
| Cross-protocol graph | 28 nodes, 26 edges; Wi-Fi, BLE, host, service, MAC and source nodes; 1 low-confidence MAC/BSSID equality hint |
| Persistent evidence | 1 baseline, 4 BLE findings, 5 policy findings; hashes and independent-manifest comparison checked |
| Fixture accounting | 55 supplied records, 55 stored, **0 lost** |
| Replay | 12 supplied policy records replayed, **0 new insertions** |

These are invented controlled observations. An SSID novelty hint can represent benign new equipment; it is not a false claim of attack. Stale/cached data excluded from analysis remains in storage and is not counted as lost. Synthetic GATT metadata represents a parser/analysis case, not a demonstrated GATT connection. The topology's cross-protocol edge means only literal address equality in supplied records; it proves no device identity or physical connectivity.

## Detection accuracy and false positives

The scored unit is **one case/rule binary alert decision**. The packaged fixture has four cases per policy rule: a qualifying two-measurement mismatch, an approved control, an expired mismatch and an insufficient-count mismatch. Labels are defined in the fixture generator independently of detector output. Each case runs in an isolated temporary database with only its selected policy rule. Full case outcomes are saved under `detection_accuracy.cases` in results.json.

| Statistic | Observed |
| --- | --- |
| Cases / positives / negatives | 20 / 5 / 15 |
| True positives / false negatives | 5 / 0 |
| True negatives / false positives | 15 / 0 |
| Accuracy / precision / recall | 100% / 100% / 100% |
| False-positive rate | 0/15 = 0% |

This is a small controlled regression suite whose labels match specified policy behavior. It is not a held-out field study, attack-detection probability, statistical guarantee, or confirmed incident assessment. The Wi-Fi nine-hint and BLE four-hint expectations are separately checked exactly, not pooled into this confusion matrix. Real-world false positives/negatives are **unmeasured**. Address rotation/spoofing, incomplete packets, platform caching, legitimate reconfiguration and untrusted source labels remain substantial limitations.

## Resource measurements

The final workload inserts **10,000 normal synthetic Wi-Fi observations** into a separate database. It fast-forwards the simulated measurement clock one second/event, applying the configured ten-minute rolling policy window after each 100-event batch. After 9,900 events of bulk warm-up, the last 100 events are inserted and detected individually. Their latency includes generation, validation, SQLite commit and policy evaluation. Timing is wall-clock `perf_counter`; CPU is `process_time`; peak RSS is Linux `getrusage(RUSAGE_SELF).ru_maxrss * 1024` for the complete demo process lifetime. No background sample list or radio queue is involved.

| Measurement | Observed final run |
| --- | --- |
| Peak RSS | **35,631,104 bytes = 33.98 MiB** |
| CPU time / benchmark wall time | **7.496 / 10.278 seconds** |
| CPU utilization | **72.93% of one logical core**, CPU seconds / wall seconds × 100 |
| Throughput | **972.97 events/second**, execution throughput rather than RF arrival rate |
| Individually measured events | 100, after 9,900-event warm-up |
| Event latency p50 / p95 / p99 | **45.32 / 52.46 / 60.33 ms** |
| Event latency maximum | 67.71 ms |
| 100-event batches | 99 |
| Batch completion p50 / p95 / p99 | 57.70 / 77.06 / 90.87 ms |
| Batch completion maximum | 94.59 ms |
| Submitted / processed / stored / lost | **10,000 / 10,000 / 10,000 / 0** |
| Synthetic loss rate | **0%** |

The declared local regression targets were peak RSS below 150 MiB, individually sampled event p95 below 1 second and zero stored-event loss; this run passed. These are prototype targets, not requirements supplied by the user or hard real-time guarantees. The source test uses a fresh 100-event child process to exercise the same measurement/budget paths without depending on a large benchmark in every suite invocation.

Peak RSS includes fixture handling and scoring performed earlier in the process; it is not a per-phase allocation delta. The full test runner's own peak RSS is separate and is not substituted for the demo process. The earlier rolling-window run is retained at artifacts/prototype-final/results.json; the latest run is not a controlled speedup comparison. CPU includes actual process work and excludes other processes; 72.93% does not mean 72.93% of a multicore phone. Tail batch latency indicates scheduling/I/O variability. No CPU duty cycle, battery/thermal, sustained RF ingestion or anomaly-heavy load claim follows from the benign stream benchmark. The latest batch maximum was below the individual-event latency target, but that is not a tested batch deadline. Main-process limits are cooperative; aggregate cgroup enforcement is absent.

Event loss measures admitted synthetic records versus stored records. It excludes failed over-air reception, Android queue pressure, omitted oversized metadata, exports that never reached Debian and intentional replay suppression. Hardware event loss is **unmeasured**.

### Disclosed dense-history stress result

An earlier exploratory run kept all 10,000 event timestamps inside the same assessment window and reevaluated accumulated history after every 100 events. It measured 33.92 MiB peak RSS, 74.08 CPU seconds / 123.02 wall seconds (60.22% of one core), 81.29 events/second, batch p95 4,613.86 ms and maximum 31,805.76 ms. All 10,000 records were stored, but its 1-second batch latency target **failed**. Raw pre-adjustment output remains [here](artifacts/prototype-demo/results.json).

The final benchmark explicitly changes the workload to a rolling window and adds individual event samples. These are different workloads measured under variable host load; their figures are not a controlled speedup comparison. The dense-history result remains a limitation: repeated full-window reevaluation at high event density can be slow. No production high-rate packet-processing guarantee is claimed. The current demo reproduces the documented rolling workload; the earlier result is an archived exploratory run rather than a second current CLI benchmark mode.

## Unsupported and incomplete hardware features

| Capability | Actual result / remaining proof |
| --- | --- |
| Guest Wi-Fi | Unsupported here: no Wi-Fi interface or phy exposed; discovery is fixture ingestion only |
| Guest Bluetooth | Unsupported here: no HCI controller exposed; no live BLE discovery |
| Real TCP/IP probes | Socket creation denied (EPERM); real loopback integration skipped; only scope/failure logic and supplied evidence analysis demonstrated |
| Host netlink/D-Bus collectors | Disabled under strict offline subprocess policy; no unsandboxed fallback |
| User and combined required namespaces | Successfully exercised unprivileged user + mount/PID/network/IPC/UTS creation |
| Full Bubblewrap isolation | Unavailable: Bubblewrap 0.12.0 fails required NETLINK_ROUTE socket setup; payload-isolation assertions cannot run |
| Shared storage | `/mnt/shared` visible as read-only virtiofs; export/request propagation across Android/VM boundary unverified |
| Android collector APK | Java, Gradle, Kotlin, adb and SDK tooling absent; compilation/install unverified |
| Android permissions/lifecycle/screenshot restrictions | Implemented in source and static-tested; no device enforcement claim |
| Live GATT enumeration | Unverified; request validation and imported synthetic successful/failed metadata tested only |
| Precise geographic location / device identity | Not implemented or claimed; no coordinates stored by default or accepted by the schema |
| Field accuracy / RF loss / phone battery | Unmeasured |
| At-rest encryption / authenticated sensor signatures | Not implemented; private files and unkeyed integrity hashes have documented limits |
| Automatic retention daemon / aggregate cgroups | Not implemented; explicit maintenance/cooperative main-process checks only |
| Package wheel/APK builds | Not performed; source launchers and canonical module CLI exercised |

## Completion status

**Implemented:** unified source-running CLI, controlled demo, all requested analysis/evidence/UI workflows, existing security controls, explicit hardware diagnostics, documentation and repeatable validation harness.

**Tested:** 183 discovered cases with the stated skip, exact fixture output/replay expectations, integrity/tampering/retention regressions, scoped stored IP analysis, source-safe cross-protocol graph, fresh dashboard snapshots, actual curses PTY, and measured synthetic resource/scoring/loss results.

**Incomplete or unsupported:** live radio/GATT/Android bridge operation, real network probing in this environment, full offline Bubblewrap setup, real-world accuracy/event loss/battery proof, geographic localization and authenticated physical identity. These are not represented as working prototype hardware features. No commit or push was made.
