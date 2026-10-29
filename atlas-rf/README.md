# ATLAS RF

Autonomous Topology, Localization, Analysis, and Security for Radio-Frequency Networks.

A local, ordinary-user prototype for importing Wi-Fi/BLE observations, freezing reviewed historical baselines, detecting explainable anomalies, examining scoped IP evidence, building an evidence graph, and viewing a terminal dashboard. The canonical CLI is **`atlas`**. `atlas-rf` is a compatibility alias to the same dispatcher, including old `import` and `probe` spellings.

**Demonstrated:** the complete controlled-fixture workflow and real terminal UI. **Not demonstrated:** live Android Wi-Fi/BLE/GATT, real LAN TCP probing, geographic localization, or a working full Bubblewrap profile on this host. No root, Android security changes, credentials, cloud account, listener or daemon are required.

## Current Debian workspace

Android installation and cellular hardware integration are pending a desktop build and an approved distribution path; see [desktop handoff](docs/desktop-handoff.md). The prepared Debian workspace runs without a Google developer account. Start with [the short operating guide](docs/debian-start.md). Imported Wi-Fi/BLE analysis, policies, topology, reports and the dashboard are available; the included working dataset is explicitly synthetic.

## Run the prototype

The prepared source checkout uses Python 3.11+ and PyYAML. Its existing `.venv` and launchers work without pip:

```sh
cd /home/droid/projects/atlas-rf
./scripts/atlas --help
./scripts/atlas doctor
./scripts/atlas status
# Choose a NEW output directory; an existing directory is never overwritten.
./scripts/atlas demo --output artifacts/my-demo --events 10000
./scripts/atlas --db artifacts/my-demo/demo.sqlite3 dashboard
```

For a normal installation with package tooling, install the declared project dependencies in a virtual environment with `python -m pip install -e .`. [Installation details and this host's offline limitations](docs/installation.md). Python module form is equivalent: `.venv/bin/python -m atlas`. No package installation was performed for this completion pass.

The demo is entirely synthetic. It imports 55 invented records, creates a five-AP/15-fresh-sample Wi-Fi baseline, produces nine Wi-Fi and four BLE review hints and five saved policy anomalies, analyzes six scoped IP records, builds a 28-node/26-edge graph, verifies evidence, prints a dashboard frame and benchmarks 10,000 events. A second import of twelve policy records inserts zero duplicates. It never scans radios, connects to a network, or claims imported GATT fixtures demonstrate a connection.

Demo artifacts include `results.json`, `baseline.json`, `evidence.json`, `evidence-manifest.json`, `report.md`, `dashboard.txt`, fixture JSONL files and separate demo/benchmark databases. Keep them separate from real observations. Packaged fixture data is in [atlas/fixtures/prototype.json](atlas/fixtures/prototype.json); regenerate from the original controlled scenarios with `.venv/bin/python examples/prototype/generate.py`.

## Cellular extension

`atlas cellular` adds SQLite history, reviewed baselines, serving-cell/channel changes, LTE↔NR monitoring, signal trends, connectivity interruption hints and Wi-Fi/cellular comparison of explicit Android-bound HTTPS tests. It reuses the existing event validator, storage, logging, reports, topology, evidence and dashboard (`5` selects cellular).

Real cellular ingestion requires an HMAC-authenticated file export and matching Debian challenge. No shared-localhost assumption is made. **Phone-to-VM delivery, Android 17 compilation/runtime and radio-bound traffic remain unverified here**; no Android-produced cellular export or build tooling was available. Unknown or cached measurements stay explicit; no rule treats unfamiliar cells or NR fallback as an IMSI-catcher attack. IMSI/ICCID/IMEI, SIM authentication keys and raw modem signaling are not collected.

```sh
./scripts/atlas --db NEW_PRIVATE_DB cellular ingest --input examples/cellular/session.atlas.json --synthetic
./scripts/atlas --db NEW_PRIVATE_DB cellular baseline --source synthetic:android:cellular-lab --through 2026-04-18T10:01:00Z
./scripts/atlas --db NEW_PRIVATE_DB cellular inspect --source synthetic:android:cellular-lab --baseline
.venv/bin/python scripts/verify_cellular.py --output NEW_DIRECTORY --events 10000
```

Latest validation: **213 tests, 212 passed and one socket-dependent skip**; cellular PTY interaction and evidence verification passed. [Cellular setup, transport acceptance, API/permission investigation and unsupported capabilities](docs/cellular.md). [Latest cellular results](artifacts/cellular-final-20261029/results.json) are explicitly synthetic. Existing Wi-Fi/BLE metrics below describe the earlier prototype workload.

## One CLI

Global `--db` and `--config` precede the subcommand. Commands operate on existing storage read-only unless their explicit action imports, creates a baseline, saves findings, exports a new file, probes, or deletes data.

| Workflow | Command |
| --- | --- |
| Environment and resources | `atlas doctor`, `atlas status`, `atlas monitor --once` |
| Wi-Fi discovery ingestion | `atlas wifi scan --input FILE` |
| BLE discovery ingestion | `atlas ble scan --input FILE` |
| Generic observation ingestion | `atlas ingest FILE.jsonl` |
| Historical Wi-Fi baseline | `atlas wifi baseline --source SOURCE`, then `--show` to read it |
| Wi-Fi anomalies | `atlas wifi anomalies --source SOURCE` |
| BLE history/anomalies | `atlas ble inspect --source SOURCE --address MAC`; `atlas ble anomalies --source SOURCE --since TIME [--save]` |
| Declarative detection | `atlas detect run --rules POLICY [--at TIME] [--save]` |
| Retained policy evidence | `atlas detect history`; `atlas detect explain FINDING_ID` |
| Multi-protocol evidence graph | `atlas topology [--output NEW_FILE]` |
| Scoped stored IP evidence | `atlas ip analyze --source SOURCE --scope IP_OR_CIDR` |
| Explicit authorized TCP probes | `atlas ip probe --authorized --scope IP_OR_CIDR --ports 22,443` |
| History and integrated reports | `atlas history`; `atlas report --format json`; `atlas report --format markdown` |
| Terminal UI | `atlas dashboard`; `atlas dashboard --once [--protocol ble] [--view findings]` |
| Evidence integrity | `atlas security seal --output NEW_MANIFEST`; `atlas security verify [--manifest MANIFEST]` |
| Retention and isolation | `atlas security retention [--apply]`; `atlas security isolation` |

For a manual replay of the completed demo:

```sh
./scripts/atlas --db artifacts/revalidation-20261029/demo.sqlite3 wifi baseline --source synthetic:android-wifi:office --show
./scripts/atlas --db artifacts/revalidation-20261029/demo.sqlite3 wifi anomalies --source synthetic:android-wifi:office
./scripts/atlas --db artifacts/revalidation-20261029/demo.sqlite3 ble anomalies --source synthetic:android-ble:lab --since 2026-04-16T10:03:00Z
./scripts/atlas --db artifacts/revalidation-20261029/demo.sqlite3 detect run --rules artifacts/revalidation-20261029/policy.yaml --at 2026-04-17T10:01:00Z
./scripts/atlas --db artifacts/revalidation-20261029/demo.sqlite3 ip analyze --source synthetic:detection:network --scope 192.0.2.0/24
./scripts/atlas --db artifacts/revalidation-20261029/demo.sqlite3 topology
./scripts/atlas --db artifacts/revalidation-20261029/demo.sqlite3 security verify --manifest artifacts/revalidation-20261029/evidence-manifest.json
```

Historical fixture assessment uses its supplied clock. Preview returns candidate findings; `--save` applies persisted replay/cooldown suppression. Dashboard keys: `1` all, `2` Wi-Fi, `3` BLE, `4` TCP, `f` findings, `o` observations, arrows/PageUp/PageDown, `q` quit. Each refresh opens a fresh read transaction. Saved BLE/policy findings are shown alongside basic heuristics; full evidence is available through JSON reports and `detect explain`.

## Measured validation

Revalidation run, 2026-10-29 20:36 UTC: 10,000 normal synthetic events, rolling ten-minute policy window, final 100 events individually timed after bulk warm-up.

| Measurement | Observed |
| --- | --- |
| Peak process memory | 33.98 MiB |
| CPU / wall time | 7.50 / 10.28 seconds |
| CPU utilization | 72.93% of one logical core |
| Individual event latency p50 / p95 / p99 | 45.32 / 52.46 / 60.33 ms |
| Throughput | 972.97 events/second |
| Submitted / stored / lost | 10,000 / 10,000 / 0 |
| Labelled policy decisions | 5 TP, 15 TN, 0 FP, 0 FN |

Accuracy is **20 controlled policy decisions**, not field attack-detection accuracy. Event loss excludes over-air loss and Android callback/queue loss. CPU is not a battery measurement or whole-device utilization. Batch tails reached 94.59 ms in this run, so this is not a real-time deadline guarantee. See [test-results.md](test-results.md) for methods, all limitations, and the earlier dense-history stress failure.

The full suite completed **183 tests: 182 passed, one real TCP test skipped** because sockets are denied. A separate real-PTY test exercised curses views and clean exit with an unchanged database. All former pytest fixture workflows now execute under unittest; pytest is not needed.

```sh
.venv/bin/python -m unittest discover -s tests -v
# NEW output directory required; tests plus actual curses PTY validation:
.venv/bin/python scripts/verify_prototype.py --demo artifacts/revalidation-20261029 --output artifacts/my-validation
```

## Security and remaining work

Both CLI spellings refuse root/effective capabilities and enforce `no_new_privs`. Data files are private, input is bounded/validated, analysis defaults to read-only, active TCP operations require explicit scope/authorization, and cellular exports require a separately paired private HMAC key. Bridge keys are sensitive credentials stored in private files/app storage, without application-level encryption. Wireless identifiers and payloads remain sensitive and unencrypted at rest. No precise coordinates are collected or accepted. Wi-Fi and cellular collection are off by default in Android source; optional Wi-Fi location permissions are separate from BLE's `neverForLocation` declaration.

Retention defaults to seven days but requires explicit maintenance; it is not a daemon. Expiring raw observations invalidates derived baselines/findings so embedded copies do not survive. Exported files, logs, backups and shell output have separate lifetimes. Independently retain evidence manifests: unkeyed hashes do not authenticate senders or defeat replacement of both evidence and manifest.

On this host no guest Wi-Fi/BLE adapters are exposed, TCP sockets are denied, and shared storage is read-only. User/required namespaces work, but the strict Bubblewrap profile fails at NETLINK_ROUTE setup and refuses execution. Host-network/D-Bus collectors are disabled. Android build tooling is absent, so APK compilation, permissions, actual collection, live GATT and transport propagation remain unverified. No geographic localization or physical device identity correlation is claimed. No commit or push was made.

[Architecture](architecture.md) · [Threat model](threat-model.md) · [Test results](test-results.md) · [Detailed security controls](docs/security.md) · [Wi-Fi](docs/wifi-intelligence.md) · [BLE](docs/ble-intelligence.md) · [Policy detection](docs/detection.md)

## Delivery status

**Implemented:** unified CLI and compatibility alias; Wi-Fi/BLE/IP workflows plus cellular history, baselines, deterministic monitoring, authenticated export verification and Android collection/bound-test source.

**Tested:** 212 passing unit/integration/security/resource cases, real curses PTY interaction including cellular, evidence verification, local authenticated synthetic protocol tests, and separate Wi-Fi/cellular synthetic benchmarks. One real-TCP test was skipped because socket creation is denied.

**Incomplete or unsupported here:** Android 17 build/install/runtime, live Wi-Fi/BLE/GATT/cellular and authenticated device-file delivery, trusted key provisioning, real Android-bound Wi-Fi/cellular performance tests, real TCP probing, full Bubblewrap isolation, field accuracy/RF loss, geographic localization and physical-device identity. No hardware capture is presented as demonstrated. No code was committed or pushed.
