# Using ATLAS in Debian

Android APK installation and cellular hardware integration are deferred. No Google developer account is needed for these workflows. Existing Android source is retained for later.

## Open the prepared workspace

The user command `atlas` is installed at `/home/droid/.local/bin/atlas` and launches the existing project virtual environment. From the terminal:

```sh
atlas --version
atlas --db /home/droid/projects/atlas-rf/artifacts/debian-working-20261029/demo.sqlite3 dashboard
```

Press `1` for all, `2` for Wi-Fi, `3` for BLE, `4` for TCP evidence; `f` for findings, `o` for observations, and `q` to quit. This workspace contains **synthetic demonstration data**, not scans of your surroundings. The default database remains separate and uninitialized until you import real observations.

## Read reports and history

```sh
cd /home/droid/projects/atlas-rf
atlas --db artifacts/debian-working-20261029/demo.sqlite3 history
atlas --db artifacts/debian-working-20261029/demo.sqlite3 report --format markdown
atlas --db artifacts/debian-working-20261029/demo.sqlite3 topology
atlas --db artifacts/debian-working-20261029/demo.sqlite3 security verify --manifest artifacts/debian-working-20261029/evidence-manifest.json
```

A generated report is also available at `artifacts/debian-working-20261029/report.md`. The evidence manifest checks logical data integrity; it does not authenticate an external sender.

## Analyze Wi-Fi/BLE history

```sh
atlas --db artifacts/debian-working-20261029/demo.sqlite3 wifi baseline --source synthetic:android-wifi:office --show
atlas --db artifacts/debian-working-20261029/demo.sqlite3 wifi anomalies --source synthetic:android-wifi:office
atlas --db artifacts/debian-working-20261029/demo.sqlite3 ble anomalies --source synthetic:android-ble:lab --since 2026-04-16T10:03:00Z
atlas --db artifacts/debian-working-20261029/demo.sqlite3 detect run --rules artifacts/debian-working-20261029/policy.yaml --at 2026-04-17T10:01:00Z
```

These analyze existing records. They do not start radio scans or active network probes. Synthetic fixtures use their historical assessment clock.

## Import actual observations later

When an authorized source provides a file matching ATLAS's observation schema, use the normal database, separate from the demo:

```sh
atlas ingest /absolute/path/to/observations.jsonl
atlas dashboard
```

Do not run the placeholder path literally. External scanner formats need an explicit adapter if they do not match the documented schema. Wi-Fi/BLE JSONL formats are described in `docs/wifi-intelligence.md` and `docs/ble-intelligence.md`. Real cellular data still requires its authenticated bridge; do not bypass it with raw imports.

## Verified scope and limits

The prepared demo exercises ingestion, SQLite history, replay deduplication, Wi-Fi baselines, Wi-Fi/BLE anomalies, declarative policies, stored IP evidence analysis, topology, reports, evidence verification and the terminal dashboard. Its benchmark submitted and stored 10,000 synthetic events with zero loss.

On this execution host, no guest Wi-Fi/BLE controller is exposed and TCP socket creation is denied. Live scans and active TCP probes therefore remain unavailable here. `/mnt/shared` is readable but read-only from Debian. No security settings or device configuration were changed.

Validation output: `artifacts/debian-working-validation-20261029/validation.json`. This distinguishes the passing software workflows from deferred hardware integration.
