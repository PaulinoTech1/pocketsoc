# Installation and startup

The project root is `/home/droid/projects/atlas-rf`. Python 3.11+ is required. Core runtime dependency: PyYAML 6.x. pytest is development-only. Rust and Node are not required for the initial application.

## Standard isolated installation

On Debian with normal package/network access, obtain the distribution's Python venv support first if missing (`python3-venv`, matching your Python version). Then, from the project directory:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
atlas status
atlas doctor
atlas --config config/atlas.yaml monitor --once
python -m pytest
```

This is the intended installation path, but pip/ensurepip and package downloads are unavailable in the inspected execution environment. Do not change Android security settings or escalate privileges to bypass those restrictions.

## Offline source startup used in this environment

The inspected Debian system already supplies PyYAML 6.0.2 but lacks pip, ensurepip, setuptools and pytest. A real virtual environment was created with access to the system package:

```sh
cd /home/droid/projects/atlas-rf
python3 -m venv --without-pip --system-site-packages .venv
. .venv/bin/activate
export PATH="$PWD/scripts:$PATH"
atlas status
atlas doctor
atlas --config config/atlas.yaml monitor --once
```

`--system-site-packages` is an explicit offline compromise: the environment shares Debian-managed Python dependencies instead of being fully isolated. It does not modify the system interpreter or install packages. `scripts/atlas` invokes the project's `.venv/bin/python`, so it also works via `./scripts/atlas` without activation. The launcher works from other directories and forwards all arguments.

This environment has been created already. No fake pip, pytest shim, mocked hardware or bypass of syscall restrictions is used. `python -m atlas` is equivalent when running from the project root with the venv activated. The tracked launchers are a source-checkout fallback, not a substitute for declaring package entry points.

## Commands

```sh
atlas status
atlas doctor
atlas --config config/atlas.yaml status
atlas monitor --once
atlas monitor --samples 3
atlas monitor                       # Ctrl-C or SIGTERM to stop
atlas report --format json
atlas report --format markdown --output assessment.md
atlas bridge verify examples/bridge-fixture/session.atlas.json
atlas wifi scan --input /path/to/session.atlas.json
```

Global `--config` and `--db` options go before the subcommand. Output files must not already exist. `status` does not create a database: `uninitialized` is normal before the first import. `doctor` returns 0 when inspection completes even if individual capabilities are UNSUPPORTED; read its structured checks. Logs go to stderr and results to stdout:

```sh
atlas doctor > doctor.json 2> doctor-events.jsonl
```

Treat redirected files as sensitive and set shell permissions appropriately. To enable bounded file logging, add `logging.file: /absolute/private/path/events.jsonl` to your YAML. Defaults log only to stderr. Configuration options, limits and exit codes are documented in [architecture.md](architecture.md).

The [Android collector source](../android/collector/README.md) has a separate build toolchain and is not an installed APK. Use its explicit fixture workflow while compilation/installation is blocked. The new `atlas bridge import FILE` validates a finalized `.atlas.json` export before opening the observation database; `atlas bridge verify-probe FILE --nonce UUID` supports the eventual real shared-file acceptance check. [Transport findings and blockers](vm-transport.md) are recorded separately.

For Wi-Fi baselines and anomalies, use the separate temporary-database walkthrough in [wifi-intelligence.md](wifi-intelligence.md). Do not mix synthetic training records into a real assessment database. `atlas wifi scan` requires an explicit file and performs no direct Android radio scan.

## Synthetic demonstration

Use a separate temporary directory to avoid mixing demonstration records with real observations:

```sh
demo_dir=$(mktemp -d)
atlas-rf --db "$demo_dir/demo.sqlite3" import examples/demo.jsonl
atlas --db "$demo_dir/demo.sqlite3" status
atlas --db "$demo_dir/demo.sqlite3" report --format markdown
atlas-rf --db "$demo_dir/demo.sqlite3" dashboard
```

The example data is labeled `synthetic:demo`; it establishes no hardware access. Existing collector, authorized probe, import, history, topology and purge commands remain under `atlas-rf`. Existing v1 databases are compatible with the new read-only report/status flow. Never point active probes at networks without authorization.

## Tests and limitations

```sh
# Full suite once the declared development dependency can be installed:
.venv/bin/python -m pytest

# Offline fallback: executes unittest classes, including application/CLI tests:
.venv/bin/python -m unittest discover -s tests -v
```

pytest collects both unittest classes and additional fixture-based workflows. The offline unittest fallback does **not** execute the three pytest fixture-based functions. A missing pytest runner is not a passing pytest run. See [development-log.md](development-log.md) for the exact verification record and [environment.md](environment.md) for current hardware, socket and netlink limitations.

For BLE advertisement analysis, stored confidence evidence and passive history, follow [ble-intelligence.md](ble-intelligence.md). Its fixture walkthrough uses a separate demo database. Active GATT requires an expiring request file, approved user-mediated transfer, exact-target Android confirmation and an already bonded target. No reverse writable-share or automatic pairing is assumed.

## Policy detection

After importing authorized observations, create a reviewed detection policy using `config/detection.yaml` as a schema example. Its bundled source/address values are synthetic and must be replaced for actual data. Run `atlas detect run --rules PATH`, list IDs with `atlas detect history`, and read the retained evidence with `atlas detect explain FINDING_ID`. See [the detection guide](detection.md) for the synthetic walkthrough and the optional historical `--at` clock. No additional dependency, network service or radio access is required.
