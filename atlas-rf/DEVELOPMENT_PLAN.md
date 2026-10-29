# ATLAS RF development plan

Autonomous Topology, Localization, Analysis, and Security for Radio-Frequency Networks.

## Current priority

Android collector build/installation is pending access to the operator's desktop; Play developer-account setup and live cellular integration remain unresolved. See docs/desktop-handoff.md. Focus on the Debian import, history, Wi-Fi/BLE analysis, policy detection, topology, reports and terminal dashboard workflows. Live Android radio integration remains incomplete; retain the existing source for later. No device security settings are to be changed.

## Completion checkpoint

The source-running integrated prototype and controlled demonstration are complete. See README.md, architecture.md, threat-model.md and test-results.md for the single CLI, generated evidence, measured synthetic results and separately incomplete hardware capabilities. No APK, live radio/GATT, real socket operation or full Bubblewrap profile is claimed as demonstrated.

## Operating boundary

Target: Pixel 10 Pro XL, Android Linux Terminal, Debian ARM64, approximately 6 GB VM RAM. Do not depend on phone radio passthrough, root, monitor mode, raw sockets, Android debug bridges, or changes to Android security. Detect guest capabilities before attempting optional collection. Guest routes and neighbors describe the VM network, which may be behind NAT, not the complete phone LAN.

## Architecture and resource budget

Use Python 3.11+ and its standard library for a dependency-free CLI, SQLite persistence, asynchronous TCP connect analysis, and a curses dashboard. Node.js is available but unnecessary for the initial release. Single local process; no listeners, telemetry, cloud service, packet capture, third-party plugins, or background daemon. Use bounded input, scan targets, concurrency, timeouts, and queries. Aim for under 150 MB resident memory in normal operation; measure rather than claim device performance.

Modules: strict observation schema → source adapters → transactional SQLite history → evidence-based anomaly rules → topology and reports → CLI/dashboard. Store source, observation time, and confidence context with observations. Treat radio identifiers as observations, not proof of a physical device's identity. RSSI is proximity evidence, not geographic localization.

## Implementation sequence

1. Foundation: package, CLI, private data directory, versioned schema, bounded JSONL import, normalized observations and provenance. Reject malformed imports atomically and deduplicate replays.
2. Collection: capability doctor; read guest routes/neighbors through `ip -j`; optional NetworkManager Wi-Fi and BlueZ BLE collection only if guest hardware/services exist. Portable JSONL supports Android companion exports or authorized external sensor exports without requiring either to be installed.
3. IP analysis: explicit literal IP/CIDR allowlist and bounded TCP connect probes. No implicit subnet scan. Record reachability only when a connection succeeds; closed/filtered responses do not prove a host absent.
4. Intelligence: historical tracking, Wi-Fi open/legacy security findings, security downgrade, new BSSID for known SSID and RSSI changes with heuristic caveats. Evidence-derived topology edges; do not invent links between co-observed devices.
5. Delivery: JSON and Markdown security reports, terminal overview with interactive refresh/filter/history, retention command, sample dataset clearly labeled synthetic, operator guide and schema reference.
6. Verification: schema/replay/rollback tests, anomaly ordering tests, local TCP integration test, topology/report checks, hostile terminal text checks, CLI end-to-end smoke test and memory measurement. Pixel hardware validation remains a distinct field acceptance step.

## Field acceptance and subsequent milestones

Initial release is a usable guest network analyzer and radio observation intelligence engine. With no guest radio adapter, Wi-Fi/BLE live capture must report unavailable and direct the operator to import. Verify on the target phone: doctor, import, dashboard, VM route collection, authorized TCP probe, report and retention. Record OS/build, available adapters and RSS. A future Android companion must use normal runtime Wi-Fi/Bluetooth permissions, respect scan throttling, and export the documented schema; building/signing that APK is a separate milestone. Later work: authenticated remote sensors, optional geographic measurements with consent, calibrated localization, and rule baselines. None is represented as working in this initial release.

## Security and assessment constraints

Only analyze networks the operator is authorized to assess. Active probes require explicit scope every invocation. Never execute imported strings or shell commands; sanitize terminal controls and Markdown content. Limit file/line size and scan expansion. Use SQLite parameters and restrictive local permissions. Reports contain sensitive identifiers; files remain local and are not encrypted at rest. Compatible subprocesses now require a strict offline Bubblewrap profile and fail closed when it cannot be established. Guest host-network/D-Bus collectors are disabled under this profile; import telemetry instead. The main interpreter is not sandboxed. Read-only analysis, explicit persistence, configurable retention maintenance, integrity verification and Android permission defaults are documented in docs/security.md.

## Primary platform references

- https://developer.android.com/develop/connectivity/wifi/wifi-scan — Android app scanning permissions and throttling.
- https://developer.android.com/develop/connectivity/bluetooth/bt-permissions — Android BLE runtime permission requirements.

These Android APIs belong to an Android app; their existence does not grant access from a Debian guest.
