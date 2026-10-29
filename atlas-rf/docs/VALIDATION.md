# Validation record

Validated 2026-10-29 in the development environment with Python 3.13.5. Target is Python 3.11+ on Debian ARM64. No physical Pixel hardware was available for this run.

## Completed

- Unit suite: **19 tests, 18 passed, 1 skipped**. The skipped integration test requires creating a real loopback TCP socket; this environment returns `Operation not permitted` at socket creation. Separate tests verify that socket denial is an explicit error and that connection refusal is not stored as a reachable service.
- CLI workflow: imported the seven synthetic observations, replayed with zero new rows, generated five expected findings, exported the eight-edge graph, queried identifier history, wrote a private Markdown report, refused overwrite, rejected a broad scope, confirmed absent-radio error messages, and purged two older observations.
- Curses UI: opened in a pseudo-terminal, refreshed after a separate import, displayed Wi-Fi history and findings using keyboard controls, and exited cleanly. Final filter adjustment ensures findings respect the selected kind; rendering remains a field check on the Android terminal.
- Capability doctor: `ip` and Bubblewrap present; NetworkManager/BlueZ tools absent; no guest Wi-Fi interfaces or Bluetooth controllers. Capability checking produced no radio scan attempts.
- Synthetic stress run: 10,000 distinct BSSIDs with one SSID, including 9,999 new-BSSID findings. Insert time 0.152 s; report analysis plus JSON serialization 0.076 s; process peak RSS **53,436 KiB** (approximately 52 MiB), JSON output 7,608,810 bytes. Measurements describe this development host, not the Tensor G5. Evidence samples per new-BSSID finding are capped to avoid quadratic report growth.

## Target field acceptance still required

1. Copy the source to Debian ARM64; run `python3 -m atlas_rf doctor` and the test suite.
2. Repeat the synthetic import/report/dashboard workflow using a dedicated demo database.
3. Run `collect network` and verify that the observed VM routes/neighbors are accurate. Record NAT boundaries; do not infer a complete phone LAN.
4. Probe a single owned listener with an explicit IP scope/port; verify open and closed cases. This is the outstanding real-socket integration check.
5. If guest radio hardware exists, verify optional collectors against the installed NetworkManager/BlueZ versions. Otherwise verify the documented import workflow using an authorized real exporter. No Android exporter is bundled.
6. Measure RSS, battery impact and UI behavior on the actual phone, including narrow terminal widths, filtering, scrolling and exit.
7. Verify private database/report permissions and retention behavior on the target filesystem.

No live radio collection, actual wireless vulnerability, exact location, or Pixel performance claim is established by synthetic tests.

## Modular application update

The original platform validation above is retained as historical evidence. Version 0.2 moves the implementation into `atlas/` and adds YAML configuration, JSON logging, diagnostics and resource monitoring. Current verification and the missing pytest-runner limitation are recorded in [development-log.md](development-log.md); startup is documented in [installation.md](installation.md). The new default application report window is 2,000 observations; original CLI limits remain available.
