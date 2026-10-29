# Security and privacy

## Hardening follow-up, 2026-10-29

Validation: **183 tests run, 182 passed, one real-TCP test skipped because socket creation is denied**. All 34 security regression tests passed. The updated [source-snapshot threat model](/home/droid/.codex/state/plugins/codex-security/scans/atlas-rf/artifacts-7363ec19ec7bbe22ef6776d4970de8de1cc148bfacb1fb579c23b32201460435/threatmodel.md) records this follow-up; the repository-root model retains the earlier prototype snapshot.

Optional local event logs now require an owned, regular, single-link file inside an owned parent that is not group/world writable. Validation happens before changing file permissions. Opens are nonblocking and reject symlinks; FIFOs cannot stall event logging. These checks also run whenever rotation reopens the log. Trusted ancestor directories and exclusive control of the operator account remain assumptions; log rotation is not designed for concurrent independent writers.

Configuration and detection-policy inputs now use bounded, nonblocking regular-file reads with symlink refusal, matching the import transport boundary. Both retain the 64 KiB limit and strict YAML validation. Use a regular file directly for `--config` and `--rules`; pipes, devices and symlink shortcuts are rejected. Six additional regression tests cover aliased log files, FIFOs, shared log directories, private rotation, and YAML symlink/FIFO refusal.

Fresh isolation tests again found working user and combined namespaces, with the full Bubblewrap profile refused because required `NETLINK_ROUTE` access is denied. No unsandboxed fallback was introduced. Android compilation and device behavior remain unverified. Android cache deletion is best-effort: cleanup runs only at session creation and filesystem deletion failures can leave older spools, so the intended two-prior-session cache bound is not guaranteed after a deletion failure.

ATLAS runs as an ordinary Linux user. The canonical CLI and its compatibility alias refuse root, mismatched real/effective IDs and effective Linux capabilities, and require Linux `no_new_privs`. They do not invoke sudo, request capabilities, change Android security settings or install privileged helpers. No inbound listener, credential store, telemetry upload, executable plugin loader or background collector is provided. Unknown credential/configuration fields are rejected; no application passwords or tokens are persisted. Sensor UUIDs and expiring GATT request IDs are identifiers, not authentication credentials.

## Defaults and explicit actions

Status, report, history, topology, passive inspection, evidence verification and retention preview use existing databases read-only. Legacy read commands no longer initialize storage. `detect run` and `ble anomalies` now preview without saving: add `--save` to retain findings. The programmatic `run` and `analyze_and_store` functions remain explicit write APIs. Import, baseline creation, `--save`, private report/manifest output and retention `--apply` are intentional writes. A configured optional log file still writes command metadata, even during read operations; stderr is the default. No collection or probes run on application startup. Legacy TCP probes now require `--authorized` plus literal, bounded scope. This flag records operator intent, not independent proof of permission.

Wireless addresses, SSIDs, BLE payloads, names, source UUIDs, timestamps and network topology are potentially sensitive. Private databases/reports/manifests use mode 0600 and newly created data directories use 0700. Database parents must be owned and not group/world writable; use a private directory, including for temporary demos. Symlink/hardlink database and unsafe SQLite sidecars are rejected. Keep all ancestor directories trusted: these pathname checks are not a defense against another process controlling the same account. JSON output escapes terminal controls; Markdown and dashboard display sanitization remain in effect. Imported data is not executed. Expected CLI errors omit exception payloads to avoid logging private paths or record values. No log contains full observations by design, but command output and reports do.

The database and exports are **not encrypted at rest**. Use an encrypted device/volume and protect backups. Shell redirection, terminal scrollback, report sharing, document providers and exported copies follow their own access controls. A chosen Android document provider may sync to a remote account; ATLAS has no control over that provider. Never place credentials in sensor names, source labels or advertisement payloads.

## Android permissions and location

No permissions are requested and no scan starts automatically. Wi-Fi is unchecked at every activity creation, and an explicit checkbox controls inclusion in a session. Permission buttons separate BLE/controller access from optional Wi-Fi location permission. No GPS/location coordinate API is called; latitude, longitude and location fields are rejected by the observation schema. Wi-Fi/BLE identifiers can still reveal location indirectly.

| Permission | Reason |
| --- | --- |
| `ACCESS_WIFI_STATE` | Read optional Wi-Fi state and scan results |
| `CHANGE_WIFI_STATE` | Explicit Wi-Fi `startScan`; no radio enable/disable operation |
| `ACCESS_COARSE_LOCATION`, `ACCESS_FINE_LOCATION` | Android's optional Wi-Fi/cellular cell-info requirements; requested together through the corresponding optional permission buttons |
| `BLUETOOTH_SCAN` with `neverForLocation` | Foreground BLE discovery without deriving physical location |
| `BLUETOOTH_CONNECT` | Controller state and explicit bonded-target GATT discovery |

INTERNET and CHANGE_NETWORK_STATE support separately confirmed bounded Android HTTPS tests; READ_PHONE_STATE supports cellular callbacks and ACCESS_NETWORK_STATE reads connectivity. There is no background location, broad storage, Bluetooth advertising, boot receiver or foreground-service permission. Storage access uses explicit document pickers. Backup and cleartext traffic are disabled; the activity uses `FLAG_SECURE` and a single-task launch mode. GATT still requires an exact-address expiring request, visible confirmation and an already-bonded target; it initiates no pairing, characteristic reads or writes. BLE `neverForLocation` may filter some beacons. Fine location stays declared because optional Wi-Fi scanning and detailed cellular cell access require it, but ATLAS never collects coordinates. OS grants can persist after a session; revoke them through Android settings if no longer needed.

These choices follow the primary [Android Wi-Fi scan documentation](https://developer.android.com/develop/connectivity/wifi/wifi-scan) and [Bluetooth permission documentation](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions). Runtime permission, screenshot, lifecycle and radio behavior still require device testing; source checks alone do not prove them.

## Retention

Configure `storage.retention_days` in YAML: default 7, permitted 1..3650. Expiration uses observation timestamps, not import time. Run maintenance explicitly, or schedule it under the same ordinary user using a scheduler you manage:

```sh
atlas --config config/atlas.yaml security retention
atlas --config config/atlas.yaml security retention --apply
```

Preview never writes. Apply uses a write transaction, `secure_delete`, then compacts SQLite. If any raw observation expires, **all Wi-Fi baselines, BLE findings and detection findings are invalidated** because they can embed expired observations. Otherwise derived rows expire by their own timestamps. This deliberately also discards newer derived evidence and suppression state; rebuild reviewed baselines and rerun analysis as needed. Legacy `atlas-rf purge --before TIMESTAMP` also invalidates every derived table when it removes observations. Successful retention changes an existing evidence manifest's digest: preserve any authorized archival copy separately before applying deletion.

There is no retention daemon and no automatic deletion during read commands. Seven days is a maintenance policy, not a guaranteed wall-clock lifetime. Maintenance must run to enforce it. Android private cache cleanup runs at new-session creation, retaining at most two previous spools and removing leftovers older than a day; current session is additional. This is a fixed cache bound, not configurable Linux retention and not cleanup while idle. Exported documents, logs, manifests, terminal output, external backups, filesystem snapshots and physical flash remnants are outside database/cache retention. Optional logs rotate at 1 MiB plus two backups and have no age-based expiration.

## Evidence verification

```sh
atlas security verify
atlas security seal --output evidence-manifest.json
# Retain the manifest independently, in a trusted location.
atlas security verify --manifest /trusted/location/evidence-manifest.json
```

Verification uses a consistent read transaction and SQLite quick-check. It checks canonical observation hashes and indexed metadata, BLE/detection finding hashes and supporting observation hashes. A logical SHA-256 snapshot covers the schemas and all rows of the four recognized evidence tables, including Wi-Fi baselines. Baselines have no independent embedded hash; an independently retained manifest is required to detect their content changes. Unknown tables fail verification. Verification is bounded to 200,000 total rows, 256 MiB serialized data and a SQLite progress budget; exceeding a budget is a failure, never a successful partial check. A manifest comparison detects additions, deletion and modification since the snapshot. SQL indexes, free space and physical page layout are not evidence and are not authenticated by the logical digest.

SHA-256 is **not sender authentication or a digital signature**. A writer who can replace both data and its manifest can recompute all hashes. Verification without a trusted external manifest detects internal inconsistencies but cannot establish completeness or historical authenticity. Bridge checksums cover payload bytes, not authenticated source identity or metadata. Source labels and supplied authorization attestations remain unverified. Evidence manifests create no signing keys or shared secrets. The separate cellular bridge creates and stores a shared HMAC authentication secret in private Debian files and Android app storage; see the cellular transport section below. Evidence integrity failures return a nonzero CLI status.

## Bubblewrap investigation and enforcement

```sh
atlas security isolation
```

This runs real `unshare` tests for user, mount, PID, network, IPC and UTS namespaces, then attempts the exact offline Bubblewrap profile with assertions for hidden host directories, read-only runtime, cleared environment, zero effective capabilities, `no_new_privs` and denied network access. Failure returns exit 2 and `usable: false`. Presence of `bwrap` or a successful whole-root bind is insufficient. The policy follows [Bubblewrap's upstream security guidance](https://github.com/containers/bubblewrap#sandbox-security) and [option documentation](https://github.com/containers/bubblewrap/blob/main/bwrap.xml).

Compatible child utilities use only trusted system executables and argument arrays, no shell, no inherited descriptors/environment, disconnected stdin and bounded private output/error files. The profile requires unshared namespaces, disabled nested user namespaces, all capabilities dropped, a new session and parent-death termination. Only `/usr`, `/bin`, `/lib` and `/lib64` runtime trees are mounted read-only; host home, shared storage, D-Bus, configuration and radios are absent. Root is read-only; private `/tmp` is capped at 16 MiB. No host network namespace is shared. Fixed executable search paths reject setuid/setgid, current-user-owned and group/world-writable tools; owner 65534 is accepted for system files whose host root is unmapped in this rootless environment. The OS runtime tree and its administrators remain trusted.

**Measured here, 2026-10-29:** Linux 6.12.93 Android kernel, aarch64, ordinary UID 1000, Bubblewrap 0.12.0. User namespace and combined required namespace creation succeeded. Full Bubblewrap setup failed with `bwrap: loopback: Failed to create NETLINK_ROUTE socket: Operation not permitted`. Thus the required profile is **unavailable on this execution host**, despite basic Bubblewrap execution having worked in an earlier whole-root-bind test. Payload isolation assertions could not run; they are not claimed as verified. Rerun on the exact intended Debian guest/device after environment changes. No sysctl, Android setting, seccomp policy or privilege was changed to bypass this restriction.

Failure never retries unsandboxed, uses `--share-net`, or substitutes `--unshare-user-try`. Guest `ip`, `nmcli` and `bluetoothctl` collectors are deliberately refused: their host-network/D-Bus requirements are incompatible with this offline profile. Host netlink diagnostics are also disabled. Use explicit Android/export telemetry. A compatible sandbox may work on another host, but no successful full-profile operation is claimed here. The main Python application and its authorized TCP probe implementation are not sandboxed by Bubblewrap; isolation is a subprocess boundary. User-namespace probes invoke fixed trusted utilities directly solely to test those kernel capabilities.

## Resource limits and remaining limits

| Surface | Enforced budget |
| --- | --- |
| Imports | 16 KiB event, 32 MiB legacy file, 50,000 batch rows; Wi-Fi/BLE and bridge have tighter bounds |
| Observation database | 200,000 observations; 256 MiB SQLite page ceiling |
| Child process | Wall timeout at most 30 seconds; 30 CPU seconds; 256 MiB address space; 64 descriptors; 64 per-user processes; zero core dumps; 2 MiB per output/error file |
| Sandbox scratch | 16 MiB `/tmp`, read-only root/runtime |
| Detection | Existing bounded policy, groups, history window, finding count and supporting-evidence bytes |
| TCP probes | 256 hosts, 32 ports, 32 workers; connection timeout 0.05..5 seconds |
| Android session | 15 seconds; BLE discovery 10 seconds; 256 queued events, 10,000 events, 8 MiB spool |

CLI monitor thresholds cover RSS, available memory and disk reserve. These are sampled checks, not kernel-wide cgroup quotas. Process limits are per-process/per-user, not an aggregate workload guarantee; child descendants, SQLite journals/VACUUM and backups can use additional resources. No custom seccomp filter, cgroup controller, sandboxed main interpreter, network broker or per-tenant boundary is implemented. Kernel/Bubblewrap vulnerabilities, compromised OS/runtime packages, root, or another process controlling the same user are outside the protection of file modes and unkeyed hashes. Subprocess pre-exec limits assume synchronous use; do not invoke the runner from a multithreaded embedded application. A strict profile can reject compatible-looking utilities due to missing locale/configuration/runtime files or process limits: no fallback is supplied.

Android compilation/installation and live permission/GATT/radio testing remain unverified: Java, Gradle, Kotlin, adb and Android SDK tooling are absent. The former three pytest fixture workflows now execute as portable unittest cases; pytest remains absent but is no longer needed for complete test discovery. This hardening pass is not an exhaustive vulnerability audit, and radio spoofing, address rotation, cached platform results and unauthenticated source imports still constrain conclusions. Anomalies remain review hints, never confirmed incidents.

## Integrated prototype completion

`atlas` now exposes ingestion, history, topology, scoped stored IP analysis, authorized IP probing, reports, dashboard and the controlled demo alongside existing Wi-Fi/BLE/policy/security commands. `atlas-rf` delegates to the same dispatcher. The main demo/test orchestration retains ordinary-user authority; the Bubblewrap policy is specifically for compatible collector/utility children, not a sandbox for the main interpreter. See [architecture](../architecture.md), [threat model](../threat-model.md) and [test results](../test-results.md).

## Cellular transport addition

Real cellular exports require a private HMAC key and matching per-assessment challenge, checked before bounded envelope validation/import. Keys are never part of observations or telemetry. Private Debian files (0600) and app-private Android preferences hold these transport keys; neither has application-level encryption. Initial trusted provisioning and deletion of transfer copies are operator responsibilities. Unsigned cellular JSONL is accepted only as explicitly labeled synthetic data, not real Android provenance. HMAC does not attest modem truth; logical evidence manifests remain unauthenticated snapshots. Cellular baselines/session metadata participate in retention invalidation. See [cellular documentation](cellular.md) for the acceptance procedure, permissions and outstanding hardware validation.
