# Cellular pipeline diagnosis — recorded before repair, 2026-10-29

The operator has deliberately paused the cellular SIM. Do not reactivate it, enable mobile data, change location/radio/cellular/security settings, or run bound cellular HTTPS tests. A paused carrier service may still appear as an active Android subscription; an empty subscription list does not prove why it is empty. No handset-state diagnosis is inferred from Debian.

## Root cause before code changes

ATLAS is currently an explicitly invoked file-ingestion/analysis engine, not a running automatic collector pipeline. An in-repository native Android collector exists, but has not been compiled, installed or demonstrated on the handset. Its visible Activity must be started manually, cellular is opt-in, and key/challenge provisioning is required. Finalization stores a private cache file; another manual document-picker export is required. Debian has verify/import commands but no inbox consumer. The dashboard only reads SQLite. Third-party applications are not a required architectural dependency, and their exports are not automatically compatible.

Separately, CellularCollector.refreshSubscriptions binds ALL telephony listeners and cell reads inside selected active subscriptions. With an empty Android subscription list it installs no telephony listeners/cell requests and reports only a zero count plus connectivity. The Python schema also rejects cell/signal/service/technology rows without a subscription ID. This unnecessarily couples attempted radio observation to an active subscription, although Android does not guarantee cell results without one. The collector must be allowed to try default-manager public radio APIs, with an explicit default scope and no fabricated subscription ID, while recording empty/unsupported/denied results accurately. Never enable a SIM to work around missing implementation.

## Eight requested checks

1. Data enters through `atlas cellular ingest --input` or `atlas bridge import FILE` (generic ingestion cannot promote raw real cellular JSONL). Finalized real cellular envelopes require the shared HMAC key and matching challenge. `atlas cellular verify` does not import.
2. Native Kotlin collector exists under android/collector, including MainActivity, CellularCollector, RadioSession, ObservationClock and BridgeAuthentication.
3. TelephonyManager is implemented: per-subscription instances, TelephonyCallback service/signal/data/display/cell listeners, cached allCellInfo, bounded requestCellInfoUpdate, LTE/NR mapping, SubscriptionManager and ConnectivityManager listeners. The active-subscription loop creates an avoidable no-subscription collection gap.
4. Gradle source configuration exists (min API 31, compile/target 35), but there is no wrapper/APK or local JDK/Gradle/SDK/ADB. APK compilation, deployment and Android 17 runtime compatibility remain UNVERIFIED. GitHub now contains the ATLAS source at PaulinoTech1/pocketsoc/atlas-rf, commit eca9c6ac4ac97702b2944fc3dbadcf9a5fb9182e.
5. Manifest declares READ_PHONE_STATE, fine/coarse location, ACCESS_NETWORK_STATE and optional Wi-Fi/BLE/authorized-test permissions. MainActivity requests runtime permissions; CellularCollector checks phone state and fine location plus the existing location-services state. Manifest declaration does not prove a runtime grant. No permission changes were attempted in this diagnosis.
6. Readable Android virtiofs share exists at /mnt/shared and is read-only to Debian. No real app-produced challenge-response export has been verified/ingested. Key/challenge reverse provisioning is unresolved. Directory visibility is not end-to-end bridge success.
7. Debian currently supports explicit imported files for cellular; no direct guest radio access, background import or automatic Android export exists. A native collector is present in source, so 'ATLAS has no collector' would be incorrect.
8. Active SIM is not needed for file authentication, transport, ingestion or analysis; the current Android implementation incorrectly gates attempted telephony observations on active subscriptions. Actual unregistered/emergency/cached cell visibility remains Android/modem/carrier dependent. A paused SIM legitimately prevents subscribed service/data and does not itself imply software failure.

## Complete current pipeline

Operator starts installed Activity (not yet deployed) → existing Android grants/feature checks → active-subscription-bound public callbacks → LTE/NR mapping and original monotonic timestamps → bounded RadioSession queue/private JSONL spool → finalized envelope + HMAC(shared key, exact inner bytes including challenge) → manual ACTION_CREATE_DOCUMENT export → chosen Android local directory → read-only Debian virtiofs → manual verify/import → validate schema/authentication before SQLite transaction → cellular history/baselines/analysis → read-only dashboard/reports.

Missing transitions are build/deploy, persistent user-authorized delivery destination, automatic delivery after explicit sessions, and a bounded authenticated inbox consumer. The dashboard cannot start Android APIs from inside Debian.

## Failure classification

- Implementation/deployment: missing APK/toolchain/installed app; no auto-delivery/consumer; no-subscription gate; misleading companion_implemented=false despite source.
- Permission/API restriction: recorded SecurityException, phone-state denial, precise-location denial, location-services off. Not observed on this handset; do not claim grants or toggle settings.
- Transport/authentication: inaccessible destination, revoked SAF grant, partial export, bad HMAC/challenge or missing inbox. Separate from radio availability; reject before database writes.
- Measurement availability: no active subscriptions, no service, empty/redacted cells, unknown or cached times, LTE/NR not exposed. Valid status-only/zero-measurement sessions must remain importable and must not count as LTE/NR success.

## Bounded repair scope

Preserve explicit user-started visible sessions and current security protections. Add optional user-selected persistent SAF directory delivery after finalization (no server, no automatic radio restart), a foreground Debian authenticated inbox consumer, accurate deployment/collection statuses, and explicit default-manager no-subscription fallback. Add regression tests before implementation. Preserve HMAC requirements for actual cellular sessions and avoid treating cellular=disabled_by_default alone as collection. Hardware integration stays UNVERIFIED until a genuine Android-produced export verifies and ingests. Kotlin/device checks cannot be represented as passing without the absent toolchain/device deployment.
