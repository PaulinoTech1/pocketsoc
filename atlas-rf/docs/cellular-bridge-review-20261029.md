# ATLAS cellular bridge review — 2026-10-29

**Hardware integration: UNVERIFIED / incomplete.** No genuine Android-produced cellular export was available for verification and ingestion. Pixel 10 Pro XL / Android 17 / Advanced Protection are operator-supplied target details, not independently established by guest inspection. No device security settings were changed, no APK was installed, and no Play release was published. This review changes documentation only; application code and existing tests are preserved.

## Authentication finding

The implemented transport is **HMAC-SHA256 with a shared secret**, not an asymmetric signature scheme. `BridgeAuthentication.sign()` in Android uses `Mac.getInstance("HmacSHA256")` and a 32-byte `SecretKeySpec`; `atlas/cellular/transport.py:unwrap()` recomputes HMAC using the same secret and compares with `hmac.compare_digest`. Neither a private signing key nor a public verification key exists in this protocol. The `signed_json` field and `sign` method names do not change that fact.

Authenticated bytes are `UTF8("ATLAS-RF authenticated export v1\n") || UTF8(signed_json)`. Exact inner-envelope bytes include metadata, challenge and the JSONL payload. The inner SHA-256 checks payload integrity; it is not sender authentication. The existing Python UTF-8 vector matches the expected value in Kotlin's test source; Kotlin execution remains pending.

Debian generates 32 random bytes encoded as 64 hex characters, requires an owned private regular single-link key file and rejects symlinks. Android imports that same hex secret into MODE_PRIVATE preferences with backup disabled. There is no Keystore wrapping or application-level encryption. Trusted initial provisioning and deletion of temporary/provider copies remain unresolved operational work. Either Android or Debian can forge an accepted MAC; this proves secret possession, not independent Android identity, modem truth, nonrepudiation or attestation.

The challenge is 32 random bytes encoded as 64 hex characters. A wrong expected challenge fails verification. Challenges are not expired or consumed automatically; reusing an expected challenge accepts the same export again. SQLite deduplication makes repeated ingestion idempotent. Renew and import the challenge for each assessment. APK signing is separate: release/upload private keys sign application artifacts, and certificate/public-key checks establish package signature validity, not cellular-export origin. See [Android app signing](https://developer.android.com/studio/publish/app-signing).

## Implemented versus simulated

| Component | What exists | Runtime evidence |
| --- | --- | --- |
| MainActivity | Permission buttons, key/challenge import, opt-in cellular, visible 15-second collection, lifecycle stop, explicit SAF export and nonce probe | Kotlin source only; no build/install/device run verified |
| CellularCollector | Active subscriptions (up to 8), subscription rebinding, service/signal/data/display callbacks; cached cell read, cell callbacks and one update request per binding; LTE/NR identities and available signal metrics; connectivity callbacks; sentinel/range omission | Calls real Android public APIs in source; no embedded simulated cellular producer; handset/modem output unverified |
| RadioSession / ObservationClock | Bounded queue/spool, receipt versus measurement time, statuses/drops, finalize/hash/HMAC | Kotlin source and unexecuted JVM tests; no Android artifact validated |
| Wi-Fi / BLE / GATT | Public scan APIs; separate authorized bonded-target GATT metadata enumeration | Source implemented; actual radio operation unverified |
| BoundedNetworkTest | Explicit endpoint authorization, Wi-Fi then cellular HTTPS tests with bounds and normal TLS | Source implemented; network binding/routing/cancellation unverified; not required for first passive LTE/NR observation |
| Debian verifier / ingestion | HMAC/challenge/envelope validation, schema checks, atomic SQLite import, replay deduplication, cellular analysis/reporting | Existing local Python tests pass; exercised with synthetic fixtures/mocks |
| examples/cellular and bridge-fixture; scripts/verify_cellular.py | Explicit synthetic data, analysis/resource demo and protocol checks | Simulation only; cannot establish Android hardware integration |

5G display overrides do not establish an NR serving cell. A subscription, service or connectivity row alone is not an LTE/NR measurement. An LTE observation is sufficient for the first real LTE/5G milestone; NR availability depends on actual modem/carrier/API reporting. Detailed cell identity requires existing precise-location permission and location-services availability. Missing/denied/redacted data must remain explicit. Do not change location, radios, debugging or security settings to force success.

## Review findings

1. **Primary delivery gap:** no compiled APK, executed Kotlin/JVM tests, lint output, installed companion, trusted pairing round trip or real Android export has been demonstrated. `companion_implemented=False` in bridge status is conservative but conflates available implementation source with verified deployment; `companion_source_available=True` and `companion_build_verified=False` give the useful distinction.
2. **Reproduced unrelated workflow defect:** `MainActivity` writes `statuses["cellular"] = "disabled_by_default"` even without cellular. `validate_envelope()` treats every status key starting with `cellular` as a cellular session, so an unpaired Wi-Fi/BLE-only or empty export is rejected as requiring authentication. A local empty-envelope reproduction produced `real cellular exports require authenticated transport`. Paired cellular exports avoid this issue. Fix separately with a focused regression covering disabled cellular versus real/failed/zero-row cellular sessions; preserve fail-closed authentication for actual cellular collection.
3. **Documentation drift corrected:** security docs previously claimed no shared secrets were stored; generic Android bridge docs contradicted the manifest about INTERNET and BLE `neverForLocation`. HMAC terminology and these source/document mismatches are now corrected. Some historic artifacts describe synthetic completions; they must not be interpreted as hardware acceptance.
4. **Protocol limitations:** shared-secret holders can forge observations; challenge freshness is operator-managed; verification summaries intentionally retain `hardware_access: UNVERIFIED`. A valid export containing zero rows or only connectivity/status events cannot satisfy LTE/NR hardware acceptance.

## Shared-storage test

`findmnt /mnt/shared` reports an autofs entry plus the effective `android` virtiofs mount with `ro,nosuid,nodev,relatime`. Directory enumeration succeeded for `/mnt/shared` and Documents. Reading one byte from an existing Documents regular file succeeded without exposing its content. `os.access('/mnt/shared/Documents', W_OK)` returned false. No write/remount attempt was made. A bounded filename search under Documents and Download found no `*atlas*` files (depth 3); this is not a whole-device search.

Therefore Android-to-Debian shared-file reads are practical, but **collector delivery remains unverified** until an app-produced file appears and verifies. Guest-to-Android key/challenge transfer cannot use writes to this read-only share. Evidence: [inspection JSON](../artifacts/bridge-review-20261029/inspection.json).

## Practical build and deployment workflow

1. Use an equipped supported workstation or Linux x86-64 CI runner. This guest is aarch64; java/javac/gradle/kotlinc/sdkmanager/aapt2/apksigner/adb are all absent from PATH. No wrapper or APK is present in the project. Native SDK tooling makes this guest a poor initial build target; Android Studio currently lists Linux ARM machines as unsupported in its [installation requirements](https://developer.android.com/studio/install).
2. Reproduce the pinned configuration first: AGP 8.9.2, Kotlin 2.1.20, JDK 17, Gradle 8.11.1, SDK platform 35 and Build Tools 35.0.0. AGP 8.9 officially supports API 35; do not simply switch compileSdk to 37 under these pins. Run from `android/collector`:

   ```sh
   gradle :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
   ```

   Expected APK: `app/build/outputs/apk/debug/app-debug.apk`. Capture the build/lint/test logs, source snapshot hash and APK SHA-256. No success is claimed until these tasks actually pass. See [AGP compatibility](https://developer.android.com/build/releases/agp-8-9-0-release-notes).
3. API 35 compilation and minimum API 31 do not establish Android 17 runtime compatibility. Review Android 17 changes affecting all apps and test on the actual target. If Play submission requires a newer target SDK, migrate compile/target SDK and compatible AGP/Gradle/Kotlin together and repeat checks. Consult [Android 17 documentation](https://developer.android.com/about/versions/17/); do not upgrade blindly for the first build.
4. **Preferred deployment: Google Play internal testing track.** Google's [Advanced Protection documentation](https://support.google.com/android/answer/16339980?hl=en) says unknown-source app installation and updates are blocked. A manually opened debug APK is therefore not the proposed path. Obtain a Play developer account/app entry, configure release signing/Play App Signing through Android Studio's Generate Signed Bundle workflow, and build a signed release AAB. The repository currently has no release signing configuration. Once configured, `gradle :app:bundleRelease` produces `app/build/outputs/bundle/release/app-release.aab`; never embed signing credentials or the bridge secret in source/artifacts.
5. Upload to the internal testing track, add the handset's Play account as a tester, and install through the tester opt-in link in Play Store. Google documents up to 100 testers and Play Store delivery for [internal testing](https://support.google.com/googleplay/android-developer/answer/9845334?hl=en). This is a policy-compatible proposed path, not an observed successful installation on this handset. Developer-account setup, Play availability and any security/policy decisions remain external prerequisites. Internal app sharing is a different feature; do not substitute a workflow requiring handset settings changes.
6. Do not enable USB/wireless debugging, allow unknown sources, disable Advanced Protection/Play Protect, unlock the bootloader or change security settings. No ADB install route is established here. No account creation/upload/publication has been attempted in this review.

## Prioritized blockers to the first genuine LTE/NR observation in Debian

1. **Build evidence:** obtain the equipped build host and get Kotlin compilation, JVM tests, lint and APK assembly passing. Resolve actual failures before distribution; provide a signed release AAB for Play.
2. **Approved installation:** provision the Play internal test and install on Pixel 10 Pro XL with Android 17 and Advanced Protection left enabled; verify actual app launch. A debug APK on disk does not resolve this.
3. **Trusted reverse provisioning:** establish an approved private Debian-to-Android transfer for the shared secret and a new public challenge. The mounted share is read-only from Debian. The implementation accepts documents, but no working reverse path is demonstrated. Do not place the secret in ordinary telemetry exports, CI artifacts or shared public directories.
4. **Actual file propagation:** export the radio-free UUID probe into a local Android document location mapping to `/mnt/shared`; verify against the UUID displayed in the app. Then export a paired challenge-response bundle and verify HMAC/challenge in Debian. Probe success alone is insufficient.
5. **Real radio availability:** with operator-approved runtime app permissions and current device settings, run a visible opt-in cellular session with an active subscription. Require at least one Android LTE/NR `cell` or `signal` observation with an available radio metric/identity; record freshness and omit unavailable values. No toggles or fabricated data to compensate for denied access.
6. **Final acceptance:** verify the original app-produced export and ingest it into a private Debian database. Confirm inserted LTE/NR records, source/session, measurement/receipt times, statuses/drops and sensible values. Re-import should insert zero duplicates. Retain original export, digest, build identity and acceptance output. Until this evidence exists, keep hardware integration incomplete.

Use the existing commands with actual paths and the challenge value read from the private challenge document:

```sh
./scripts/atlas cellular verify --input ACTUAL_EXPORT.atlas.json --key PRIVATE_KEY_FILE --nonce EXPECTED_CHALLENGE
./scripts/atlas --db PRIVATE_DB cellular ingest --input ACTUAL_EXPORT.atlas.json --key PRIVATE_KEY_FILE --nonce EXPECTED_CHALLENGE
./scripts/atlas --db PRIVATE_DB cellular inspect --source android:INSTALL_UUID:cellular
```

Do not pass `--synthetic` for real acceptance. Verification authenticates supplied bytes; operator-confirmed Android production plus actual LTE/NR content and successful ingestion supply the missing integration evidence.

## Validation

`.venv/bin/python -m unittest discover -s tests -v`: 213 tests run, OK, one skipped. Existing ResourceWarnings mention unclosed SQLite connections; no test failed. Full output: [unittest log](../artifacts/bridge-review-20261029/unittest.txt). Pytest invocation was unavailable (`No module named pytest`); this suite's tests are unittest-compatible. Kotlin tests, lint, APK/AAB assembly, Play installation and actual Android export verification/ingestion remain unexecuted. No application code or tests were modified.
