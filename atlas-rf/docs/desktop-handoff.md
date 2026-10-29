# Desktop handoff for the Android collector

The Debian demo/dashboard has run successfully. Live phone-radio collection and Android-to-Debian integration remain incomplete. The operator currently has only a Pixel available and plans to use a desktop later.

## Existing validation

The latest Debian verification ran 213 tests: 212 passed, one TCP socket test skipped because this execution sandbox denies socket creation. The real terminal dashboard passed Wi-Fi/BLE/stored-TCP views and left its database unchanged. Demo observations and benchmark data are synthetic.

## When a desktop is available

1. Obtain this source on the desktop. Open `android/collector` in Android Studio or use its documented command-line toolchain.
2. Reproduce the pinned JDK 17 / Gradle 8.11.1 / AGP 8.9.2 / Kotlin 2.1.20 / Android SDK 35 build first. Run `gradle :app:testDebugUnitTest :app:lintDebug :app:assembleDebug` and resolve actual build failures. These tasks have not run in the Pixel Debian workspace.
3. Keep Advanced Protection and other phone security controls unchanged. A built debug APK alone does not establish an approved installation path. The proposed route is a signed release AAB distributed through Google Play internal testing, using an appropriate developer account. No developer account or Play release has been provisioned by this project.
4. Establish trusted key/challenge transfer to Android and actual document export back into the read-only Debian share. HMAC uses a shared secret, not an asymmetric signing/verification pair.
5. Validate a genuine Android-produced export and ingest actual observations before marking hardware integration complete. A probe, synthetic fixture, or zero-row export alone is insufficient for LTE/NR acceptance.

See [collector build instructions](../android/collector/README.md), [bridge review and blockers](cellular-bridge-review-20261029.md), and [Debian operating guide](debian-start.md).

No direct nRF Connect integration has been implemented. That app's data must be examined and adapted before ATLAS can ingest it; automatic aggregation is not currently established.
