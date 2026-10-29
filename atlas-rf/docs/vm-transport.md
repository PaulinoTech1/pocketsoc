# VM transport investigation

Inspection: **2026-10-29, approximately 17:08 UTC**. Performed before implementing the collector. No Android settings, root state, firmware, radio mode or network configuration was changed.

## Available methods and observed limits

| Method | Status in current execution view | Evidence / decision |
| --- | --- | --- |
| Android shared files through virtiofs | SUPPORTED mount/directory visibility; end-to-end collector delivery UNVERIFIED | `/mnt/shared` has an effective `android virtiofs ro,nosuid,nodev,relatime` mount; Documents and Download are readable directories. Select this for the prototype, pending the nonce-file check. |
| Guest writes back through shared mount | UNSUPPORTED here | `test -w /mnt/shared/Documents` returns 1; effective mount is read-only. No write/remount attempted. |
| Android app → guest localhost TCP | UNVERIFIED addressing; UNSUPPORTED socket creation here | `ip -j address show` fails with netlink EPERM; AF_INET socket creation fails errno 1. No host/guest loopback identity is assumed. |
| VM vsock | UNVERIFIED host endpoint/protocol; UNSUPPORTED socket creation here | virtio-vsock driver directory exists but no accessible `/dev/vsock` or `/dev/vhost-vsock`; AF_VSOCK socket creation fails errno 1. A missing device node alone would not prove vsock absent. |
| Unix-domain sockets | SUPPORTED local socket creation only | AF_UNIX socket creation succeeds without bind/connect; no exported endpoint exists. This does not establish communication across Android/VM kernels. |
| USB / adb | UNSUPPORTED in this context | No `/dev/bus/usb` access and no adb executable; no debugging bridge was enabled. |
| virtio serial channel | UNVERIFIED / not exposed at checked path | No `/dev/virtio-ports` entries found. No host service/protocol was discovered. |

Commands used: `findmnt`, `ls -ld`, `test -r`, `test -w`, reads of `/proc/net/dev`, `/proc/net/route`, `/proc/net/unix`, `ip -j address show`, `command -v`, limited toolchain-path checks and socket **creation-only** tests in Python. No packet or payload was sent during network investigation. The current `/proc/net` view contains loopback and tunnels, without sysfs's broader virtio interface; see [environment.md](environment.md).

## Selected prototype transport

Use a user-selected Android document export, followed by explicit Debian file verification/import. This works with a read-only guest share because the **Android app**, not the guest, writes the file. The app uses the supported Storage Access Framework; no broad storage permission is required. Select a local Documents provider/location, because a cloud provider URI is not necessarily visible in the guest. [Android document storage guide](https://developer.android.com/training/data-storage/shared/documents-files).

The mount has been observed. A real collector-written file has **not** yet crossed it in this session. Do not describe the complete shared-file transport as verified until the following acceptance check succeeds on the actual phone.

## Nonce-file verification procedure

1. Build/install the collector through an already approved Android deployment mechanism. Current build/install blockers are recorded below; do not change Android security settings to bypass them.
2. Without granting radio permissions, press **Export transport nonce**. The app displays a random UUID and opens the document picker.
3. Save `atlas-transport-probe.json` to local `Documents/ATLAS-RF`, or another explicitly chosen local directory that maps into the share. Wait for the app to confirm the stream closed. If the provider gives the file a suffix, use its actual name.
4. From Debian, verify the file using the exact UUID displayed by the app:

```sh
./scripts/atlas bridge verify-probe "/mnt/shared/Documents/ATLAS-RF/atlas-transport-probe.json" \
  --nonce "REPLACE_WITH_UUID_DISPLAYED_BY_APP"
```

5. Confirm `nonce_matches: true`, `synthetic: false`, `path_on_android_share: true` and `status: SUPPORTED`. A nonce typed from another source does not satisfy this operator acceptance check.
6. Then export a real telemetry session and use `atlas bridge verify` followed by `atlas bridge import`. Confirm the expected source labels, timestamps and counts. This second check establishes telemetry delivery, separately from nonce-file visibility.

The nonce proves that the expected file can be read when compared with the app display. It is not cryptographic authentication; a local writer with access could forge a file. SHA-256 in telemetry covers the exact JSONL payload and detects accidental damage against the declared hash. It does not authenticate metadata or a sender.

## If networking is needed later

There is no Android/guest network bridge or listener. The cellular extension declares INTERNET only for explicit Android-bound HTTPS tests; those requests are not used as a VM transport. Future networking must first verify actual guest/host addresses and a reachable endpoint without assuming localhost. Require TLS with pinned server identity and client authentication (for example, mutually authenticated TLS), explicitly paired credentials, bounded frames/timeouts, replay protection and operator-scoped acceptance. Credentials must stay in Android Keystore / private guest storage, outside shared telemetry files. Do not introduce a plaintext or unauthenticated fallback. This is a future requirement, not a claim of a functioning network bridge.

## APK build and installation blocker

- `java`, `javac`, `gradle`, `kotlinc`, `sdkmanager`, `aapt`, `aapt2`, `apksigner` and `adb` were absent from PATH.
- No Android SDK/JDK/Gradle installation was found at the limited conventional paths checked (`/opt`, `/usr/lib`, `/usr/local`, home Android SDK / Gradle cache locations).
- `ANDROID_HOME`, `ANDROID_SDK_ROOT` and `JAVA_HOME` were unset.
- Attempted `gradle --offline :app:testDebugUnitTest :app:assembleDebug` in `android/collector`: `gradle: command not found` (exit 127).
- Current restricted networking also prevents ordinary dependency downloads; no toolchain installation or privileged workaround was attempted.
- No APK was produced, signed, installed or run. Kotlin compilation, JVM tests, Android API behavior and actual shared-file propagation remain **UNVERIFIED**.

Continue using [the explicit fixture workflow](../android/collector/README.md) for Debian transport validation. It is intentionally synthetic and cannot establish radio access or Android-to-VM delivery.

## Cellular authenticated file transport

Cellular telemetry now requires an HMAC-authenticated finalized document and matching expected Debian challenge. The existing nonce-only probe and unkeyed Wi-Fi/BLE envelope remain compatibility tools; they do not authenticate cellular exports. Follow the [cellular transport acceptance procedure](cellular.md) before real collection. The shared Documents directory is visible but contained no Android cellular export in this completion session; `adb` and Android build tooling are absent. Phone-to-VM delivery and trusted key provisioning remain UNVERIFIED. Local protocol tests are explicitly synthetic. No Android/VM shared-localhost assumption or network fallback was introduced.
