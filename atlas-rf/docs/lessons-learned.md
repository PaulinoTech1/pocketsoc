# ATLAS project decisions

## 2026-10-29 — Repository packaging

ATLAS source was published as a separate Python/Kotlin component under atlas-rf in PaulinoTech1/pocketsoc without replacing existing PocketSOC documentation. It is not a Rust/runtime/database integration. Existing local PocketSOC edits were preserved.

## 2026-10-29 — Separate collection, delivery and measurement availability

Pre-change trace found a native collector source but no APK deployment, manual SAF export plus manual Debian import, and telephony calls inside an active-subscription-only loop. An inactive/paused SIM is an expected operational constraint, not a software defect or permission to change settings. Repair default-manager attempts with explicit no-subscription scope, optional user-selected SAF folder delivery and bounded operator-started authenticated intake. Keep serving baselines conservative for unattributed default-manager rows. No sockets/continuous background collection or settings changes were introduced.

Alternative: pretend the dashboard could call Android APIs or require SIM activation; rejected because the guest lacks Android API/radio access and SIM activation is expressly forbidden. Preserve HMAC and reject partial/synthetic/unauthenticated inbox files. Provider rename/grant loss is a transport failure, not measurement unavailability. Existing assertions for historical companion_implemented are retained; new source/deployment status fields clarify them.

Regression tests first failed for the missing module, unsupported default scope and disabled-cellular rejection. Python verification is recorded in artifacts/cellular-pipeline-validation-20261029. New Kotlin target-selection tests are unexecuted because the build toolchain is absent. Revisit persistent/background streaming only with an explicit lifecycle/transport contract and genuine device evidence. Hardware integration remains incomplete.

Actual final validation: 225 tests run, 224 passed, one existing socket-dependent skip; real PTY dashboard passed with unchanged database. No Kotlin/device test success is implied.
