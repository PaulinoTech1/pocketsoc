# ATLAS project decisions

## 2026-10-29: Publish ATLAS as a separate component in PocketSOC

The operator identified PaulinoTech1/pocketsoc as the requested publication destination. Remote inspection found PocketSOC documentation and no ATLAS source. Keep the existing PocketSOC files and history, add the independently tested ATLAS Python/Kotlin project under atlas-rf, and link it from the root README. This avoids replacing the existing Rust project documentation or implying the runtimes are integrated. The local PocketSOC working tree has unrelated changes and is left untouched.

ATLAS remains a Python/SQLite offline analysis component with optional Kotlin Android collector source; PocketSOC's Rust implementation remains separate. This is a packaging choice, not a Rust rewrite or shared-database integration. Revisit if a concrete integration contract is requested.

Validation: 213 Python tests run, 212 passed, one socket-dependent skip; real PTY dashboard checks passed. Desktop APK compilation, installation, Android export transfer and live LTE/NR ingestion remain unverified. No device security settings changed. Publish source and selected nonsensitive validation logs, excluding databases, pairing secrets, caches and binaries.
