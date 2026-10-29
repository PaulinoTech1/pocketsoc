# Deterministic wireless detection

`atlas detect` evaluates explicit YAML policy against locally stored observations. It never scans radios, probes networks, invokes an LLM, or declares a confirmed security incident. Rule predicates, threshold arithmetic, normalization and ordering are fixed Python code. YAML selects predicates and supplies reviewed expectations; arbitrary expressions, scripts, plugins and object tags are not supported.

## Run, explain and history

After the normal installation/startup setup:

```sh
export PATH="$PWD/scripts:$PATH"
# Synthetic demo only; keep separate from actual observation history.
mkdir -m 700 -p .atlas-demo
atlas-rf --db .atlas-demo/atlas-detection-demo.sqlite3 import examples/detection/telemetry.jsonl
atlas --db .atlas-demo/atlas-detection-demo.sqlite3 detect run --save \
  --rules config/detection.yaml --at 2026-04-17T10:01:00Z
atlas --db .atlas-demo/atlas-detection-demo.sqlite3 detect history
# Use a complete finding ID returned by run/history:
atlas --db .atlas-demo/atlas-detection-demo.sqlite3 detect explain FINDING_ID
```

The twelve-row synthetic fixture contains approved controls, cached observations and repeated policy mismatches. Expected first assessment: five anomalies, one for each configured rule. Repeating the assessment saves zero findings and reports five suppressed candidates. The fixture generator is `examples/detection/generate.py`; it invents all measurements and performs no collection. The explicit historical clock keeps this walkthrough reproducible. Real assessments normally omit `--at`, using current UTC time.

`run --rules FILE [--at ISO_TIMESTAMP]` previews in a read-only transaction. Add `--save` to evaluate and persist new findings atomically. Preview does not apply saved-finding cooldown suppression; it returns current policy candidates with `saved: 0`. Missing storage fails explicitly. `explain FINDING_ID` reads the saved full explanation, including the exact normalized rule and supporting observations. It does not depend on the current YAML. Retention invalidates saved findings when raw evidence expires. `history [--rule-id ID] [--limit 1..500]` returns a compact newest-first index with total and truncation information; the default limit is 100. Explain requires the complete 64-character ID. Both reads use a read-only database transaction; an existing database with no findings returns empty history.

The example policy deliberately matches only `synthetic:detection:*` sources. Replace source labels, SSIDs, addresses, services and allowed endpoints with reviewed scope before using real data. No discovered inventory is silently approved and no default rule scans a subnet.

## YAML policy

`config/detection.yaml` contains all five runnable rule examples. Top-level fields are `version: 1`, optional `defaults`, and a nonempty `rules` list. Each rule requires a unique `id`, fixed `type`, nonempty exact `sources`, `severity`, `confidence`, `investigation`, and its predicate parameters. Optional `enabled` defaults to true. Unknown fields, duplicate keys, aliases, anchors, explicit YAML tags and excessive nesting fail validation. Policies are bounded to 64 KiB, 10,000 YAML tokens, eight nesting levels and 64 rules.

Severity is one of `info`, `low`, `medium`, `high`, `critical`. Confidence is `low`, `medium`, or `high`. These are operator-configured rule labels, not probabilities, authentication guarantees or proof of identity. Supporting records preserve their own provenance metadata, including supplied BLE `evidence_confidence`.

Defaults and per-rule overrides:

| Setting | Default | Meaning |
| --- | --- | --- |
| `min_observations` | 2 | 1..20 distinct qualifying measurement times for one source/asset/mismatch |
| `window_seconds` | 300 | Required observations must fit within this inclusive interval; 1..86400 |
| `max_age_seconds` | 300 | Only measurements within this inclusive age at the assessment clock are considered; 1..86400 |
| `cooldown_seconds` | 3600 | Suppress the same rule/source/asset/mismatch for this interval; 0..86400 |

The supplied example overrides maximum age to 600 seconds. Counts use observation time, not ingestion time or repeated executions. Reimporting a record, changing RSSI at the same timestamp, or rerunning detection cannot turn one measurement time into multiple threshold samples. Future observations relative to `--at` are excluded. Wi-Fi additionally requires explicit fresh metadata and callback age at most 30 seconds; cached/stale/unknown metadata cannot trigger Wi-Fi rules. BLE/TCP measurement age uses the same assessment-clock bound, while BLE completeness/status restrictions apply as below. Missing fields never become invented measurements.

## Predicate semantics

| Type | Required parameters | Match |
| --- | --- | --- |
| `ap-security-downgrade` | `ssid`, `expected_security` | Fresh matching SSID advertises weaker recognized security than the explicit expectation |
| `unrecognized-bssid` | `ssid`, `approved_bssids` | Fresh matching protected SSID uses an address outside the explicit approved list |
| `ble-service-change` | `address`, `expected_services`, `evidence_kind` | Supplied service metadata differs from the monitored expectation for this exact source/address |
| `unknown-management-interface` | `ports`, `allowed_networks` | A recorded successful TCP connection on a configured management port has an IP outside approved networks |
| `unexpected-network-exposure` | `allowed_networks`, `allowed_ports` | Recorded successful TCP connection falls outside the approved network/port combination |

All predicates require an exact source from `sources`. SSIDs compare exactly; there is no wildcard or inferred physical asset linking. Approved BSSIDs and BLE addresses normalize to lowercase MAC strings. `expected_services` is a nonempty list of UUIDs, normalized like the BLE schema. Ports are literal integer lists, with at most 256 entries. Networks are literal CIDR strings with no host bits; IPv4 and IPv6 are supported. Empty allowed-network/allowed-port lists approve nothing. Network/port allowlists form a Cartesian product, not individual endpoint exceptions.

Security expectations are `WPA`, `WPA2`, `WPA3`, or `OWE`. Advertised security ranks are OPEN/NONE/-- below WEP below WPA below WPA2/RSN/OWE below WPA3/SAE. Mixed recognized modes use the weakest advertised mode. Unknown security produces no downgrade verdict. This tests advertised policy compliance, not negotiated encryption or vulnerability; WPA3-to-WPA2 is detectable, while WPA2 and OWE have the same rank for this predicate. The expected level comes from reviewed policy, not automatically learned history. A single weak broadcast cannot satisfy the default threshold.

An unrecognized BSSID is an inventory anomaly. Mesh expansion, replacement APs and legitimate roaming can explain it; duplicate SSIDs alone do not establish an attack. No proof that two BSSIDs refer to the same physical AP is asserted.

BLE `evidence_kind: advertisement` requires an explicit complete advertisement with a UUID list and detects added UUIDs outside the expectation. Missing advertised UUIDs never prove removed capabilities. `evidence_kind: gatt` requires a complete, authorized enumeration record and compares returned service UUIDs with expected UUIDs, including additions and omissions. Failed, cancelled, partial or timed-out enumeration does not trigger service removal. Existing GATT import validation requires enumeration-only scope and no-write/no-pairing attestations. The detector performs no GATT operations. Android may cache GATT metadata. Address rotation results in a different address scope; matching names or payloads never merge addresses. Even the same address can be reused, so physical identity remains unverified.

Management rules identify configured port-policy mismatches, not verified protocols or administrative consoles. TCP evidence means a connection succeeded from the collector's vantage point. It does not prove Internet exposure, vulnerability, ownership or service identity. Routes and neighbor-cache entries alone cannot trigger exposure rules; absence of observations cannot prove a host/service is absent. Legitimate new listeners and approved network changes require investigation and policy review.

## Findings and suppression

Each full finding retains:

- `id` and `rule_id`, observation `timestamp`, severity and confidence;
- `supporting_observations`, each with its canonical observation hash and a full copy of the supplied record;
- `affected_assets`, including the source, observed identifier and radio physical-identity caveat;
- `recommended_investigation`, factual mismatch details, exact normalized `rule_snapshot` and `policy_sha256`;
- threshold arithmetic, limitations, `classification: anomaly` and `confirmed_incident: false`.

No rule elevates anomalies into confirmed incidents. Repeated evidence or a high severity label does not change that classification. Confirmation requires a separate investigation; no incident-promotion command is supplied.

Stable SHA-256 finding IDs derive from normalized policy and evidence. Evidence ordering uses measurement time followed by canonical observation hash, so out-of-order ingestion and same-time record insertion order produce the same result. Exact replay IDs are suppressed even with a zero cooldown. Cooldown keys include the complete normalized rule, exact source/asset and mismatch details. Repeated candidates during a cooldown are suppressed in the current run and against saved findings. A new mismatch, source, asset, or rule revision has a different suppression scope. Cooldown time is measured from observation timestamps; late older evidence cannot override a later saved alert. No mutable LLM score, wall-clock randomness or automatic baseline learning affects verdicts. The returned `evaluated_at` is assessment metadata; finding timestamps remain measurement times.

`run --save` returns newly saved findings, `saved`, `suppressed`, coverage counters, and `confirmed_incidents: 0`. Coverage `examined` counts source-matching rule/observation comparisons, so an observation can be counted by multiple rules. `stale` counts Wi-Fi freshness exclusions in those comparisons; `threshold_pending` counts candidate groups below their count threshold. Observations outside an age window are excluded by the query rather than included in the stale counter. No matches is not a security certification.

## Bounds and retention

Evaluation streams at most 50,000 age-window rows per enabled rule and retains at most 4096 source/asset/mismatch groups per rule. More than 500 candidate findings or 8 MiB total supporting evidence fails the run explicitly and rolls back all new findings. Limits also count candidates later suppressed; narrow the age window or policy if needed. Input windows are bounded, and SQLite uses its existing observation-time index and bounded cache. No Rust component or new package dependency was introduced; YAML uses the existing PyYAML dependency.

`detection_findings` is an additive SQLite audit table with a suppression index. Retention and observation purge invalidate derived findings when they delete raw observations, including embedded evidence and suppression state. See [security.md](security.md) for retention and integrity verification. Detection findings are not automatically included in legacy `atlas report` rules; use `detect history` and `detect explain`.

Tests cover all five predicates, benign approvals, unknown security, stale/cached/old/future observations, rotating BLE addresses, incomplete advertisements, GATT failure versus complete evidence, threshold windows, same-timestamp deduplication, cooldown expiry, stable IDs across insertion order, transactional failure, replay suppression, retained explanations and the CLI workflow. See [development-log.md](development-log.md) for executed verification and environment limitations.
