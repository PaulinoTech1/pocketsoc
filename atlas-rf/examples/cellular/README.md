# Explicitly synthetic cellular fixtures

All records are invented. `observations.jsonl` uses `synthetic:` sources; `session.atlas.json` declares `metadata.synthetic=true`. No Android APIs or network tests produced these values. Regenerate with `.venv/bin/python examples/cellular/generate.py` from the repository root.

The scenario includes serving and neighboring LTE/NR cells, cached/unknown controls, normal radio/display changes, service/data/connectivity interruptions, monotonic signal degradation and two invented bound HTTPS results. The endpoint `example.invalid` is a reserved invalid example and is never contacted by the fixture workflow.

Use `atlas cellular ingest --input FILE --synthetic`. See [cellular documentation](../../docs/cellular.md) for expected rules, authenticated real-data requirements and all hardware limitations.
