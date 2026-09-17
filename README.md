# ai-audit-trail

A tamper-evident audit trail for AI decisions. Every decision an AI system
makes — who/what/when, the model id, an input fingerprint, the output, the
policy verdict, and any human reviewer overrides — is appended to a
hash-chained, append-only JSONL log. Any modification, insertion, deletion or
reordering of records breaks the chain and is caught by `verify`.

Built by [Anusha Mukka](https://anushamukka.com).

## Why

AI governance frameworks (NIST AI RMF, EU AI Act logging obligations) expect
operators to keep records of consequential automated decisions. `ai-audit-trail`
gives you a small, dependency-free tool for that: log decisions, prove the log
wasn't altered, redact sensitive inputs while keeping them verifiable, and
export evidence for auditors.

## Install

```bash
pip install git+https://github.com/anushamukka9/ai-audit-trail.git
```

Or from source:

```bash
git clone https://github.com/anushamukka9/ai-audit-trail.git
cd ai-audit-trail
pip install .
```

Requires Python 3.9+. No third-party dependencies.

## Quickstart

```python
from ai_audit_trail import AuditTrail, DecisionEvent

trail = AuditTrail("audit-trail.jsonl")

trail.append(DecisionEvent(
    model_id="fraud-detector-v3",
    decision="deny",
    input={"txn_id": "txn-8842", "amount": 9400},
    output={"score": 0.93, "reason": "velocity_anomaly"},
    actor="inference-service",
    policy_verdict="escalate",
))

# Prove nothing was altered
assert trail.verify().ok

# Query history
for record in trail.query(model_id="fraud-detector-v3", decision="deny"):
    print(record["seq"], record["event"]["timestamp"])

# Export for an auditor (with PII scrubbed)
trail.export_json("audit-export.json", redact_auto=True)
```

See [`examples/quickstart.py`](examples/quickstart.py) for a runnable version.

## CLI

```bash
# Log a decision
audit-trail log --model fraud-detector-v3 --decision deny \
    --input '{"email":"jane@example.com","amount":9400}' \
    --output '{"score":0.93}' --actor inference-service \
    --policy-verdict escalate --redact-auto

# Log a human reviewer override
audit-trail override --model fraud-detector-v3 --seq 0 \
    --decision approve --reviewer human-reviewer-1 \
    --rationale "false positive confirmed"

# Verify the chain
audit-trail verify

# Query by model / decision / actor / time range
audit-trail query --model fraud-detector-v3 --decision deny \
    --since 2026-09-01T00:00:00+00:00 --limit 20

# Export as JSON (optionally with redaction)
audit-trail export --output audit.json --redact-auto
```

## API

- `AuditTrail(path)` — append-only JSONL store. Thread-safe and
  multi-process-safe appends.
- `AuditTrail.append(event, redact_fields=None, redact_auto=False)` — log a
  `DecisionEvent` (or plain dict); returns the stored record with `seq`,
  `prev_hash`, `entry_hash`.
- `AuditTrail.verify()` — recompute the full chain; returns a
  `VerificationResult` with `ok`, `records_checked`, `errors`.
- `AuditTrail.query(model_id=None, decision=None, actor=None, since=None,
  until=None, limit=None)` — filter records.
- `AuditTrail.get(seq)` / `len(trail)` / `iter_events()` — record access.
- `AuditTrail.export_json(dest, redact_fields=None, redact_auto=False)` —
  export records as a JSON array.
- `DecisionEvent` / `OverrideEvent` — event models; inputs are SHA-256
  fingerprinted at log time.
- `ai_audit_trail.redaction.redact_input(event, fields, auto)` — mask named
  fields and/or common PII patterns (email, phone, SSN, card numbers),
  preserving `input_fingerprint` so a holder of the raw input can still prove
  it matches the record.

## Architecture

Each record on disk is one canonical-JSON line:

```json
{"seq": 3, "prev_hash": "…", "event": {…}, "entry_hash": "…"}
```

where `entry_hash = sha256(canonical(seq, prev_hash, event))` and the genesis
record chains to a fixed all-zeros hash. The hash chain makes the log
tamper-evident: altering any payload changes its hash and breaks every later
link; deleting or reordering records breaks sequence linkage. Verification
replays the whole chain from genesis.

Redaction is designed so privacy and verifiability coexist: the raw input is
replaced by a tombstone (`{"redacted": true, "masked_value": …, "fields": …}`)
while `input_fingerprint` (the SHA-256 of the canonical raw input, captured
before redaction) is retained. Anyone holding the original input can recompute
its fingerprint and confirm it matches the audit record.

## Docs

- [`docs/usage.md`](docs/usage.md) — full usage guide (library + CLI).

## License

MIT — Copyright (c) 2026 Anusha Mukka. See [LICENSE](LICENSE).
