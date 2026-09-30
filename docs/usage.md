# Usage Guide

## Concepts

**Event.** A `DecisionEvent` records one AI decision: `model_id`, `decision`,
`input`, `output`, `actor`, `policy_verdict`, plus free-form `metadata` and a
UTC `timestamp`. At log time the input is SHA-256 fingerprinted from its
canonical JSON form, so the record is verifiable even when the input itself is
later redacted or dropped.

**Record.** The stored unit: `{"seq", "prev_hash", "event", "entry_hash"}`.
`seq` starts at 0 and increments by 1; `prev_hash` is the previous record's
`entry_hash` (all zeros for genesis); `entry_hash` is
`sha256(canonical_json({seq, prev_hash, event}))`.

**Override.** An `OverrideEvent` is a `DecisionEvent` subclass that must carry
`overrides_seq` (the decision it corrects), a `reviewer` and a `rationale`.
It logs the corrected outcome as `override:<decision>` while keeping the
original record untouched. Corrections are themselves audited, never
edited.

## Library usage

### Logging with redaction at write time

```python
from ai_audit_trail import AuditTrail, DecisionEvent

trail = AuditTrail("/var/log/ai/audit.jsonl")

event = DecisionEvent(
    model_id="credit-scorer-v2",
    decision="deny",
    input={"applicant": "Jane Doe", "email": "jane@example.com", "score_inputs": {...}},
    output={"band": "D", "apr": 0.29},
    actor="lending-api",
    policy_verdict="deny",
)
record = trail.append(event, redact_fields=["applicant"], redact_auto=True)
print(record["seq"], record["entry_hash"])
```

`redact_fields` masks named keys anywhere in the input tree; `redact_auto`
also masks email/phone/SSN/card-number patterns in strings. The record keeps
`input_fingerprint` (computed from the *raw* input before redaction).

### Querying

```python
# All denies by a model in September 2026
rows = trail.query(
    model_id="credit-scorer-v2",
    decision="deny",
    since="2026-09-01T00:00:00+00:00",
    until="2026-10-01T00:00:00+00:00",
)

# The last 50 events overall
recent = trail.query(limit=50)
```

### Verifying integrity

```python
result = trail.verify()
if not result.ok:
    for err in result.errors:
        print("TAMPER:", err)
```

`verify()` checks: every record is well-formed, `seq` values are 0..n-1 in
order, every `prev_hash` links to the previous `entry_hash`, and every
`entry_hash` recomputes correctly. Any failure names the offending record.
`examples/tamper_demo.py` demonstrates the three attack shapes this
catches: payload modification, link breaking, and record deletion.

## Rotating logs

When the log grows large, rotate it without breaking the chain:

```python
trail = AuditTrail("/var/log/ai/audit.jsonl")
checkpoint = trail.rotate(max_records=100_000)
```

`rotate` renames the live file to
`audit.jsonl.<UTC timestamp>.archived.jsonl`, writes the checkpoint
(`audit.jsonl.checkpoint.json`) with the last `seq` and `entry_hash`, and
leaves an empty live file behind. Continue the chain by opening the new
file with the checkpoint:

```python
continued = AuditTrail(
    "/var/log/ai/audit.jsonl",
    checkpoint=AuditTrail.load_checkpoint("/var/log/ai/audit.jsonl"),
)
continued.append(DecisionEvent(model_id="m", decision="ok"))
assert continued.verify().ok
```

The archived file verifies on its own, and the new file's first record
chains to the archived tip. From the CLI:

```bash
audit-trail rotate --max-records 100000 [--archive-dir /var/log/ai/archive] [--force]
audit-trail checkpoint   # print the current chain tip as JSON
```

### Exporting with retroactive redaction

```python
# Export for an external auditor with PII scrubbed, even if it was
# logged in the clear.
count = trail.export_json("auditor-export.json", redact_auto=True)
```

## CLI usage

All commands accept `--log PATH` to choose the log file (default
`./audit-trail.jsonl`).

| Command | Purpose |
|---|---|
| `audit-trail log --model M --decision D [--input JSON] [--output JSON] [--actor A] [--policy-verdict V] [--metadata JSON] [--redact-field F …] [--redact-auto]` | Log one decision |
| `audit-trail override --model M --seq N --decision D --reviewer R [--rationale R]` | Log a human override of record N |
| `audit-trail verify` | Verify the hash chain (exit 1 on tampering) |
| `audit-trail query [--model M] [--decision D] [--actor A] [--since ISO] [--until ISO] [--limit N] [--verbose]` | Query records |
| `audit-trail stats` | Record counts, time range, chain status |
| `audit-trail rotate [--max-records N] [--archive-dir DIR] [--force]` | Archive the log, continue the chain |
| `audit-trail checkpoint` | Print the current chain tip |
| `audit-trail export --output FILE [--redact-field F ...] [--redact-auto]` | Export as JSON array |

`--input`/`--output` accept either JSON or plain text; JSON is parsed when
possible, otherwise kept as a string.

Exit codes: `0` on success; `verify` exits `1` when the chain is broken.

## Operational notes

- **Append-only.** The library never edits or deletes records. For rotation,
  use `rotate()`: the chain continues across files via checkpoint hashes.
- **Concurrency.** Appends take an in-process lock plus an `flock` file lock,
  so multiple processes can share one log file safely.
- **Storage.** One JSON line per record. Fingerprints are computed from
  canonical JSON (sorted keys), so equivalent payloads hash identically.
- **Threat model.** The chain detects modification of the log *file itself*.
  It does not protect against a compromised host writing false events in
  the first place. Pair it with restricted write access and, for strong
  guarantees, periodic external anchoring (e.g. publish the latest
  `entry_hash` to an independent store).
