"""Test suite for ai-audit-trail."""

import json
import os

import pytest

from ai_audit_trail import AuditTrail, DecisionEvent
from ai_audit_trail.hashing import entry_hash
from ai_audit_trail.models import OverrideEvent
from ai_audit_trail.redaction import redact_input


@pytest.fixture()
def trail(tmp_path):
    return AuditTrail(str(tmp_path / "trail.jsonl"))


def _event(**kwargs):
    base = dict(model_id="fraud-detector-v3", decision="deny")
    base.update(kwargs)
    return DecisionEvent(**base)


def test_append_assigns_seq_and_chain(trail):
    r1 = trail.append(_event(input={"a": 1}))
    r2 = trail.append(_event(input={"a": 2}))
    assert r1["seq"] == 0
    assert r2["seq"] == 1
    assert r2["prev_hash"] == r1["entry_hash"]


def test_verify_clean_chain(trail):
    for i in range(5):
        trail.append(_event(input={"i": i}))
    result = trail.verify()
    assert result.ok
    assert result.records_checked == 5


def test_verify_detects_tampering(trail):
    trail.append(_event(input={"a": 1}))
    trail.append(_event(input={"a": 2}))
    # corrupt the first record's payload in place
    with open(trail.path) as fh:
        lines = fh.readlines()
    record = json.loads(lines[0])
    record["event"]["input"] = {"a": 999}
    lines[0] = json.dumps(record) + "\n"
    with open(trail.path, "w") as fh:
        fh.writelines(lines)
    result = trail.verify()
    assert not result.ok
    assert any("entry_hash mismatch" in e for e in result.errors)


def test_verify_detects_broken_link(trail):
    trail.append(_event(input={"a": 1}))
    trail.append(_event(input={"a": 2}))
    with open(trail.path) as fh:
        lines = fh.readlines()
    record = json.loads(lines[1])
    record["prev_hash"] = "f" * 64
    record["entry_hash"] = entry_hash(record["seq"], record["prev_hash"], record["event"])
    lines[1] = json.dumps(record) + "\n"
    with open(trail.path, "w") as fh:
        fh.writelines(lines)
    result = trail.verify()
    assert not result.ok
    assert any("prev_hash mismatch" in e for e in result.errors)


def test_query_filters(trail):
    trail.append(_event(model_id="m1", decision="approve", actor="svc-a"))
    trail.append(_event(model_id="m1", decision="deny", actor="svc-b"))
    trail.append(_event(model_id="m2", decision="deny", actor="svc-a"))
    assert len(trail.query(model_id="m1")) == 2
    assert len(trail.query(decision="deny")) == 2
    assert len(trail.query(actor="svc-a")) == 2
    assert len(trail.query(model_id="m1", decision="deny")) == 1


def test_query_time_range(trail):
    trail.append(DecisionEvent(model_id="m", decision="x", timestamp="2026-01-10T00:00:00+00:00"))
    trail.append(DecisionEvent(model_id="m", decision="x", timestamp="2026-06-10T00:00:00+00:00"))
    trail.append(DecisionEvent(model_id="m", decision="x", timestamp="2026-09-10T00:00:00+00:00"))
    assert len(trail.query(since="2026-03-01T00:00:00+00:00")) == 2
    assert len(trail.query(until="2026-03-01T00:00:00+00:00")) == 1
    assert len(trail.query(since="2026-03-01T00:00:00+00:00",
                           until="2026-08-01T00:00:00+00:00")) == 1


def test_redaction_masks_fields_and_keeps_fingerprint(trail):
    event = _event(input={"name": "Jane Doe", "email": "jane@example.com", "amount": 50})
    record = trail.append(event, redact_fields=["name"], redact_auto=True)
    stored = record["event"]["input"]
    assert stored["redacted"] is True
    assert stored["masked_value"]["name"] == "[REDACTED]"
    assert stored["masked_value"]["email"] == "[REDACTED]"
    assert stored["masked_value"]["amount"] == 50
    assert record["event"]["input_fingerprint"] == event.input_fingerprint
    assert trail.verify().ok


def test_redact_input_unit():
    event = {"input": {"ssn": "123-45-6789", "note": "ok"}, "input_fingerprint": "abc"}
    redacted = redact_input(event, auto=True)
    assert redacted["input"]["redacted"] is True
    assert redacted["input"]["masked_value"]["ssn"] == "[REDACTED]"
    assert redacted["input_fingerprint"] == "abc"  # fingerprint preserved


def test_override_event_links_to_original(trail):
    original = trail.append(_event(decision="deny"))
    override = OverrideEvent(
        model_id="fraud-detector-v3",
        decision="approve",
        overrides_seq=original["seq"],
        reviewer="human-reviewer-1",
        rationale="false positive confirmed",
    )
    record = trail.append(override)
    assert record["event"]["overrides_seq"] == original["seq"]
    assert record["event"]["actor"] == "human-reviewer-1"
    assert record["event"]["decision"].startswith("override:")
    assert trail.verify().ok


def test_export_json_roundtrip(trail, tmp_path):
    trail.append(_event(input={"email": "a@b.com"}))
    trail.append(_event(input={"x": 1}))
    dest = str(tmp_path / "export.json")
    count = trail.export_json(dest, redact_auto=True)
    assert count == 2
    with open(dest) as fh:
        records = json.load(fh)
    assert len(records) == 2
    assert records[0]["event"]["input"]["redacted"] is True
    assert records[0]["event"]["input"]["masked_value"] == {"email": "[REDACTED]"}
    assert records[1]["event"]["input"]["redacted"] is True
    assert records[1]["event"]["input"]["masked_value"] == {"x": 1}


def test_empty_log_verifies(trail):
    result = trail.verify()
    assert result.ok
    assert result.records_checked == 0


def test_persistence_across_instances(tmp_path):
    path = str(tmp_path / "trail.jsonl")
    AuditTrail(path).append(_event(input={"a": 1}))
    trail2 = AuditTrail(path)
    assert len(trail2) == 1
    assert trail2.verify().ok
    record = trail2.append(_event(input={"a": 2}))
    assert record["seq"] == 1


def test_genesis_record_links_to_genesis_hash(trail):
    record = trail.append(_event(input={"a": 1}))
    assert record["prev_hash"] == "0" * 64
    recomputed = entry_hash(record["seq"], record["prev_hash"], record["event"])
    assert recomputed == record["entry_hash"]


def test_input_fingerprint_is_deterministic():
    e1 = _event(input={"b": 2, "a": 1})
    e2 = _event(input={"a": 1, "b": 2})
    assert e1.input_fingerprint == e2.input_fingerprint
