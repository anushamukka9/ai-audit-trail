"""Input redaction helpers.

Redaction keeps the log useful for audits while protecting sensitive data:
the raw input is replaced with a tombstone that preserves the
``input_fingerprint`` recorded at log time, so a reviewer holding the
original input can still prove it matches the audit record.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Sequence, Tuple

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)")
SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
CREDIT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")

TOKEN = "[REDACTED]"


def mask_text(text: str) -> Tuple[str, List[str]]:
    """Mask common PII patterns in free text. Returns (masked, hits)."""
    hits: List[str] = []
    for name, pattern in (
        ("email", EMAIL_RE),
        ("phone", PHONE_RE),
        ("ssn", SSN_RE),
        ("card", CREDIT_CARD_RE),
    ):
        text, n = pattern.subn(TOKEN, text)
        if n:
            hits.append(name)
    return text, hits


def _mask_value(value: Any, fields: Sequence[str], path: str, hits: List[str]) -> Any:
    if isinstance(value, dict):
        return {
            k: (TOKEN if k in fields else _mask_value(v, fields, f"{path}.{k}", hits))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_mask_value(v, fields, f"{path}[]", hits) for v in value]
    if isinstance(value, str):
        masked, found = mask_text(value)
        hits.extend(found)
        return masked
    return value


def redact_input(
    event_dict: Dict[str, Any], fields: Sequence[str] | None = None, auto: bool = False
) -> Dict[str, Any]:
    """Return a copy of ``event_dict`` with sensitive input removed.

    ``fields`` masks named keys (recursively); ``auto`` also masks common
    PII patterns in any string. The original ``input_fingerprint`` is kept so
    the redacted record remains verifiable against the raw input.
    """
    event = dict(event_dict)
    payload = event.get("input")
    if payload is None:
        return event
    hits: List[str] = []
    masked = _mask_value(payload, tuple(fields or ()), "input", hits)
    if auto and isinstance(payload, str):
        masked, found = mask_text(payload)
        hits.extend(found)
    event["input"] = {
        "redacted": True,
        "masked_value": masked,
        "fields": sorted(set(hits)),
    }
    event["redacted"] = True
    event["redacted_fields"] = sorted(set(list(event.get("redacted_fields", [])) + hits))
    return event
