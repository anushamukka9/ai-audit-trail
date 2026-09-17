"""Hash-chain construction and verification.

Each record links to the previous one:

    entry_hash = sha256(canonical_json({
        "seq": seq,
        "prev_hash": prev_hash,
        "event": event_dict,
    }))

The genesis record (seq 0) uses the constant GENESIS_PREV_HASH, so any
modification, insertion, deletion or reordering of records breaks the chain.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict

from ai_audit_trail.models import canonical_json

GENESIS_PREV_HASH = "0" * 64
HASH_ALGO = "sha256"


def entry_hash(seq: int, prev_hash: str, event: Dict[str, Any]) -> str:
    body = {"seq": seq, "prev_hash": prev_hash, "event": event}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def is_well_formed_record(record: Dict[str, Any]) -> bool:
    return (
        isinstance(record, dict)
        and isinstance(record.get("seq"), int)
        and isinstance(record.get("prev_hash"), str)
        and isinstance(record.get("entry_hash"), str)
        and isinstance(record.get("event"), dict)
    )
