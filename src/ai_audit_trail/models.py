"""Data model for audit-trail events."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(obj: Any) -> str:
    """Deterministic JSON for hashing and fingerprinting."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def fingerprint(payload: Any) -> str:
    """SHA-256 fingerprint of a canonical payload."""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass
class DecisionEvent:
    """One AI decision recorded in the audit trail."""

    model_id: str
    decision: str
    input: Any = None
    output: Any = None
    actor: str = "system"
    policy_verdict: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utcnow_iso)
    input_fingerprint: Optional[str] = None
    redacted: bool = False
    redacted_fields: list = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.input_fingerprint is None and self.input is not None:
            self.input_fingerprint = fingerprint(self.input)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionEvent":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class OverrideEvent(DecisionEvent):
    """A human reviewer's override of a previously logged decision."""

    overrides_seq: Optional[int] = None
    reviewer: str = ""
    rationale: str = ""

    def __post_init__(self) -> None:
        if self.overrides_seq is None:
            raise ValueError("overrides_seq is required for an override event")
        self.actor = self.reviewer or self.actor
        self.decision = f"override:{self.decision}"
        super().__post_init__()
