"""ai-audit-trail: tamper-evident audit trail for AI decisions.

Append-only, hash-chained event log that records who/what/when for every
AI decision — model id, input fingerprint, output, policy verdict and any
reviewer overrides — so the record is verifiable after the fact.
"""

from ai_audit_trail.store import AuditTrail
from ai_audit_trail.models import DecisionEvent

__all__ = ["AuditTrail", "DecisionEvent"]
__version__ = "0.1.0"
