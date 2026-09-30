"""Runnable quickstart: log, verify, query, export.

Run from the repo root:

    pip install -e .
    python examples/quickstart.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ai_audit_trail import AuditTrail, DecisionEvent  # noqa: E402


def main() -> None:
    # Work in a temp dir so repeated runs start from a clean log.
    with tempfile.TemporaryDirectory() as tmp:
        log_path = str(Path(tmp) / "audit-trail.jsonl")
        trail = AuditTrail(log_path)

        # Log two AI decisions
        trail.append(DecisionEvent(
            model_id="fraud-detector-v3",
            decision="deny",
            input={"txn_id": "txn-8842", "amount": 9400, "country": "NG"},
            output={"score": 0.93, "reason": "velocity_anomaly"},
            actor="inference-service",
            policy_verdict="escalate",
        ))

        trail.append(
            DecisionEvent(
                model_id="fraud-detector-v3",
                decision="deny",
                input={"txn_id": "txn-8843", "amount": 120, "country": "US"},
                output={"score": 0.12},
                actor="inference-service",
                policy_verdict="allow",
            ),
            redact_auto=True,  # masks emails/phones/SSNs if present in input
        )

        # Verify the chain
        result = trail.verify()
        print("chain intact:", result.ok, f"({result.records_checked} records)")

        # Query: all deny decisions from this model
        for record in trail.query(model_id="fraud-detector-v3", decision="deny"):
            event = record["event"]
            print(f"seq={record['seq']} decision={event['decision']} "
                  f"verdict={event['policy_verdict']}")

        # Export for an auditor
        export_path = str(Path(tmp) / "ai-audit-trail-export.json")
        trail.export_json(export_path)
        print(f"exported to {export_path}")


if __name__ == "__main__":
    main()
