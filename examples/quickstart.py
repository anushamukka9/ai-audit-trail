"""Smoke-free runnable quickstart: log, verify, query, export."""

from ai_audit_trail import AuditTrail, DecisionEvent

trail = AuditTrail("/tmp/ai-audit-trail-quickstart.jsonl")

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
trail.export_json("/tmp/ai-audit-trail-export.json")
print("exported to /tmp/ai-audit-trail-export.json")
