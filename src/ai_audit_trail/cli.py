"""Command-line interface for ai-audit-trail."""

from __future__ import annotations

import argparse
import json
import sys

from ai_audit_trail.models import DecisionEvent, OverrideEvent
from ai_audit_trail.store import AuditTrail

DEFAULT_PATH = "audit-trail.jsonl"


def _trail(args: argparse.Namespace) -> AuditTrail:
    return AuditTrail(args.log)


def _json_or_text(value: str):
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def cmd_log(args: argparse.Namespace) -> int:
    event = DecisionEvent(
        model_id=args.model,
        decision=args.decision,
        input=_json_or_text(args.input) if args.input else None,
        output=_json_or_text(args.output) if args.output else None,
        actor=args.actor,
        policy_verdict=args.policy_verdict,
        metadata=json.loads(args.metadata) if args.metadata else {},
    )
    record = _trail(args).append(
        event,
        redact_fields=args.redact_field or None,
        redact_auto=args.redact_auto,
    )
    print(f"logged seq={record['seq']} hash={record['entry_hash'][:16]}...")
    return 0


def cmd_override(args: argparse.Namespace) -> int:
    event = OverrideEvent(
        model_id=args.model,
        decision=args.decision,
        overrides_seq=args.seq,
        reviewer=args.reviewer,
        rationale=args.rationale,
        input=_json_or_text(args.input) if args.input else None,
        output=_json_or_text(args.output) if args.output else None,
    )
    record = _trail(args).append(event)
    print(f"logged override seq={record['seq']} of seq={args.seq}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    result = _trail(args).verify()
    if result.ok:
        print(f"OK: {result.records_checked} record(s), chain intact")
        return 0
    print(f"FAILED: {len(result.errors)} problem(s) in {result.records_checked} record(s):")
    for error in result.errors:
        print(f"  - {error}")
    return 1


def cmd_query(args: argparse.Namespace) -> int:
    records = _trail(args).query(
        model_id=args.model,
        decision=args.decision,
        actor=args.actor,
        since=args.since,
        until=args.until,
        limit=args.limit,
    )
    for record in records:
        event = record["event"]
        print(
            f"seq={record['seq']} ts={event.get('timestamp')} "
            f"model={event.get('model_id')} decision={event.get('decision')} "
            f"actor={event.get('actor')} hash={record['entry_hash'][:12]}..."
        )
    if args.verbose:
        print(json.dumps(records, indent=2))
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    count = _trail(args).export_json(
        args.output,
        redact_fields=args.redact_field or None,
        redact_auto=args.redact_auto,
    )
    print(f"exported {count} record(s) to {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit-trail",
        description="Tamper-evident audit trail for AI decisions.",
    )
    parser.add_argument("--log", default=DEFAULT_PATH, help="path to the JSONL log file")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("log", help="log one AI decision event")
    p.add_argument("--model", required=True, help="model id, e.g. fraud-detector-v3")
    p.add_argument("--decision", required=True, help="the decision, e.g. approve/deny")
    p.add_argument("--input", help="input payload (JSON string or plain text)")
    p.add_argument("--output", help="output payload (JSON string or plain text)")
    p.add_argument("--actor", default="system", help="who/what made the decision")
    p.add_argument("--policy-verdict", help="policy engine verdict, e.g. allow/deny/escalate")
    p.add_argument("--metadata", help="extra JSON object, e.g. '{\"region\": \"us\"}'")
    p.add_argument("--redact-field", action="append", help="input field to redact (repeatable)")
    p.add_argument("--redact-auto", action="store_true", help="auto-mask PII patterns in input")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("override", help="log a human reviewer override of an earlier decision")
    p.add_argument("--model", required=True)
    p.add_argument("--seq", type=int, required=True, help="seq of the decision being overridden")
    p.add_argument("--decision", required=True, help="the corrected decision")
    p.add_argument("--reviewer", required=True)
    p.add_argument("--rationale", default="")
    p.add_argument("--input", help="input payload (JSON string or plain text)")
    p.add_argument("--output", help="output payload (JSON string or plain text)")
    p.set_defaults(func=cmd_override)

    p = sub.add_parser("verify", help="verify the hash chain")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("query", help="query events by model/decision/actor/time range")
    p.add_argument("--model")
    p.add_argument("--decision")
    p.add_argument("--actor")
    p.add_argument("--since", help="ISO timestamp, e.g. 2026-09-01T00:00:00+00:00")
    p.add_argument("--until", help="ISO timestamp")
    p.add_argument("--limit", type=int, help="show only the last N matches")
    p.add_argument("--verbose", action="store_true", help="print full records as JSON")
    p.set_defaults(func=cmd_query)

    p = sub.add_parser("export", help="export the trail as a JSON array")
    p.add_argument("--output", required=True, help="destination .json file")
    p.add_argument("--redact-field", action="append")
    p.add_argument("--redact-auto", action="store_true")
    p.set_defaults(func=cmd_export)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
