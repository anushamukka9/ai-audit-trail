"""Tamper-detection demo: the hash chain catches every kind of meddling.

Builds a small audit trail, verifies it is clean, then applies three
attacks directly to the log file (payload modification, link breaking,
record deletion) and shows what `verify` reports for each. Finally it
restores the log from a backup copy and verifies the chain is intact
again.

Run from the repo root:

    pip install -e .
    python examples/tamper_demo.py
"""

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ai_audit_trail import AuditTrail, DecisionEvent  # noqa: E402


def rewrite(path: Path, transform):
    lines = path.read_text(encoding="utf-8").splitlines()
    transform(lines)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def show(title: str, trail: AuditTrail) -> None:
    result = trail.verify()
    print(f"{title}: chain intact = {result.ok}")
    for error in result.errors:
        print(f"    - {error}")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "trail.jsonl"
        trail = AuditTrail(str(path))

        for i in range(3):
            trail.append(DecisionEvent(
                model_id="fraud-detector-v3",
                decision="deny",
                input={"txn_id": f"txn-88{i}", "amount": 100 * (i + 1)},
                actor="inference-service",
            ))
        backup = Path(tmp) / "trail.jsonl.bak"
        shutil.copy(path, backup)

        show("clean log                      ", trail)

        # Attack 1: quietly edit a stored payload.
        def tamper_payload(lines):
            record = json.loads(lines[1])
            record["event"]["input"]["amount"] = 999999
            lines[1] = json.dumps(record)

        rewrite(path, tamper_payload)
        show("payload modified               ", trail)
        shutil.copy(backup, path)

        # Attack 2: re-point a link so the chain no longer connects.
        def tamper_link(lines):
            record = json.loads(lines[2])
            record["prev_hash"] = "0" * 64
            lines[2] = json.dumps(record)

        rewrite(path, tamper_link)
        show("link broken                    ", trail)
        shutil.copy(backup, path)

        # Attack 3: delete a record from the middle.
        rewrite(path, lambda lines: lines.pop(1))
        show("record deleted                 ", trail)

        # Recovery: restore from the backup copy.
        shutil.copy(backup, path)
        show("restored from backup           ", trail)


if __name__ == "__main__":
    main()
