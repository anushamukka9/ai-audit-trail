"""Append-only JSONL audit-trail store with hash-chained integrity."""

from __future__ import annotations

import contextlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Sequence

from ai_audit_trail import hashing
from ai_audit_trail.models import DecisionEvent, canonical_json
from ai_audit_trail.redaction import redact_input


class VerificationResult:
    def __init__(self, ok: bool, records_checked: int, errors: List[str]) -> None:
        self.ok = ok
        self.records_checked = records_checked
        self.errors = errors

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"VerificationResult(ok={self.ok}, "
            f"records_checked={self.records_checked}, errors={self.errors})"
        )


class AuditTrail:
    """An append-only, hash-chained audit log backed by a JSONL file.

    Safe for concurrent use from threads and multiple processes: appends are
    serialised with an in-process lock plus an OS-level file lock.

    ``checkpoint`` links a fresh log to an archived one: pass the checkpoint
    dict written by :meth:`rotate` and the first record of the new file
    chains to the archived log's last ``entry_hash`` (with ``seq``
    continuing), so verification spans the rotation boundary.
    """

    def __init__(self, path: str, checkpoint: Dict[str, Any] | None = None) -> None:
        self.path = path
        self._checkpoint = dict(checkpoint) if checkpoint else None
        self._lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)

    @property
    def checkpoint_path(self) -> str:
        return self.path + ".checkpoint.json"

    # ------------------------------------------------------------------
    # low-level record IO
    # ------------------------------------------------------------------
    def _read_records(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        records = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"corrupt record at line {lineno}: {exc}") from exc
                records.append(record)
        return records

    @staticmethod
    def _file_lock(fh):  # pragma: no cover - platform detail
        try:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            return contextlib.nullcontext()
        except Exception:
            return contextlib.nullcontext()

    # ------------------------------------------------------------------
    # append
    # ------------------------------------------------------------------
    def append(
        self,
        event: DecisionEvent | Dict[str, Any],
        redact_fields: Sequence[str] | None = None,
        redact_auto: bool = False,
    ) -> Dict[str, Any]:
        """Append an event; returns the stored record (with seq and hashes).

        If ``redact_fields``/``redact_auto`` are given, the input payload is
        redacted *before* the record hash is computed, so the fingerprint of
        the original input is still provable.
        """
        if isinstance(event, DecisionEvent):
            event_dict = event.to_dict()
        else:
            event_dict = dict(event)
            if "timestamp" not in event_dict:
                event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
        if redact_fields or redact_auto:
            event_dict = redact_input(event_dict, redact_fields, redact_auto)
            # redaction happens before fingerprinting on the raw input,
            # so fingerprint the raw payload explicitly
            if isinstance(event, DecisionEvent) and event.input is not None:
                event_dict["input_fingerprint"] = event.input_fingerprint

        with self._lock:
            records = self._read_records()
            if records:
                last = records[-1]
                prev_hash = last["entry_hash"]
                seq = last["seq"] + 1
            elif self._checkpoint:
                # Fresh file continuing an archived log: chain to the
                # checkpoint and continue the sequence numbering.
                prev_hash = self._checkpoint["entry_hash"]
                seq = self._checkpoint["last_seq"] + 1
            else:
                prev_hash = hashing.GENESIS_PREV_HASH
                seq = 0
            record = {
                "seq": seq,
                "prev_hash": prev_hash,
                "event": event_dict,
                "entry_hash": hashing.entry_hash(seq, prev_hash, event_dict),
            }
            with open(self.path, "a", encoding="utf-8") as fh:
                with self._file_lock(fh):
                    fh.write(canonical_json(record) + "\n")
        return record

    # ------------------------------------------------------------------
    # read / query
    # ------------------------------------------------------------------
    def __len__(self) -> int:
        return len(self._read_records())

    def iter_events(self) -> Iterator[Dict[str, Any]]:
        for record in self._read_records():
            yield record

    def get(self, seq: int) -> Optional[Dict[str, Any]]:
        for record in self._read_records():
            if record.get("seq") == seq:
                return record
        return None

    @staticmethod
    def _parse_ts(value: str) -> Optional[datetime]:
        try:
            dt = datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def query(
        self,
        *,
        model_id: Optional[str] = None,
        decision: Optional[str] = None,
        actor: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Filter records by model, decision, actor and/or time range."""
        since_dt = self._parse_ts(since) if since else None
        until_dt = self._parse_ts(until) if until else None
        matches = []
        for record in self._read_records():
            event = record.get("event", {})
            if model_id and event.get("model_id") != model_id:
                continue
            if decision and event.get("decision") != decision:
                continue
            if actor and event.get("actor") != actor:
                continue
            ts = self._parse_ts(str(event.get("timestamp", "")))
            if since_dt and (ts is None or ts < since_dt):
                continue
            if until_dt and (ts is None or ts > until_dt):
                continue
            matches.append(record)
        if limit is not None:
            matches = matches[-limit:]
        return matches

    # ------------------------------------------------------------------
    # verification
    # ------------------------------------------------------------------
    def verify(self) -> VerificationResult:
        """Recompute the full hash chain; report any tampering.

        When this trail was opened with a ``checkpoint``, the first record
        is expected to chain to the checkpoint's ``entry_hash`` and the
        sequence is expected to continue from the checkpoint's ``last_seq``.
        """
        errors: List[str] = []
        records = self._read_records()
        if self._checkpoint:
            expected_prev_hash = self._checkpoint["entry_hash"]
            expected_first_seq = self._checkpoint["last_seq"] + 1
        else:
            expected_prev_hash = hashing.GENESIS_PREV_HASH
            expected_first_seq = 0
        prev_hash = expected_prev_hash
        for index, record in enumerate(records):
            expected_seq = expected_first_seq + index
            if not hashing.is_well_formed_record(record):
                errors.append(f"record at index {index}: malformed")
                continue
            if record["seq"] != expected_seq:
                errors.append(
                    f"record at index {index}: seq is {record['seq']}, "
                    f"expected {expected_seq}"
                )
            if record["prev_hash"] != prev_hash:
                errors.append(f"record seq {record['seq']}: prev_hash mismatch (link broken)")
            expected = hashing.entry_hash(record["seq"], record["prev_hash"], record["event"])
            if record["entry_hash"] != expected:
                errors.append(f"record seq {record['seq']}: entry_hash mismatch (content altered)")
            prev_hash = record.get("entry_hash", prev_hash)
        return VerificationResult(ok=not errors, records_checked=len(records), errors=errors)

    # ------------------------------------------------------------------
    # checkpoints and rotation
    # ------------------------------------------------------------------
    def checkpoint(self) -> Dict[str, Any] | None:
        """Describe the current tip of the log.

        Returns a dict with ``last_seq``, ``entry_hash``, ``records``,
        ``genesis_prev_hash`` (what this file chains from) and
        ``checkpointed_at``; None for an empty log. The dict is what
        :meth:`rotate` persists and what a fresh :class:`AuditTrail`
        accepts as its ``checkpoint`` argument to continue the chain.
        """
        records = self._read_records()
        if not records:
            return None
        last = records[-1]
        return {
            "last_seq": last["seq"],
            "entry_hash": last["entry_hash"],
            "records": len(records),
            "genesis_prev_hash": (
                self._checkpoint["entry_hash"]
                if self._checkpoint
                else hashing.GENESIS_PREV_HASH
            ),
            "checkpointed_at": datetime.now(timezone.utc).isoformat(),
        }

    def rotate(
        self,
        max_records: int = 10000,
        archive_dir: str | None = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        """Archive the current log and start a fresh file that continues the chain.

        The live file is renamed to
        ``<name>.<UTC timestamp>.archived.jsonl`` (in ``archive_dir``, which
        defaults to the log's directory) and the checkpoint is written to
        ``<log path>.checkpoint.json``. The next :class:`AuditTrail` opened
        on this path with that checkpoint chains to the archived tip, so no
        link is lost across the rotation. Returns the checkpoint dict.

        Raises :class:`ValueError` when the log holds fewer than
        ``max_records`` records (pass ``force=True`` to rotate anyway) or
        when the log is empty.
        """
        records = self._read_records()
        if not records:
            raise ValueError("cannot rotate an empty log")
        if not force and len(records) < max_records:
            raise ValueError(
                f"log has {len(records)} record(s), below max_records={max_records}; "
                "pass force=True to rotate anyway"
            )
        cp = self.checkpoint()
        assert cp is not None  # guarded by the empty-log check above
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        directory = archive_dir or os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        archive_path = os.path.join(
            directory, f"{os.path.basename(self.path)}.{stamp}.archived.jsonl"
        )
        os.replace(self.path, archive_path)
        cp["archived_log"] = archive_path
        with open(self.checkpoint_path, "w", encoding="utf-8") as fh:
            json.dump(cp, fh, indent=2)
        return cp

    @classmethod
    def load_checkpoint(cls, path: str) -> Dict[str, Any]:
        """Read the checkpoint file written by :meth:`rotate` for ``path``."""
        with open(path + ".checkpoint.json", encoding="utf-8") as fh:
            return json.load(fh)

    # ------------------------------------------------------------------
    # export
    # ------------------------------------------------------------------
    def export_json(self, dest: str, redact_fields: Sequence[str] | None = None,
                    redact_auto: bool = False) -> int:
        """Export all records as a JSON array. Optional retroactive redaction."""
        records = []
        for record in self._read_records():
            if redact_fields or redact_auto:
                record = dict(record)
                record["event"] = redact_input(record["event"], redact_fields, redact_auto)
            records.append(record)
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2, sort_keys=True)
        return len(records)
