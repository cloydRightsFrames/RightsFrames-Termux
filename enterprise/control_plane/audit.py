from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "rf.audit.v1"
ZERO = "0" * 64

def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        last = None
        with self.path.open("rb") as fh:
            for raw in fh:
                if raw.strip():
                    last = json.loads(raw)
        return last

    def append(self, action: str, actor: str, outcome: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        if not action or not actor or outcome not in {"allow", "deny", "observe"}:
            raise ValueError("invalid audit event")
        previous = self._last()
        event = {
            "schema": SCHEMA,
            "seq": int(previous["seq"]) + 1 if previous else 1,
            "ts": _now(),
            "action": action,
            "actor": actor,
            "outcome": outcome,
            "details": details or {},
            "prev_hash": previous["hash"] if previous else ZERO,
        }
        event["hash"] = _hash(_canonical(event))
        encoded = _canonical(event) + b"\\n"
        fd, tmp = tempfile.mkstemp(prefix=".audit.", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "wb") as fh:
                if self.path.exists():
                    fh.write(self.path.read_bytes())
                fh.write(encoded)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return event

    def verify(self) -> tuple[bool, str]:
        if not self.path.exists():
            return True, "empty"
        expected_seq, previous = 1, ZERO
        try:
            with self.path.open("rb") as fh:
                for raw in fh:
                    if not raw.strip():
                        continue
                    event = json.loads(raw)
                    supplied = event.pop("hash")
                    if event.get("seq") != expected_seq:
                        return False, f"sequence mismatch at {expected_seq}"
                    if event.get("prev_hash") != previous:
                        return False, f"previous hash mismatch at {expected_seq}"
                    if _hash(_canonical(event)) != supplied:
                        return False, f"hash mismatch at {expected_seq}"
                    previous = supplied
                    expected_seq += 1
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            return False, f"invalid audit log: {exc}"
        return True, f"verified {expected_seq - 1} events"
