from __future__ import annotations
import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from core.rf_filelock import exclusive_file_lock

SCHEMA = "rf.audit.v1"
ZERO = "0" * 64

def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class _BrokenChain(ValueError):
    pass


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        last = None
        previous = ZERO
        seq = 1
        with self.path.open("rb") as fh:
            for raw in fh:
                if not raw.strip():
                    continue
                event = json.loads(raw)
                if not isinstance(event, dict) or not isinstance(event.get("hash"), str):
                    raise _BrokenChain(f"invalid audit event at {seq}")
                supplied = event.pop("hash")
                if type(event.get("seq")) is not int or event["seq"] != seq:
                    raise _BrokenChain(f"sequence mismatch at {seq}")
                if event.get("prev_hash") != previous:
                    raise _BrokenChain(f"previous hash mismatch at {seq}")
                if _hash(_canonical(event)) != supplied:
                    raise _BrokenChain(f"hash mismatch at {seq}")
                event["hash"] = previous = supplied
                last = event
                seq += 1
        return last

    def append(self, action: str, actor: str, outcome: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        if not action or not actor or outcome not in {"allow", "deny", "observe"}:
            raise ValueError("invalid audit event")

        with exclusive_file_lock(self.path.with_name(self.path.name + ".lock")):
            return self._append_locked(action, actor, outcome, details)

    def _append_locked(self, action: str, actor: str, outcome: str,
                       details: dict[str, Any] | None) -> dict[str, Any]:
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
        encoded = _canonical(event) + b"\n"

        fd, tmp = tempfile.mkstemp(prefix=".audit.", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "wb") as fh:
                if self.path.exists():
                    with self.path.open("rb") as source:
                        shutil.copyfileobj(source, fh)
                        if source.tell():
                            source.seek(-1, os.SEEK_END)
                            if source.read(1) != b"\n":
                                fh.write(b"\n")
                fh.write(encoded)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
            if os.name == "posix":
                directory = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

        return event

    def verify(self) -> tuple[bool, str]:
        if not self.path.exists():
            return True, "empty"

        try:
            last = self._last()
        except _BrokenChain as exc:
            return False, str(exc)
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            return False, f"invalid audit log: {exc}"

        count = last["seq"] if last else 0
        return True, f"verified {count} events"
