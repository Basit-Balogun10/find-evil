from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Mapping


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class AuditLogger:
    log_path: Path = Path("logs/audit.jsonl")
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def record(
        self,
        *,
        node: str,
        event: str,
        state: Mapping[str, Any] | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "timestamp": _utc_timestamp(),
            "node": node,
            "event": event,
            "details": details or {},
        }

        if state is not None:
            entry["iteration_count"] = int(state.get("iteration_count", 0))
            entry["max_iterations"] = int(state.get("max_iterations", 0))

        with self._lock:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")

        return entry


AUDIT_LOGGER = AuditLogger()