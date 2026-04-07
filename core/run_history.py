"""
Hellcat Run History Store
=========================
Persistent JSONL-based scan/tool execution history with search, filter, and export.
Inspired by HexStrike's run_history_store.py — adapted for Hellcat's architecture.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger("hellcat.history")

_DATA_DIR = os.environ.get("HELLCAT_DATA_DIR", ".hellcat")
_HISTORY_FILE = "run_history.jsonl"


class RunStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class RunRecord:
    """Single tool/scan execution record."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    tool: str = ""
    target: str = ""
    command: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    exit_code: int = -1
    stdout_summary: str = ""
    stderr_summary: str = ""
    findings_count: int = 0
    duration_ms: float = 0.0
    started_at: str = ""
    finished_at: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RunRecord:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class RunHistoryStore:
    """Append-only JSONL store with in-memory index for fast queries."""

    def __init__(self, data_dir: str = _DATA_DIR) -> None:
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / _HISTORY_FILE
        self._index: Dict[str, RunRecord] = {}
        self._load_index()

    # --- persistence ---

    def _load_index(self) -> None:
        if not self._path.exists():
            return
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = RunRecord.from_dict(json.loads(line))
                        self._index[rec.id] = rec
                    except (json.JSONDecodeError, TypeError):
                        continue
        except Exception as exc:
            logger.warning("History load error: %s", exc)

    def _append(self, record: RunRecord) -> None:
        try:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record.to_dict(), default=str, ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.warning("History write error: %s", exc)

    def _rewrite(self) -> None:
        """Rewrite entire file from index (after update)."""
        try:
            with open(self._path, "w", encoding="utf-8") as f:
                for rec in self._index.values():
                    f.write(json.dumps(rec.to_dict(), default=str, ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.warning("History rewrite error: %s", exc)

    # --- CRUD ---

    def start_run(self, tool: str, target: str = "", command: str = "",
                  parameters: Optional[Dict] = None, tags: Optional[List[str]] = None) -> RunRecord:
        rec = RunRecord(
            tool=tool, target=target, command=command,
            parameters=parameters or {},
            status=RunStatus.RUNNING.value,
            started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            tags=tags or [],
        )
        self._index[rec.id] = rec
        self._append(rec)
        logger.debug("Run started: %s [%s] target=%s", rec.id, tool, target)
        return rec

    def finish_run(self, run_id: str, *, status: str = "success", exit_code: int = 0,
                   stdout_summary: str = "", stderr_summary: str = "",
                   findings_count: int = 0, duration_ms: float = 0.0,
                   metadata: Optional[Dict] = None) -> Optional[RunRecord]:
        rec = self._index.get(run_id)
        if not rec:
            logger.warning("Run not found: %s", run_id)
            return None
        rec.status = status
        rec.exit_code = exit_code
        rec.stdout_summary = stdout_summary[:5000]
        rec.stderr_summary = stderr_summary[:2000]
        rec.findings_count = findings_count
        rec.duration_ms = duration_ms
        rec.finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if metadata:
            rec.metadata.update(metadata)
        self._rewrite()
        return rec

    def get(self, run_id: str) -> Optional[RunRecord]:
        return self._index.get(run_id)

    # --- query ---

    def query(self, *, tool: str = "", target: str = "", status: str = "",
              tag: str = "", limit: int = 50, offset: int = 0) -> List[RunRecord]:
        results: List[RunRecord] = []
        for rec in reversed(list(self._index.values())):
            if tool and tool.lower() not in rec.tool.lower():
                continue
            if target and target.lower() not in rec.target.lower():
                continue
            if status and rec.status != status:
                continue
            if tag and tag not in rec.tags:
                continue
            results.append(rec)
        return results[offset:offset + limit]

    def stats(self) -> Dict[str, Any]:
        total = len(self._index)
        by_status: Dict[str, int] = {}
        by_tool: Dict[str, int] = {}
        total_duration = 0.0
        for rec in self._index.values():
            by_status[rec.status] = by_status.get(rec.status, 0) + 1
            by_tool[rec.tool] = by_tool.get(rec.tool, 0) + 1
            total_duration += rec.duration_ms
        return {
            "total_runs": total,
            "by_status": by_status,
            "top_tools": dict(sorted(by_tool.items(), key=lambda x: -x[1])[:10]),
            "avg_duration_ms": round(total_duration / max(total, 1), 1),
        }

    def export_json(self) -> List[Dict[str, Any]]:
        return [rec.to_dict() for rec in self._index.values()]

    @property
    def count(self) -> int:
        return len(self._index)


# Singleton
_store: Optional[RunHistoryStore] = None


def get_history_store() -> RunHistoryStore:
    global _store
    if _store is None:
        _store = RunHistoryStore()
    return _store
