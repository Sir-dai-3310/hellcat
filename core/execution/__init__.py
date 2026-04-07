"""
Hellcat Failure Recovery + WebSocket Push
==========================================
IntelligentErrorHandler: auto-retry, tool substitution, param adjustment.
WebSocket event broadcaster for real-time scan progress.
"""
from __future__ import annotations

import logging
import time
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("hellcat.recovery")


# ---------------------------------------------------------------------------
# Error Classification
# ---------------------------------------------------------------------------

class ErrorType(Enum):
    TIMEOUT = "timeout"
    PERMISSION = "permission_denied"
    NETWORK = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    TOOL_MISSING = "tool_not_found"
    INVALID_PARAMS = "invalid_parameters"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    AUTH_FAILED = "authentication_failed"
    TARGET_DOWN = "target_unreachable"
    PARSE_ERROR = "parsing_error"
    UNKNOWN = "unknown"


class RecoveryAction(Enum):
    RETRY = "retry_with_backoff"
    SWITCH_TOOL = "switch_to_alternative"
    ADJUST_PARAMS = "adjust_parameters"
    DEGRADE = "graceful_degradation"
    ABORT = "abort"


# ---------------------------------------------------------------------------
# Error Pattern Matching
# ---------------------------------------------------------------------------

ERROR_PATTERNS: Dict[str, ErrorType] = {
    "timed out": ErrorType.TIMEOUT,
    "timeout": ErrorType.TIMEOUT,
    "permission denied": ErrorType.PERMISSION,
    "connection refused": ErrorType.NETWORK,
    "name resolution": ErrorType.NETWORK,
    "rate limit": ErrorType.RATE_LIMITED,
    "429": ErrorType.RATE_LIMITED,
    "not found": ErrorType.TOOL_MISSING,
    "no such file": ErrorType.TOOL_MISSING,
    "authentication": ErrorType.AUTH_FAILED,
    "unauthorized": ErrorType.AUTH_FAILED,
    "memory": ErrorType.RESOURCE_EXHAUSTED,
}

TOOL_ALTERNATIVES: Dict[str, List[str]] = {
    "nmap": ["rustscan", "masscan"],
    "ffuf": ["feroxbuster", "gobuster"],
    "nuclei": ["nikto"],
    "sqlmap": ["sqlmap"],
    "amass": ["subfinder"],
    "subfinder": ["amass"],
    "hydra": ["netexec", "medusa"],
    "gobuster": ["feroxbuster", "ffuf"],
    "nikto": ["nuclei"],
    "john": ["hashcat"],
    "hashcat": ["john"],
    "ghidra": ["radare2"],
}

RECOVERY_STRATEGIES: Dict[ErrorType, List[RecoveryAction]] = {
    ErrorType.TIMEOUT: [RecoveryAction.RETRY, RecoveryAction.ADJUST_PARAMS],
    ErrorType.NETWORK: [RecoveryAction.RETRY, RecoveryAction.DEGRADE],
    ErrorType.RATE_LIMITED: [RecoveryAction.RETRY, RecoveryAction.ADJUST_PARAMS],
    ErrorType.TOOL_MISSING: [RecoveryAction.SWITCH_TOOL, RecoveryAction.DEGRADE],
    ErrorType.PERMISSION: [RecoveryAction.ADJUST_PARAMS, RecoveryAction.DEGRADE],
    ErrorType.AUTH_FAILED: [RecoveryAction.ADJUST_PARAMS, RecoveryAction.ABORT],
    ErrorType.RESOURCE_EXHAUSTED: [RecoveryAction.ADJUST_PARAMS, RecoveryAction.DEGRADE],
    ErrorType.TARGET_DOWN: [RecoveryAction.RETRY, RecoveryAction.ABORT],
    ErrorType.UNKNOWN: [RecoveryAction.RETRY, RecoveryAction.DEGRADE],
}


class IntelligentErrorHandler:
    """Classify errors and suggest recovery strategies."""

    @staticmethod
    def classify(error_msg: str) -> ErrorType:
        msg = error_msg.lower()
        for pattern, etype in ERROR_PATTERNS.items():
            if pattern in msg:
                return etype
        return ErrorType.UNKNOWN

    @staticmethod
    def get_recovery(error_type: ErrorType) -> List[RecoveryAction]:
        return RECOVERY_STRATEGIES.get(error_type, [RecoveryAction.RETRY])

    @staticmethod
    def get_alternative_tool(tool: str) -> Optional[str]:
        alts = TOOL_ALTERNATIVES.get(tool, [])
        import shutil
        for alt in alts:
            if shutil.which(alt):
                return alt
        return alts[0] if alts else None

    @staticmethod
    def handle(tool: str, error_msg: str) -> Dict[str, Any]:
        etype = IntelligentErrorHandler.classify(error_msg)
        actions = IntelligentErrorHandler.get_recovery(etype)
        alt = IntelligentErrorHandler.get_alternative_tool(tool)
        return {
            "error_type": etype.value,
            "recovery_actions": [a.value for a in actions],
            "alternative_tool": alt,
            "suggestion": f"Try {alt}" if alt and RecoveryAction.SWITCH_TOOL in actions
                          else f"Retry with backoff" if RecoveryAction.RETRY in actions
                          else "Abort and investigate",
        }


def execute_with_recovery(func: Callable, tool: str = "",
                          max_retries: int = 2, backoff: float = 2.0) -> Dict[str, Any]:
    """Execute func with automatic retry and error recovery."""
    last_error = ""
    for attempt in range(max_retries + 1):
        try:
            return func()
        except Exception as exc:
            last_error = str(exc)
            if attempt < max_retries:
                wait = backoff * (2 ** attempt)
                logger.warning("Attempt %d failed (%s), retrying in %.1fs: %s",
                               attempt + 1, tool, wait, exc)
                time.sleep(wait)
    recovery = IntelligentErrorHandler.handle(tool, last_error)
    return {"success": False, "error": last_error, "recovery": recovery}


# ---------------------------------------------------------------------------
# WebSocket Event Broadcaster
# ---------------------------------------------------------------------------

class EventBroadcaster:
    """Simple pub/sub for real-time WebSocket push."""

    def __init__(self) -> None:
        self._listeners: Dict[str, List[Callable]] = {}

    def on(self, event: str, callback: Callable) -> None:
        self._listeners.setdefault(event, []).append(callback)

    def emit(self, event: str, data: Any = None) -> None:
        for cb in self._listeners.get(event, []):
            try:
                cb(data)
            except Exception as exc:
                logger.debug("Event listener error (%s): %s", event, exc)

    def emit_scan_progress(self, tool: str, progress: float, target: str) -> None:
        self.emit("scan_progress", {"tool": tool, "progress": progress, "target": target})

    def emit_vuln_found(self, vuln_type: str, url: str, severity: str) -> None:
        self.emit("vuln_found", {"vuln_type": vuln_type, "url": url, "severity": severity})

    def emit_task_status(self, task_id: str, status: str) -> None:
        self.emit("task_status", {"task_id": task_id, "status": status})
