"""
Hellcat Error Recovery System
==============================
Three-tier recovery: retry with exponential backoff → fallback tool → human escalation.
Inspired by HexStrike's failure_recovery_system.py — hardened for Hellcat's red-team context.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger("hellcat.recovery")


class RecoveryAction(Enum):
    RETRY = "retry"
    FALLBACK = "fallback"
    ESCALATE = "escalate"
    ABORT = "abort"


@dataclass
class RecoveryEvent:
    """Audit record for a recovery attempt."""
    tool: str
    target: str
    error: str
    action: str
    attempt: int
    resolved: bool
    duration_ms: float = 0.0
    fallback_tool: str = ""
    timestamp: float = field(default_factory=time.time)


# ═══════════════════════════════════════════════════════════════════════════
# Fallback registry: tool → ordered list of alternatives
# ═══════════════════════════════════════════════════════════════════════════

TOOL_FALLBACKS: Dict[str, List[str]] = {
    # network recon
    "nmap": ["rustscan", "masscan"],
    "rustscan": ["nmap", "masscan"],
    "masscan": ["nmap", "rustscan"],
    # subdomain enum
    "subfinder": ["amass", "assetfinder"],
    "amass": ["subfinder", "assetfinder"],
    # web scanning
    "nuclei": ["nikto", "wapiti"],
    "nikto": ["nuclei", "wapiti"],
    "ffuf": ["feroxbuster", "gobuster", "dirsearch"],
    "feroxbuster": ["ffuf", "gobuster"],
    "gobuster": ["ffuf", "feroxbuster"],
    # injection
    "sqlmap": ["ghauri", "commix"],
    "xsstrike": ["dalfox"],
    "sstimap": ["tplmap"],
    # brute force
    "hydra": ["medusa", "patator"],
    "medusa": ["hydra", "patator"],
    "john": ["hashcat"],
    "hashcat": ["john"],
    # lateral movement
    "netexec": ["crackmapexec", "impacket"],
    # cloud
    "prowler": ["scout-suite"],
    "scout-suite": ["prowler"],
    # binary
    "ghidra": ["radare2", "rizin"],
    "radare2": ["ghidra", "rizin"],
}


# ═══════════════════════════════════════════════════════════════════════════
# Error classifiers
# ═══════════════════════════════════════════════════════════════════════════

_TRANSIENT_PATTERNS = frozenset({
    "connection refused", "connection reset", "timeout", "timed out",
    "temporarily unavailable", "too many open files", "broken pipe",
    "network unreachable", "dns resolution failed", "429",
})

_FATAL_PATTERNS = frozenset({
    "command not found", "no such file", "permission denied",
    "not installed", "segmentation fault", "killed",
})


def classify_error(error: str) -> RecoveryAction:
    """Determine recovery strategy from error text."""
    err_lower = error.lower()
    if any(p in err_lower for p in _FATAL_PATTERNS):
        return RecoveryAction.FALLBACK
    if any(p in err_lower for p in _TRANSIENT_PATTERNS):
        return RecoveryAction.RETRY
    return RecoveryAction.RETRY    # default: try again


# ═══════════════════════════════════════════════════════════════════════════
# Recovery executor
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class RecoveryPolicy:
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    backoff_factor: float = 2.0
    try_fallbacks: bool = True
    escalation_callback: Optional[Callable[[str, str, str], None]] = None


class RecoveryExecutor:
    """Execute a tool command with automatic 3-tier recovery."""

    def __init__(self, policy: Optional[RecoveryPolicy] = None) -> None:
        self.policy = policy or RecoveryPolicy()
        self.events: List[RecoveryEvent] = []

    async def execute_with_recovery(
        self,
        tool: str,
        target: str,
        run_fn: Callable[..., Coroutine[Any, Any, Dict[str, Any]]],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Try to execute `run_fn(tool, target, **kwargs)`.
        On failure: retry → fallback → escalate.
        Returns the result dict or an error dict.
        """
        # --- Tier 1: Retry with backoff ---
        last_error = ""
        for attempt in range(1, self.policy.max_retries + 1):
            t0 = time.time()
            try:
                result = await run_fn(tool, target, **kwargs)
                self._record(tool, target, "", RecoveryAction.RETRY, attempt, True, time.time() - t0)
                return result
            except Exception as exc:
                last_error = str(exc)
                action = classify_error(last_error)
                dur = (time.time() - t0) * 1000
                self._record(tool, target, last_error, action, attempt, False, dur)

                if action == RecoveryAction.FALLBACK:
                    break    # skip remaining retries, go to tier 2

                delay = min(
                    self.policy.base_delay * (self.policy.backoff_factor ** (attempt - 1)),
                    self.policy.max_delay,
                )
                logger.warning(
                    "[Tier1] %s failed (attempt %d/%d): %s — retry in %.1fs",
                    tool, attempt, self.policy.max_retries, last_error, delay,
                )
                await asyncio.sleep(delay)

        # --- Tier 2: Fallback tools ---
        if self.policy.try_fallbacks:
            fallbacks = TOOL_FALLBACKS.get(tool, [])
            for fb_tool in fallbacks:
                logger.info("[Tier2] Trying fallback: %s → %s", tool, fb_tool)
                t0 = time.time()
                try:
                    result = await run_fn(fb_tool, target, **kwargs)
                    self._record(tool, target, last_error, RecoveryAction.FALLBACK,
                                 0, True, (time.time() - t0) * 1000, fb_tool)
                    result["_recovery"] = {"original_tool": tool, "fallback_tool": fb_tool}
                    return result
                except Exception as fb_exc:
                    dur = (time.time() - t0) * 1000
                    self._record(tool, target, str(fb_exc), RecoveryAction.FALLBACK,
                                 0, False, dur, fb_tool)
                    logger.warning("[Tier2] Fallback %s also failed: %s", fb_tool, fb_exc)

        # --- Tier 3: Escalate ---
        logger.error("[Tier3] All recovery exhausted for %s on %s — escalating", tool, target)
        self._record(tool, target, last_error, RecoveryAction.ESCALATE, 0, False)
        if self.policy.escalation_callback:
            self.policy.escalation_callback(tool, target, last_error)

        return {
            "success": False,
            "error": last_error,
            "recovery": "escalated",
            "tool": tool,
            "target": target,
            "attempts": self.policy.max_retries,
            "fallbacks_tried": TOOL_FALLBACKS.get(tool, []),
        }

    def _record(self, tool: str, target: str, error: str, action: RecoveryAction,
                attempt: int, resolved: bool, duration_ms: float = 0.0,
                fallback_tool: str = "") -> None:
        self.events.append(RecoveryEvent(
            tool=tool, target=target, error=error[:500],
            action=action.value, attempt=attempt, resolved=resolved,
            duration_ms=duration_ms, fallback_tool=fallback_tool,
        ))

    def stats(self) -> Dict[str, Any]:
        total = len(self.events)
        resolved = sum(1 for e in self.events if e.resolved)
        by_action: Dict[str, int] = {}
        for e in self.events:
            by_action[e.action] = by_action.get(e.action, 0) + 1
        return {
            "total_events": total,
            "resolved": resolved,
            "resolution_rate": round(resolved / max(total, 1), 3),
            "by_action": by_action,
        }
