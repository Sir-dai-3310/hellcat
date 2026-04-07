"""
Hellcat Standard Response Format
==================================
Unified response builder for all API/MCP tool returns.
Eliminates inconsistency between 'success'/'status'/'error' keys.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


def ok(data: Any = None, **extra: Any) -> Dict[str, Any]:
    """Standard success response."""
    resp: Dict[str, Any] = {"success": True}
    if data is not None:
        if isinstance(data, dict):
            resp.update(data)
        else:
            resp["data"] = data
    resp.update(extra)
    return resp


def err(message: str, code: str = "error", **extra: Any) -> Dict[str, Any]:
    """Standard error response."""
    return {"success": False, "error": message, "error_code": code, **extra}


def paginated(items: List[Any], total: int = 0,
              offset: int = 0, limit: int = 50) -> Dict[str, Any]:
    """Standard paginated response."""
    return {
        "success": True,
        "items": items,
        "total": total or len(items),
        "offset": offset,
        "limit": limit,
        "has_more": (offset + limit) < (total or len(items)),
    }


def finding(vuln_type: str, url: str, severity: str = "medium",
            param: str = "", payload: str = "", evidence: str = "",
            confidence: float = 0.0, verified: bool = False,
            remediation: str = "", **extra: Any) -> Dict[str, Any]:
    """Standard vulnerability finding format."""
    return {
        "vuln_type": vuln_type,
        "url": url,
        "severity": severity,
        "param": param,
        "payload": payload,
        "evidence": evidence,
        "confidence": confidence,
        "verified": verified,
        "remediation": remediation,
        "timestamp": time.time(),
        **extra,
    }


def tool_result(tool: str, success: bool, stdout: str = "",
                stderr: str = "", duration: float = 0.0,
                return_code: int = 0, **extra: Any) -> Dict[str, Any]:
    """Standard external tool execution result."""
    return {
        "success": success,
        "tool": tool,
        "stdout": stdout,
        "stderr": stderr,
        "duration": round(duration, 2),
        "return_code": return_code,
        **extra,
    }
