"""
Hellcat API Middleware Stack
============================
Bearer token auth · Token-bucket rate limiting · CORS · Request audit logging.
Drawn from HexStrike's security patterns, adapted for Hellcat's Flask API.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple

from flask import Flask, Request, Response, g, jsonify, request

logger = logging.getLogger("hellcat.middleware")

# ---------------------------------------------------------------------------
# Configuration (env-driven, secure defaults)
# ---------------------------------------------------------------------------

API_TOKEN: Optional[str] = os.environ.get("HELLCAT_API_TOKEN")
RATE_LIMIT_RPM: int = int(os.environ.get("HELLCAT_RATE_LIMIT_RPM", "120"))
RATE_LIMIT_BURST: int = int(os.environ.get("HELLCAT_RATE_LIMIT_BURST", "20"))
CORS_ORIGINS: str = os.environ.get("HELLCAT_CORS_ORIGINS", "http://localhost:*")
AUDIT_LOG_DIR: str = os.environ.get("HELLCAT_AUDIT_DIR", ".hellcat/audit")

# Paths that skip auth entirely
_PUBLIC_PATHS = frozenset({"/health", "/mcp/health", "/api/v1/version"})


# ═══════════════════════════════════════════════════════════════════════════
# 1. Bearer Token Authentication
# ═══════════════════════════════════════════════════════════════════════════

def _verify_token(req: Request) -> Tuple[bool, str]:
    """Validate Authorization: Bearer <token>. Returns (ok, reason)."""
    if not API_TOKEN:
        return True, "auth_disabled"        # no token configured → open
    if req.path in _PUBLIC_PATHS:
        return True, "public_path"

    header = req.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return False, "missing_bearer"

    provided = header[7:]
    if not hmac.compare_digest(provided, API_TOKEN):
        return False, "invalid_token"
    return True, "ok"


# ═══════════════════════════════════════════════════════════════════════════
# 2. Token-Bucket Rate Limiter
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class _Bucket:
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.monotonic)


class TokenBucketLimiter:
    """Per-IP token-bucket rate limiter with configurable RPM and burst."""

    def __init__(self, rpm: int = 120, burst: int = 20) -> None:
        self._rate = rpm / 60.0          # tokens per second
        self._burst = float(burst)
        self._buckets: Dict[str, _Bucket] = defaultdict(
            lambda: _Bucket(tokens=float(burst), last_refill=time.monotonic())
        )

    def allow(self, key: str) -> bool:
        b = self._buckets[key]
        now = time.monotonic()
        elapsed = now - b.last_refill
        b.tokens = min(self._burst, b.tokens + elapsed * self._rate)
        b.last_refill = now
        if b.tokens >= 1.0:
            b.tokens -= 1.0
            return True
        return False

    def cleanup(self, max_age: float = 3600.0) -> int:
        """Remove stale buckets. Call periodically."""
        now = time.monotonic()
        stale = [k for k, v in self._buckets.items() if now - v.last_refill > max_age]
        for k in stale:
            del self._buckets[k]
        return len(stale)


_limiter = TokenBucketLimiter(rpm=RATE_LIMIT_RPM, burst=RATE_LIMIT_BURST)


# ═══════════════════════════════════════════════════════════════════════════
# 3. CORS
# ═══════════════════════════════════════════════════════════════════════════

def _apply_cors(resp: Response) -> Response:
    origin = request.headers.get("Origin", "")
    allowed = _match_cors_origin(origin)
    if allowed:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        resp.headers["Access-Control-Max-Age"] = "3600"
    return resp


def _match_cors_origin(origin: str) -> bool:
    if not origin:
        return False
    for pattern in CORS_ORIGINS.split(","):
        pattern = pattern.strip()
        if pattern == "*":
            return True
        if "*" in pattern:
            prefix = pattern.split("*")[0]
            if origin.startswith(prefix):
                return True
        elif origin == pattern:
            return True
    return False


# ═══════════════════════════════════════════════════════════════════════════
# 4. Request Audit Logger
# ═══════════════════════════════════════════════════════════════════════════

class AuditLogger:
    """Append-only JSONL audit log for API requests."""

    def __init__(self, log_dir: str = AUDIT_LOG_DIR) -> None:
        self._dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

    def _path(self) -> str:
        date_str = time.strftime("%Y-%m-%d")
        return os.path.join(self._dir, f"audit-{date_str}.jsonl")

    def log(self, entry: Dict[str, Any]) -> None:
        try:
            line = json.dumps(entry, default=str, ensure_ascii=False)
            with open(self._path(), "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as exc:
            logger.warning("Audit write failed: %s", exc)

    def query(self, date: Optional[str] = None, path_contains: str = "",
              limit: int = 100) -> List[Dict[str, Any]]:
        """Read audit entries. date format: YYYY-MM-DD."""
        target = date or time.strftime("%Y-%m-%d")
        filepath = os.path.join(self._dir, f"audit-{target}.jsonl")
        if not os.path.exists(filepath):
            return []
        results: List[Dict[str, Any]] = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if path_contains and path_contains not in entry.get("path", ""):
                    continue
                results.append(entry)
                if len(results) >= limit:
                    break
        return results


_audit = AuditLogger()


# ═══════════════════════════════════════════════════════════════════════════
# 5. Middleware Registration (call once on app)
# ═══════════════════════════════════════════════════════════════════════════

def register_middleware(app: Flask) -> None:
    """Attach all middleware to a Flask app instance."""

    @app.before_request
    def _mw_auth_and_rate_limit():
        # --- OPTIONS preflight → skip auth ---
        if request.method == "OPTIONS":
            return

        # --- Auth ---
        ok, reason = _verify_token(request)
        if not ok:
            logger.warning("Auth rejected [%s]: %s %s", reason, request.method, request.path)
            return jsonify({"error": "unauthorized", "detail": reason}), 401

        # --- Rate limit ---
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
        if not _limiter.allow(client_ip):
            logger.warning("Rate-limited: %s %s %s", client_ip, request.method, request.path)
            return jsonify({"error": "rate_limit_exceeded"}), 429

        # --- Stash for audit ---
        g.request_start = time.time()
        g.client_ip = client_ip

    @app.after_request
    def _mw_cors_and_audit(resp: Response) -> Response:
        # --- CORS ---
        resp = _apply_cors(resp)

        # --- Security headers ---
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Request-Id"] = hashlib.sha256(
            f"{time.time()}{request.path}".encode()
        ).hexdigest()[:12]

        # --- Audit log ---
        duration = time.time() - getattr(g, "request_start", time.time())
        _audit.log({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ip": getattr(g, "client_ip", "unknown"),
            "method": request.method,
            "path": request.path,
            "status": resp.status_code,
            "duration_ms": round(duration * 1000, 1),
            "user_agent": request.headers.get("User-Agent", "")[:200],
        })
        return resp

    # --- Handle OPTIONS preflight for CORS ---
    @app.route("/<path:path>", methods=["OPTIONS"])
    @app.route("/", methods=["OPTIONS"])
    def _cors_preflight(path: str = ""):
        resp = app.make_response("")
        return _apply_cors(resp)

    logger.info(
        "Middleware registered — auth=%s rate_limit=%d/min cors=%s audit=%s",
        "enabled" if API_TOKEN else "disabled",
        RATE_LIMIT_RPM,
        CORS_ORIGINS,
        AUDIT_LOG_DIR,
    )


# Public API
__all__ = [
    "register_middleware",
    "TokenBucketLimiter",
    "AuditLogger",
    "API_TOKEN",
    "RATE_LIMIT_RPM",
]
