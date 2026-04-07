"""
Hellcat Performance Optimization Layer
=======================================
Dual-layer cache (LRU memory + disk), lazy import manager,
token-bucket rate limiter, circuit breaker.
Ported from HexStrike 6.2 performance_optimizer + advanced_cache.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, TypeVar

logger = logging.getLogger("hellcat.perf")
T = TypeVar("T")


# ---------------------------------------------------------------------------
# Dual-Layer Cache
# ---------------------------------------------------------------------------

class AdvancedCache:
    """LRU memory cache with TTL and optional disk persistence."""

    def __init__(self, max_size: int = 1000, default_ttl: int = 3600,
                 disk_path: Optional[str] = None) -> None:
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._disk_path = disk_path
        self._store: OrderedDict[str, Any] = OrderedDict()
        self._expiry: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Any:
        with self._lock:
            if key in self._store:
                if self._expiry.get(key, float("inf")) > time.time():
                    self._store.move_to_end(key)
                    self._hits += 1
                    return self._store[key]
                else:
                    self._remove(key)
            self._misses += 1
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = value
            self._expiry[key] = time.time() + (ttl or self._default_ttl)
            while len(self._store) > self._max_size:
                oldest = next(iter(self._store))
                self._remove(oldest)

    def delete(self, key: str) -> bool:
        with self._lock:
            return self._remove(key)

    def _remove(self, key: str) -> bool:
        if key in self._store:
            del self._store[key]
            self._expiry.pop(key, None)
            return True
        return False

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._expiry.clear()

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total else 0.0

    def stats(self) -> Dict[str, Any]:
        return {
            "size": len(self._store), "max_size": self._max_size,
            "hits": self._hits, "misses": self._misses,
            "hit_rate": round(self.hit_rate, 3),
        }

    @staticmethod
    def make_key(*parts: Any) -> str:
        raw = json.dumps(parts, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Lazy Import Manager
# ---------------------------------------------------------------------------

class LazyImportManager:
    """Defer heavy imports until first use."""

    HEAVY_MODULES = ["selenium", "playwright", "angr", "pwntools",
                     "mitmproxy", "volatility3", "ghidra"]

    def __init__(self) -> None:
        self._loaded: Dict[str, Any] = {}

    def get(self, module_name: str) -> Any:
        if module_name not in self._loaded:
            try:
                self._loaded[module_name] = importlib.import_module(module_name)
                logger.debug("Lazy-loaded: %s", module_name)
            except ImportError:
                self._loaded[module_name] = None
                logger.debug("Lazy-load unavailable: %s", module_name)
        return self._loaded[module_name]

    @property
    def loaded_modules(self) -> List[str]:
        return [k for k, v in self._loaded.items() if v is not None]


# ---------------------------------------------------------------------------
# Token Bucket Rate Limiter
# ---------------------------------------------------------------------------

class TokenBucketRateLimiter:
    """Rate limiter using token bucket algorithm."""

    def __init__(self, rate: float = 10.0, burst: int = 20) -> None:
        self._rate = rate
        self._burst = burst
        self._tokens = float(burst)
        self._last_refill = time.time()
        self._lock = threading.Lock()
        self._total_allowed = 0
        self._total_denied = 0

    def allow(self) -> bool:
        with self._lock:
            now = time.time()
            elapsed = now - self._last_refill
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            self._last_refill = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                self._total_allowed += 1
                return True
            self._total_denied += 1
            return False

    def stats(self) -> Dict[str, Any]:
        return {"rate": self._rate, "burst": self._burst,
                "tokens": round(self._tokens, 1),
                "allowed": self._total_allowed, "denied": self._total_denied}


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """Prevents cascading failures by tripping after N consecutive errors."""

    def __init__(self, failure_threshold: int = 5, reset_timeout: int = 60) -> None:
        self._threshold = failure_threshold
        self._reset_timeout = reset_timeout
        self._failures = 0
        self._last_failure: float = 0.0
        self._state = "closed"  # closed, open, half_open

    @property
    def state(self) -> str:
        if self._state == "open":
            if time.time() - self._last_failure > self._reset_timeout:
                self._state = "half_open"
        return self._state

    def call(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        if self.state == "open":
            raise RuntimeError(f"Circuit breaker is OPEN (failures={self._failures})")
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as exc:
            self._on_failure()
            raise

    def _on_success(self) -> None:
        self._failures = 0
        self._state = "closed"

    def _on_failure(self) -> None:
        self._failures += 1
        self._last_failure = time.time()
        if self._failures >= self._threshold:
            self._state = "open"

    def reset(self) -> None:
        self._failures = 0
        self._state = "closed"


# ---------------------------------------------------------------------------
# Performance Manager (unified)
# ---------------------------------------------------------------------------

class PerformanceManager:
    """Singleton performance optimization facade."""

    def __init__(self) -> None:
        self.cache = AdvancedCache(max_size=2000, default_ttl=1800)
        self.lazy = LazyImportManager()
        self.rate_limiter = TokenBucketRateLimiter(rate=50.0, burst=100)
        self.circuit_breaker = CircuitBreaker(failure_threshold=5, reset_timeout=60)

    def stats(self) -> Dict[str, Any]:
        return {
            "cache": self.cache.stats(),
            "rate_limiter": self.rate_limiter.stats(),
            "circuit_breaker": self.circuit_breaker.state,
            "lazy_loaded": self.lazy.loaded_modules,
        }
