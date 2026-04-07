"""
Hellcat Detector Framework
==========================
Abstract base detector, composite pattern, factory with decorator-based
registration, and preset scan profiles (OWASP Top-10, injection suite, etc.).
Ported from AutoRedTeam-Orchestrator core/detectors/.
"""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Type

from hellcat.core.models import DetectionResult, DetectorType, Severity

logger = logging.getLogger("hellcat.detectors")


# ---------------------------------------------------------------------------
# Base Detector
# ---------------------------------------------------------------------------

class BaseDetector(ABC):
    """Abstract base for all vulnerability detectors."""

    name: str = "base"
    description: str = ""
    vuln_type: str = ""
    severity: Severity = Severity.MEDIUM
    detector_type: DetectorType = DetectorType.MISC
    version: str = "1.0.0"

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config: Dict[str, Any] = config or {}
        self._start_time: float = 0.0

    @abstractmethod
    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        ...

    async def async_detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.detect(url, **kwargs))

    def get_payloads(self) -> List[str]:
        return []

    def _create_result(
        self,
        url: str,
        vulnerable: bool = True,
        param: str = "",
        payload: str = "",
        evidence: str = "",
        confidence: float = 0.0,
        verified: bool = False,
        remediation: str = "",
        references: Optional[List[str]] = None,
        request_info: Optional[dict] = None,
        response_info: Optional[dict] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> DetectionResult:
        return DetectionResult(
            url=url, vulnerable=vulnerable,
            vuln_type=self.vuln_type or self.name, severity=self.severity,
            param=param, payload=payload, evidence=evidence,
            confidence=confidence, verified=verified,
            remediation=remediation, references=references or [],
            request_info=request_info, response_info=response_info,
            extra=extra or {},
        )

    def _log_start(self, url: str) -> None:
        self._start_time = time.time()
        logger.info("[%s] scanning %s", self.name, url)

    def _log_end(self, url: str, results: List[DetectionResult]) -> None:
        elapsed = time.time() - self._start_time
        hits = sum(1 for r in results if r.vulnerable)
        logger.info("[%s] %s — %d findings in %.1fs", self.name, url, hits, elapsed)

    def verify(self, result: DetectionResult) -> bool:
        return result.vulnerable

    def __enter__(self) -> BaseDetector:
        return self

    def __exit__(self, *_: Any) -> bool:
        return False


# ---------------------------------------------------------------------------
# Composite Detector
# ---------------------------------------------------------------------------

class CompositeDetector(BaseDetector):
    name = "composite"
    description = "Multi-detector composite scanner"

    def __init__(self, detectors: Optional[List[BaseDetector]] = None,
                 config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._detectors: List[BaseDetector] = detectors or []

    def add_detector(self, detector: BaseDetector) -> None:
        self._detectors.append(detector)

    def remove_detector(self, name: str) -> bool:
        before = len(self._detectors)
        self._detectors = [d for d in self._detectors if d.name != name]
        return len(self._detectors) < before

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        for det in self._detectors:
            try:
                results.extend(det.detect(url, **kwargs))
            except Exception as exc:
                logger.warning("[composite] %s failed: %s", det.name, exc)
        return results

    async def async_detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        coros = [det.async_detect(url, **kwargs) for det in self._detectors]
        gathered = await asyncio.gather(*coros, return_exceptions=True)
        results: List[DetectionResult] = []
        for item in gathered:
            if isinstance(item, list):
                results.extend(item)
            elif isinstance(item, Exception):
                logger.warning("[composite] error: %s", item)
        return results


# ---------------------------------------------------------------------------
# Streaming Detector
# ---------------------------------------------------------------------------

class StreamingDetector(BaseDetector):
    async def stream_detect(self, url: str, **kwargs: Any) -> AsyncIterator[DetectionResult]:
        for r in await self.async_detect(url, **kwargs):
            yield r


# ---------------------------------------------------------------------------
# Context-Aware Detector
# ---------------------------------------------------------------------------

class ContextAwareDetector(BaseDetector):
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._context: Dict[str, Any] = {}

    def set_context(self, key: str, value: Any) -> None:
        self._context[key] = value

    def get_context(self, key: str, default: Any = None) -> Any:
        return self._context.get(key, default)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

class DetectorFactory:
    _detectors: Dict[str, Type[BaseDetector]] = {}
    _metadata: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def register(cls, name: str, detector_class: Type[BaseDetector],
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        cls._detectors[name] = detector_class
        cls._metadata[name] = metadata or {}

    @classmethod
    def unregister(cls, name: str) -> bool:
        removed = name in cls._detectors
        cls._detectors.pop(name, None)
        cls._metadata.pop(name, None)
        return removed

    @classmethod
    def create(cls, name: str, config: Optional[Dict[str, Any]] = None) -> BaseDetector:
        if name not in cls._detectors:
            raise KeyError(f"Detector '{name}' not registered")
        return cls._detectors[name](config)

    @classmethod
    def create_all(cls, config: Optional[Dict[str, Any]] = None) -> List[BaseDetector]:
        return [k(config) for k in cls._detectors.values()]

    @classmethod
    def create_by_type(cls, dt: DetectorType,
                       config: Optional[Dict[str, Any]] = None) -> List[BaseDetector]:
        return [k(config) for k in cls._detectors.values()
                if getattr(k, "detector_type", None) == dt]

    @classmethod
    def create_composite(cls, names: List[str],
                         config: Optional[Dict[str, Any]] = None) -> CompositeDetector:
        dets = [cls.create(n, config) for n in names if n in cls._detectors]
        return CompositeDetector(dets, config)

    @classmethod
    def list_detectors(cls) -> List[str]:
        return sorted(cls._detectors.keys())

    @classmethod
    def get_detector_info(cls, name: str) -> Dict[str, Any]:
        k = cls._detectors.get(name)
        if k is None:
            return {}
        return {
            "name": name,
            "description": getattr(k, "description", ""),
            "vuln_type": getattr(k, "vuln_type", ""),
            "severity": getattr(k, "severity", Severity.MEDIUM).value,
            "detector_type": getattr(k, "detector_type", DetectorType.MISC).value,
            **(cls._metadata.get(name, {})),
        }

    @classmethod
    def get_all_info(cls) -> List[Dict[str, Any]]:
        return [cls.get_detector_info(n) for n in cls.list_detectors()]

    @classmethod
    def exists(cls, name: str) -> bool:
        return name in cls._detectors

    @classmethod
    def clear(cls) -> None:
        cls._detectors.clear()
        cls._metadata.clear()


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------

def register_detector(name: str, metadata: Optional[Dict[str, Any]] = None):
    def decorator(cls: Type[BaseDetector]) -> Type[BaseDetector]:
        DetectorFactory.register(name, cls, metadata)
        return cls
    return decorator


# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------

class DetectorPresets:
    @staticmethod
    def owasp_top10(config: Optional[Dict[str, Any]] = None) -> CompositeDetector:
        names = ["sqli", "xss", "rce", "ssrf", "ssti", "xxe", "idor", "cors",
                 "path_traversal", "auth_bypass"]
        return DetectorFactory.create_composite(
            [n for n in names if DetectorFactory.exists(n)], config)

    @staticmethod
    def injection_suite(config: Optional[Dict[str, Any]] = None) -> CompositeDetector:
        names = ["sqli", "xss", "rce", "ssti", "xxe"]
        return DetectorFactory.create_composite(
            [n for n in names if DetectorFactory.exists(n)], config)

    @staticmethod
    def auth_suite(config: Optional[Dict[str, Any]] = None) -> CompositeDetector:
        names = ["auth_bypass", "idor", "cors"]
        return DetectorFactory.create_composite(
            [n for n in names if DetectorFactory.exists(n)], config)

    @staticmethod
    def quick_scan(config: Optional[Dict[str, Any]] = None) -> CompositeDetector:
        return DetectorFactory.create_composite(
            [n for n in ["sqli", "xss", "cors"] if DetectorFactory.exists(n)], config)

    @staticmethod
    def full_scan(config: Optional[Dict[str, Any]] = None) -> CompositeDetector:
        return CompositeDetector(DetectorFactory.create_all(config), config)
