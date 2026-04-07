"""
Hellcat Auth/Access Detectors
=============================
IDOR, CORS misconfiguration, path traversal, auth bypass detection.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from hellcat.core.detectors import BaseDetector, register_detector
from hellcat.core.models import DetectionResult, DetectorType, Severity

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# CORS Detector
# ---------------------------------------------------------------------------

@register_detector("cors", {"owasp": "A01:2021"})
class CORSDetector(BaseDetector):
    name = "cors"
    description = "CORS misconfiguration detector"
    vuln_type = "CORS Misconfiguration"
    severity = Severity.MEDIUM
    detector_type = DetectorType.REQUEST

    ORIGINS_TO_TEST = [
        "https://evil.com",
        "null",
        "https://evil.target.com",
    ]

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        try:
            import requests
            for origin in self.ORIGINS_TO_TEST:
                resp = requests.get(url, headers={"Origin": origin}, timeout=10, verify=False)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "*" or acao == origin:
                    results.append(self._create_result(
                        url, payload=f"Origin: {origin}",
                        evidence=f"ACAO={acao}, ACAC={acac}",
                        confidence=0.9 if acao == origin else 0.7,
                        remediation="Restrict ACAO to trusted origins, avoid wildcard with credentials",
                    ))
                    break
        except Exception:
            pass
        self._log_end(url, results)
        return results


# ---------------------------------------------------------------------------
# IDOR Detector
# ---------------------------------------------------------------------------

@register_detector("idor", {"owasp": "A01:2021"})
class IDORDetector(BaseDetector):
    name = "idor"
    description = "Insecure Direct Object Reference detector"
    vuln_type = "IDOR"
    severity = Severity.HIGH
    detector_type = DetectorType.ACCESS

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        params = kwargs.get("params", {})
        try:
            import requests
            for param, val in params.items():
                if not str(val).isdigit():
                    continue
                # Request with original ID
                r1 = requests.get(url, params=params, timeout=10, verify=False)
                # Request with modified ID
                modified = dict(params)
                modified[param] = str(int(val) + 1)
                r2 = requests.get(url, params=modified, timeout=10, verify=False)
                # If both return 200 with different content, possible IDOR
                if r1.status_code == 200 and r2.status_code == 200:
                    if r1.text != r2.text and len(r2.text) > 100:
                        results.append(self._create_result(
                            url, param=param, payload=f"{param}={modified[param]}",
                            evidence=f"Different response for id={val} vs id={modified[param]}",
                            confidence=0.65,
                            remediation="Implement server-side authorization checks on object access",
                        ))
        except Exception:
            pass
        self._log_end(url, results)
        return results


# ---------------------------------------------------------------------------
# Path Traversal Detector
# ---------------------------------------------------------------------------

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....\\....\\....\\windows\\win.ini",
    "../../../etc/passwd%00", "..%252f..%252f..%252fetc%252fpasswd",
]

PATH_TRAVERSAL_SIGNATURES = [
    "root:x:", "root:*:", "[fonts]", "[extensions]",
    "daemon:x:", "bin:x:", "nobody:x:",
]


@register_detector("path_traversal", {"owasp": "A01:2021"})
class PathTraversalDetector(BaseDetector):
    name = "path_traversal"
    description = "Path traversal / directory traversal detector"
    vuln_type = "Path Traversal"
    severity = Severity.HIGH
    detector_type = DetectorType.FILE

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        params = kwargs.get("params", {})
        file_params = [p for p in params if any(k in p.lower() for k in
                       ("file", "path", "page", "doc", "template", "include", "dir", "folder"))]
        if not file_params:
            file_params = list(params.keys())[:3]

        try:
            import requests
            for param in file_params:
                for payload in PATH_TRAVERSAL_PAYLOADS[:6]:
                    test_params = dict(params)
                    test_params[param] = payload
                    resp = requests.get(url, params=test_params, timeout=10, verify=False)
                    for sig in PATH_TRAVERSAL_SIGNATURES:
                        if sig in resp.text:
                            results.append(self._create_result(
                                url, param=param, payload=payload,
                                evidence=f"File content signature found: {sig}",
                                confidence=0.95, verified=True,
                                remediation="Validate and sanitize file paths, use allowlists",
                            ))
                            break
                    if results:
                        break
                if results:
                    break
        except Exception:
            pass
        self._log_end(url, results)
        return results


# ---------------------------------------------------------------------------
# Auth Bypass Detector
# ---------------------------------------------------------------------------

AUTH_BYPASS_PATHS = [
    "/admin", "/admin/", "/administrator", "/dashboard",
    "/api/admin", "/manager", "/console", "/debug",
    "/.env", "/config", "/swagger", "/graphql",
]


@register_detector("auth_bypass", {"owasp": "A07:2021"})
class AuthBypassDetector(BaseDetector):
    name = "auth_bypass"
    description = "Authentication bypass and unprotected endpoint detector"
    vuln_type = "Authentication Bypass"
    severity = Severity.CRITICAL
    detector_type = DetectorType.AUTH

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        try:
            import requests
            for path in AUTH_BYPASS_PATHS:
                test_url = urljoin(base, path)
                resp = requests.get(test_url, timeout=8, verify=False, allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 200:
                    if not any(k in resp.text.lower() for k in ("login", "sign in", "authenticate")):
                        results.append(self._create_result(
                            test_url, payload=path,
                            evidence=f"HTTP 200 with {len(resp.text)} bytes, no auth required",
                            confidence=0.6,
                            remediation="Enforce authentication on all sensitive endpoints",
                        ))
                        if len(results) >= 3:
                            break
        except Exception:
            pass
        self._log_end(url, results)
        return results
