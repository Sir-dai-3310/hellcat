"""
Hellcat Open Redirect + CRLF Injection + Prototype Pollution Detectors
======================================================================
High-value bug bounty vuln types. Inspired by CORScanner/ppfuzz/crlf-scanner.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urljoin, quote

from hellcat.core.detectors import BaseDetector, register_detector
from hellcat.core.models import DetectionResult, DetectorType, Severity

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


# ---------------------------------------------------------------------------
# R16: Open Redirect
# ---------------------------------------------------------------------------

REDIRECT_PARAMS = ["url", "redirect", "next", "return", "redir", "return_to",
                   "redirect_uri", "redirect_url", "dest", "destination",
                   "go", "target", "link", "out", "continue", "forward"]

REDIRECT_PAYLOADS = [
    "https://evil.com", "//evil.com", "/\\evil.com", "https:evil.com",
    "////evil.com", "https://evil.com/%2f..", "//evil%00.com",
    "https://evil.com@legitimate.com", "//%0d%0aevil.com",
    "https://legitimate.com.evil.com",
]


@register_detector("open_redirect", {"owasp": "A01:2021", "bounty": "$200-$1000"})
class OpenRedirectDetector(BaseDetector):
    name = "open_redirect"
    description = "Open Redirect vulnerability detector"
    vuln_type = "Open Redirect"
    severity = Severity.MEDIUM
    detector_type = DetectorType.REQUEST

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        params = kwargs.get("params", {})
        # Auto-detect redirect params
        test_params = [p for p in params if p.lower() in REDIRECT_PARAMS]
        if not test_params:
            test_params = [p for p in params][:3]

        for param in test_params:
            for payload in REDIRECT_PAYLOADS[:5]:
                try:
                    test_p = dict(params)
                    test_p[param] = payload
                    resp = requests.get(url, params=test_p, timeout=8,
                                        verify=False, allow_redirects=False)
                    location = resp.headers.get("Location", "")
                    if resp.status_code in (301, 302, 303, 307, 308):
                        if "evil.com" in location:
                            results.append(self._create_result(
                                url, param=param, payload=payload,
                                evidence=f"Redirect to: {location}",
                                confidence=0.95, verified=True,
                                remediation="Validate redirect URLs against allowlist, use relative paths",
                            ))
                            break
                except Exception:
                    pass
            if results:
                break
        self._log_end(url, results)
        return results


# ---------------------------------------------------------------------------
# R17: CRLF Injection
# ---------------------------------------------------------------------------

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:hellcat=crlf",
    "%0d%0aX-Injected:hellcat",
    "%0aX-Injected:hellcat",
    "%0dX-Injected:hellcat",
    "\r\nX-Injected:hellcat",
    "%E5%98%8A%E5%98%8DX-Injected:hellcat",  # Unicode CRLF
]


@register_detector("crlf", {"owasp": "A03:2021", "bounty": "$500-$3000"})
class CRLFDetector(BaseDetector):
    name = "crlf"
    description = "CRLF Injection / HTTP Response Splitting detector"
    vuln_type = "CRLF Injection"
    severity = Severity.HIGH
    detector_type = DetectorType.INJECTION

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        params = kwargs.get("params", {})
        test_params = list(params.keys())[:5] if params else ["q"]

        for param in test_params:
            for payload in CRLF_PAYLOADS[:4]:
                try:
                    test_p = dict(params)
                    test_p[param] = payload
                    resp = requests.get(url, params=test_p, timeout=8, verify=False)
                    # Check if injected header appears
                    if "X-Injected" in resp.headers or "hellcat=crlf" in resp.headers.get("Set-Cookie", ""):
                        results.append(self._create_result(
                            url, param=param, payload=payload,
                            evidence=f"Injected header found in response",
                            confidence=0.95, verified=True,
                            remediation="Sanitize CRLF characters in user input, encode output in headers",
                        ))
                        break
                except Exception:
                    pass
            if results:
                break
        self._log_end(url, results)
        return results


# ---------------------------------------------------------------------------
# R18: Prototype Pollution (client-side)
# ---------------------------------------------------------------------------

PP_PAYLOADS = [
    "__proto__[polluted]=hellcat",
    "constructor[prototype][polluted]=hellcat",
    "__proto__.polluted=hellcat",
]


@register_detector("prototype_pollution", {"bounty": "$500-$5000"})
class PrototypePollutionDetector(BaseDetector):
    name = "prototype_pollution"
    description = "Client-side Prototype Pollution via URL parameters"
    vuln_type = "Prototype Pollution"
    severity = Severity.HIGH
    detector_type = DetectorType.INJECTION

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        for payload in PP_PAYLOADS:
            test_url = f"{url}?{payload}" if "?" not in url else f"{url}&{payload}"
            try:
                resp = requests.get(test_url, timeout=8, verify=False)
                # Check if pollution marker appears in response
                if "hellcat" in resp.text and "polluted" in resp.text:
                    results.append(self._create_result(
                        url, payload=payload,
                        evidence="Prototype pollution marker reflected in response",
                        confidence=0.60,
                        remediation="Freeze Object.prototype, validate property names, use Map instead of objects",
                    ))
                    break
                # Check for query param reflection (lower confidence)
                if payload in resp.text:
                    results.append(self._create_result(
                        url, payload=payload,
                        evidence="Pollution payload reflected (needs manual verification)",
                        confidence=0.35,
                        remediation="Freeze Object.prototype, sanitize query parameters",
                    ))
                    break
            except Exception:
                pass
        self._log_end(url, results)
        return results


# ---------------------------------------------------------------------------
# R19: Enhanced IDOR (API-focused)
# ---------------------------------------------------------------------------

@register_detector("api_idor", {"owasp": "A01:2021", "bounty": "$1000-$10000"})
class APIIDORDetector(BaseDetector):
    name = "api_idor"
    description = "API-focused IDOR detector with sequential/UUID ID testing"
    vuln_type = "API IDOR"
    severity = Severity.HIGH
    detector_type = DetectorType.ACCESS

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        # Detect numeric IDs in URL path
        id_pattern = re.findall(r'/(\d{1,10})(?:/|$|\?)', url)
        if not id_pattern:
            self._log_end(url, results)
            return results

        for original_id in id_pattern[:2]:
            try:
                # Request with original ID
                r1 = requests.get(url, timeout=8, verify=False)
                # Request with ID+1
                modified_url = url.replace(f"/{original_id}", f"/{int(original_id)+1}", 1)
                r2 = requests.get(modified_url, timeout=8, verify=False)
                # Request with ID-1
                if int(original_id) > 1:
                    modified_url2 = url.replace(f"/{original_id}", f"/{int(original_id)-1}", 1)
                    r3 = requests.get(modified_url2, timeout=8, verify=False)
                else:
                    r3 = r2

                # Check: all return 200 with different content
                if (r1.status_code == 200 and r2.status_code == 200
                        and r1.text != r2.text and len(r2.text) > 50):
                    results.append(self._create_result(
                        url, payload=f"ID={original_id} vs ID={int(original_id)+1}",
                        evidence=f"Different responses for adjacent IDs (size diff: {abs(len(r1.text)-len(r2.text))} bytes)",
                        confidence=0.70,
                        remediation="Implement server-side authorization, use UUIDs, validate resource ownership",
                    ))
                    break
            except Exception:
                pass
        self._log_end(url, results)
        return results
