"""
Hellcat DOM XSS Detector
=========================
Detect DOM-based XSS by identifying dangerous JS sinks fed by
user-controllable sources in page source code.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from hellcat.core.detectors import BaseDetector, register_detector
from hellcat.core.models import DetectionResult, DetectorType, Severity

# Dangerous JS sinks that can execute code
JS_SINKS = [
    r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"\.insertAdjacentHTML\s*\(",
    r"document\.write\s*\(", r"document\.writeln\s*\(",
    r"eval\s*\(", r"setTimeout\s*\(", r"setInterval\s*\(",
    r"Function\s*\(", r"execScript\s*\(",
    r"\.src\s*=", r"\.href\s*=", r"\.action\s*=",
    r"location\s*=", r"location\.href\s*=", r"location\.replace\s*\(",
    r"location\.assign\s*\(", r"window\.open\s*\(",
    r"\.setAttribute\s*\(\s*['\"]on", r"\.setAttribute\s*\(\s*['\"]href",
    r"jQuery\.html\s*\(", r"\$\s*\(\s*['\"]<", r"\.append\s*\(",
    r"\.prepend\s*\(", r"\.after\s*\(", r"\.before\s*\(",
    r"\.replaceWith\s*\(", r"\.wrap\s*\(",
    r"v-html\s*=", r"dangerouslySetInnerHTML",
]

# User-controllable sources
JS_SOURCES = [
    r"location\.hash", r"location\.search", r"location\.href",
    r"location\.pathname", r"document\.URL", r"document\.documentURI",
    r"document\.referrer", r"document\.cookie",
    r"window\.name", r"window\.location",
    r"\.getParameter\s*\(", r"\.get\s*\(\s*['\"]",
    r"URLSearchParams", r"hashParams", r"queryString",
    r"postMessage", r"localStorage\.getItem", r"sessionStorage\.getItem",
]


@register_detector("dom_xss", {"owasp": "A03:2021"})
class DOMXSSDetector(BaseDetector):
    name = "dom_xss"
    description = "DOM-based XSS detector via source-sink analysis"
    vuln_type = "DOM XSS"
    severity = Severity.HIGH
    detector_type = DetectorType.INJECTION

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []

        # Get page source
        page_source = kwargs.get("page_source", "")
        if not page_source:
            page_source = self._fetch_source(url)
        if not page_source:
            self._log_end(url, results)
            return results

        # Extract all JS from page
        scripts = self._extract_scripts(page_source)
        all_js = "\n".join(scripts)

        # Find sinks
        found_sinks = []
        for pattern in JS_SINKS:
            matches = re.finditer(pattern, all_js)
            for m in matches:
                # Get context (line around the match)
                start = max(0, m.start() - 80)
                end = min(len(all_js), m.end() + 80)
                context = all_js[start:end].strip()
                found_sinks.append({"pattern": pattern, "context": context, "position": m.start()})

        # Find sources
        found_sources = []
        for pattern in JS_SOURCES:
            matches = re.finditer(pattern, all_js)
            for m in matches:
                start = max(0, m.start() - 60)
                end = min(len(all_js), m.end() + 60)
                context = all_js[start:end].strip()
                found_sources.append({"pattern": pattern, "context": context})

        # Source->Sink flow analysis (simplified: if both exist in same script block)
        if found_sinks and found_sources:
            for sink in found_sinks[:5]:
                for source in found_sources[:5]:
                    results.append(self._create_result(
                        url,
                        evidence=f"Source: {source['pattern']} -> Sink: {sink['pattern']}\n"
                                 f"Source context: {source['context'][:100]}\n"
                                 f"Sink context: {sink['context'][:100]}",
                        confidence=0.65,
                        remediation="Use textContent instead of innerHTML, sanitize DOM inputs, implement CSP",
                        extra={"sinks_found": len(found_sinks), "sources_found": len(found_sources)},
                    ))
                    break  # one finding per sink
                if results:
                    break
        elif found_sinks:
            # Sinks without identified sources — lower confidence
            results.append(self._create_result(
                url,
                evidence=f"Dangerous JS sinks found ({len(found_sinks)}) but no direct user source identified.\n"
                         f"Top sink: {found_sinks[0]['context'][:150]}",
                confidence=0.35,
                extra={"sinks_found": len(found_sinks), "sources_found": 0},
            ))

        self._log_end(url, results)
        return results

    def _fetch_source(self, url: str) -> str:
        try:
            import requests
            resp = requests.get(url, timeout=10, verify=False)
            return resp.text
        except Exception:
            return ""

    def _extract_scripts(self, html: str) -> List[str]:
        scripts = []
        # Inline scripts
        for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
            content = m.group(1).strip()
            if content:
                scripts.append(content)
        # Event handlers in attributes
        for m in re.finditer(r'on\w+\s*=\s*["\']([^"\']+)', html, re.IGNORECASE):
            scripts.append(m.group(1))
        # javascript: URLs
        for m in re.finditer(r'javascript:\s*([^"\'>\s]+)', html, re.IGNORECASE):
            scripts.append(m.group(1))
        return scripts
