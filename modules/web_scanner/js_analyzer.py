"""
Hellcat JS Analyzer
====================
Crawl and analyze JavaScript files to extract:
- API endpoints  - Subdomains  - Secrets/tokens
- Interesting paths  - Comments with sensitive info
Inspired by reconFTW JS analysis pipeline.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List
from urllib.parse import urljoin

logger = logging.getLogger("hellcat.js")

# Regex patterns for extraction
ENDPOINT_PATTERNS = [
    r"""(?:"|')(/api/[^\s"']+)(?:"|')""",
    r"""(?:"|')(/v[0-9]+/[^\s"']+)(?:"|')""",
    r"""(?:"|')(https?://[^\s"']+)(?:"|')""",
    r"""fetch\s*\(\s*(?:"|')([^\s"']+)""",
    r"""\.(?:get|post|put|delete|patch)\s*\(\s*(?:"|')([^\s"']+)""",
    r"""XMLHttpRequest.*?\.open\s*\(\s*(?:"|')\w+(?:"|')\s*,\s*(?:"|')([^\s"']+)""",
    r"""(?:href|src|action)\s*=\s*(?:"|')([^\s"']+)""",
    r"""(?:url|endpoint|path|route)\s*[=:]\s*(?:"|')([^\s"']+)""",
]

SUBDOMAIN_PATTERN = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"


class JSAnalyzer:
    """Extract endpoints, subdomains, and secrets from JavaScript."""

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Fetch and analyze a JS file or HTML page."""
        try:
            import requests
            resp = requests.get(url, timeout=15, verify=False)
            return self.analyze_text(resp.text, base_url=url)
        except Exception as exc:
            return {"error": str(exc), "url": url}

    def analyze_text(self, text: str, base_url: str = "") -> Dict[str, Any]:
        """Analyze text content for endpoints, subdomains, secrets."""
        endpoints = self._extract_endpoints(text)
        subdomains = self._extract_subdomains(text)
        comments = self._extract_comments(text)

        # Secret scan
        from hellcat.core.detectors.misc.secrets import SecretScanner
        secrets = SecretScanner().scan_text(text, location=base_url)

        # JS file references
        js_files = re.findall(r'(?:src|href)\s*=\s*["\']([^"\']*\.js[^"\']*)', text)
        if base_url:
            js_files = [urljoin(base_url, f) for f in js_files]

        return {
            "endpoints": sorted(set(endpoints))[:100],
            "subdomains": sorted(set(subdomains))[:50],
            "secrets": [s.to_dict() for s in secrets],
            "js_files": js_files[:30],
            "comments_with_info": comments[:20],
            "stats": {
                "endpoints_found": len(endpoints),
                "subdomains_found": len(subdomains),
                "secrets_found": len(secrets),
                "js_files_found": len(js_files),
            },
        }

    def analyze_multiple(self, urls: List[str]) -> Dict[str, Any]:
        """Analyze multiple JS/HTML URLs."""
        all_endpoints, all_subs, all_secrets = [], [], []
        for url in urls[:20]:
            result = self.analyze_url(url)
            all_endpoints.extend(result.get("endpoints", []))
            all_subs.extend(result.get("subdomains", []))
            all_secrets.extend(result.get("secrets", []))
        return {
            "urls_analyzed": len(urls),
            "total_endpoints": len(set(all_endpoints)),
            "total_subdomains": len(set(all_subs)),
            "total_secrets": len(all_secrets),
            "endpoints": sorted(set(all_endpoints))[:100],
            "subdomains": sorted(set(all_subs))[:50],
            "secrets": all_secrets[:20],
        }

    def _extract_endpoints(self, text: str) -> List[str]:
        eps = []
        for pattern in ENDPOINT_PATTERNS:
            eps.extend(re.findall(pattern, text))
        return [e for e in eps if len(e) > 3 and not e.endswith((".css", ".png", ".jpg", ".gif", ".ico"))]

    def _extract_subdomains(self, text: str) -> List[str]:
        subs = re.findall(SUBDOMAIN_PATTERN, text)
        return [s for s in subs if not s.endswith((".js", ".css", ".png", ".jpg"))
                and "." in s and len(s) > 5]

    def _extract_comments(self, text: str) -> List[str]:
        comments = []
        # Single-line JS comments
        for m in re.finditer(r"//\s*(.{10,80})", text):
            c = m.group(1).strip()
            if any(k in c.lower() for k in ("todo", "fixme", "hack", "password",
                   "secret", "key", "token", "admin", "debug", "temp", "api")):
                comments.append(c)
        # Multi-line comments
        for m in re.finditer(r"/\*(.{10,200}?)\*/", text, re.DOTALL):
            c = m.group(1).strip()
            if any(k in c.lower() for k in ("todo", "password", "secret", "key", "api")):
                comments.append(c[:100])
        return comments
