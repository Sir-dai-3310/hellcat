"""Hellcat Bounty Hunter handlers — Repeater/Intruder/Auth/SSRF/Report MCP tools."""
from __future__ import annotations
import logging
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from fastmcp import FastMCP
    from hellcat.hellcat_mcp import ToolCounter

def register_bounty_tools(mcp: FastMCP, counter: ToolCounter, logger: logging.Logger) -> None:

    @mcp.tool()
    def http_request(method: str, url: str, params: str = "", body: str = "",
                     headers: str = "", cookies: str = "") -> dict:
        """Send HTTP request and get full response (like Burp Repeater).
        Example: http_request(method="GET", url="http://target.com/api", params="id=1&name=test")"""
        from hellcat.modules.web_scanner import Repeater
        h = dict(x.split(":", 1) for x in headers.split("|") if ":" in x) if headers else {}
        p = dict(x.split("=", 1) for x in params.split("&") if "=" in x) if params else {}
        c = dict(x.split("=", 1) for x in cookies.split(";") if "=" in x) if cookies else {}
        rep = Repeater(timeout=15)
        pair = rep.send_raw(method, url, headers=h, params=p, body=body, cookies=c)
        return pair.to_dict()

    @mcp.tool()
    def fuzz_params(url: str, params: str, payloads_type: str = "xss",
                    method: str = "GET") -> dict:
        """Fuzz all URL parameters with payloads (like Burp Intruder Sniper).
        Example: fuzz_params(url="http://target.com/search", params="q=test&page=1", payloads_type="sqli")"""
        from hellcat.modules.web_scanner import Repeater, Intruder
        from hellcat.modules.payload import PayloadGenerator
        p = dict(x.split("=", 1) for x in params.split("&") if "=" in x)
        if not p:
            return {"error": "params required (e.g. q=test&page=1)"}
        payloads = PayloadGenerator.get_extended(payloads_type, 15)
        if not payloads:
            payloads = PayloadGenerator.get_payloads(payloads_type, "basic", 10)
        intr = Intruder(Repeater(timeout=10))
        results = intr.fuzz_params(url, p, payloads, method)
        summary = intr.summary(results)
        return {"params_tested": list(results.keys()), "total_requests": summary["total_requests"],
                "anomalies": summary["anomalies"][:10], "anomaly_count": summary["anomaly_count"]}

    @mcp.tool()
    def auth_login(login_url: str, username: str, password: str,
                   username_field: str = "username", password_field: str = "password") -> dict:
        """Login to target and capture session tokens/cookies.
        Example: auth_login(login_url="http://target.com/login", username="admin", password="<password>")"""
        from hellcat.modules.api_security import AuthManager, AuthProfile
        am = AuthManager()
        am.add_profile(AuthProfile(
            name="target", auth_type="cookie", login_url=login_url,
            login_data={username_field: username, password_field: password},
        ))
        return am.login("target")

    @mcp.tool()
    def jwt_decode(token: str) -> dict:
        """Decode a JWT token (no verification) to inspect claims.
        Example: jwt_decode(token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxx")"""
        from hellcat.modules.api_security import AuthManager
        return AuthManager.decode_jwt(token)

    @mcp.tool()
    def ssrf_scan(url: str, params: str) -> dict:
        """Test URL parameters for SSRF vulnerabilities.
        Example: ssrf_scan(url="http://target.com/fetch", params="url=test&callback=test")"""
        if not url.startswith(("http://", "https://")):
            return {"error": "url must start with http://"}
        from hellcat.core.detectors import DetectorFactory
        try:
            from hellcat.core.detectors.request import SSRFDetector  # noqa
        except Exception:
            pass
        p = dict(x.split("=", 1) for x in params.split("&") if "=" in x)
        if not DetectorFactory.exists("ssrf"):
            return {"error": "ssrf detector not available"}
        det = DetectorFactory.create("ssrf")
        results = det.detect(url, params=p)
        return {"findings": [r.to_dict() for r in results], "count": len(results)}

    @mcp.tool()
    def race_test(url: str, method: str = "GET", threads: int = 10) -> dict:
        """Test for race condition vulnerabilities via concurrent requests.
        Example: race_test(url="http://target.com/api/transfer", method="POST", threads=20)"""
        from hellcat.core.detectors import DetectorFactory
        try:
            from hellcat.core.detectors.request import RaceConditionDetector  # noqa
        except Exception:
            pass
        if not DetectorFactory.exists("race_condition"):
            return {"error": "race_condition detector not available"}
        det = DetectorFactory.create("race_condition")
        results = det.detect(url, method=method, threads=threads)
        return {"findings": [r.to_dict() for r in results], "count": len(results)}

    @mcp.tool()
    def graphql_scan(url: str) -> dict:
        """Scan for GraphQL introspection and misconfigurations.
        Example: graphql_scan(url="http://target.com")"""
        from hellcat.core.detectors import DetectorFactory
        try:
            from hellcat.core.detectors.request import GraphQLDetector  # noqa
        except Exception:
            pass
        if not DetectorFactory.exists("graphql"):
            return {"error": "graphql detector not available"}
        det = DetectorFactory.create("graphql")
        results = det.detect(url)
        return {"findings": [r.to_dict() for r in results], "count": len(results)}

    @mcp.tool()
    def bounty_report(vuln_type: str, url: str, param: str, payload: str,
                      evidence: str, severity: str = "high") -> dict:
        """Generate HackerOne-ready bug bounty report from finding.
        Example: bounty_report(vuln_type="sqli", url="http://target.com/search", param="q", payload="' OR 1=1--", evidence="MySQL error", severity="critical")"""
        from hellcat.templates.report import BountyReportGenerator
        finding = {"vuln_type": vuln_type, "url": url, "param": param,
                   "payload": payload, "evidence": evidence, "severity": severity}
        return BountyReportGenerator.generate(finding)

    @mcp.tool()
    def secret_scan(url: str) -> dict:
        """Scan URL for leaked secrets (API keys, tokens, passwords, private keys).
        Example: secret_scan(url="http://target.com")"""
        from hellcat.core.detectors.misc.secrets import SecretScanner
        scanner = SecretScanner()
        findings = scanner.scan_url(url)
        return {"url": url, "secrets_found": len(findings),
                "findings": [f.to_dict() for f in findings[:20]]}

    @mcp.tool()
    def js_analyze(url: str) -> dict:
        """Crawl and analyze JavaScript files for endpoints, subdomains, and secrets.
        Example: js_analyze(url="http://target.com")"""
        from hellcat.modules.web_scanner.js_analyzer import JSAnalyzer
        return JSAnalyzer().analyze_url(url)

    @mcp.tool()
    def subdomain_takeover(subdomains: str) -> dict:
        """Check subdomains for takeover vulnerabilities (GitHub/AWS/Heroku/Azure/etc).
        Example: subdomain_takeover(subdomains="test.example.com,dev.example.com")"""
        from hellcat.core.detectors.misc.takeover import SubdomainTakeoverScanner
        subs = [s.strip() for s in subdomains.split(",") if s.strip()]
        scanner = SubdomainTakeoverScanner()
        results = scanner.check_batch(subs[:20])
        vulnerable = [r for r in results if r.get("vulnerable")]
        return {"checked": len(results), "vulnerable": len(vulnerable), "results": results}

    @mcp.tool()
    def smuggling_scan(url: str) -> dict:
        """Test for HTTP Request Smuggling (CL.TE / TE.CL desync).
        Example: smuggling_scan(url="http://target.com")"""
        from hellcat.core.detectors.request.smuggling import HTTPSmugglingDetector
        det = HTTPSmugglingDetector()
        results = det.detect(url, timeout=8)
        return {"findings": [r.to_dict() for r in results], "count": len(results)}

    @mcp.tool()
    def nuclei_template_gen(cve_id: str, description: str, cvss: float = 0.0,
                            affected: str = "") -> dict:
        """AI-generate a Nuclei YAML detection template from CVE info.
        Example: nuclei_template_gen(cve_id="CVE-2026-33017", description="RCE in Langflow", cvss=9.3)"""
        from hellcat.core.ai.nuclei_gen import NucleiTemplateGenerator
        template = NucleiTemplateGenerator.from_cve(cve_id, description, cvss, affected)
        return {"cve_id": cve_id, "template": template, "length": len(template)}

    @mcp.tool()
    def scan_mode(target: str, mode: str = "normal") -> dict:
        """Run scan in stealth/normal/aggressive mode.
        stealth=passive only, normal=balanced, aggressive=full assault.
        Example: scan_mode(target="example.com", mode="aggressive")"""
        from hellcat.core.engine import MultiModeScanner
        return MultiModeScanner.scan(target, mode)

    @mcp.tool()
    def open_redirect_scan(url: str, params: str = "") -> dict:
        """Test for Open Redirect vulnerabilities.
        Example: open_redirect_scan(url="http://target.com/login", params="next=test&redirect=test")"""
        if not url.startswith(("http://", "https://")):
            return {"error": "url must start with http://"}
        from hellcat.core.detectors import DetectorFactory
        try:
            from hellcat.core.detectors.misc.web_vulns import OpenRedirectDetector  # noqa
        except Exception:
            pass
        p = dict(x.split("=", 1) for x in params.split("&") if "=" in x) if params else {}
        if not DetectorFactory.exists("open_redirect"):
            return {"error": "open_redirect detector unavailable"}
        results = DetectorFactory.create("open_redirect").detect(url, params=p)
        return {"findings": [r.to_dict() for r in results], "count": len(results)}

    @mcp.tool()
    def crlf_scan(url: str, params: str = "") -> dict:
        """Test for CRLF Injection / HTTP Response Splitting.
        Example: crlf_scan(url="http://target.com/search", params="q=test")"""
        if not url.startswith(("http://", "https://")):
            return {"error": "url must start with http://"}
        from hellcat.core.detectors import DetectorFactory
        try:
            from hellcat.core.detectors.misc.web_vulns import CRLFDetector  # noqa
        except Exception:
            pass
        p = dict(x.split("=", 1) for x in params.split("&") if "=" in x) if params else {}
        if not DetectorFactory.exists("crlf"):
            return {"error": "crlf detector unavailable"}
        results = DetectorFactory.create("crlf").detect(url, params=p)
        return {"findings": [r.to_dict() for r in results], "count": len(results)}

    @mcp.tool()
    def vuln_chain_analyze(findings_json: str) -> dict:
        """Analyze multiple vulnerabilities for exploit chain opportunities.
        Example: vuln_chain_analyze(findings_json='[{"vuln_type":"xss"},{"vuln_type":"open_redirect"}]')"""
        import json
        try:
            findings = json.loads(findings_json)
        except Exception:
            return {"error": "Invalid JSON. Provide array of {vuln_type: ...} objects."}
        from hellcat.agents.cve import VulnerabilityCorrelator
        chains = VulnerabilityCorrelator.correlate(findings)
        return {"chains_found": len(chains), "chains": chains}

    @mcp.tool()
    def waf_detect(url: str) -> dict:
        """Detect and fingerprint WAF vendor on target.
        Example: waf_detect(url="http://target.com")"""
        from hellcat.core.detectors.misc.waf import WAFDetector
        return WAFDetector().detect(url)

    @mcp.tool()
    def waf_bypass_payloads(waf_name: str, vuln_type: str = "xss") -> dict:
        """Get WAF-specific bypass payloads for a vulnerability type.
        Example: waf_bypass_payloads(waf_name="Cloudflare", vuln_type="sqli")"""
        from hellcat.core.detectors.misc.waf import WAFDetector
        payloads = WAFDetector.get_bypass_payloads(waf_name, vuln_type)
        return {"waf": waf_name, "vuln_type": vuln_type, "payloads": payloads, "count": len(payloads)}

    @mcp.tool()
    def professional_report(target: str, findings_json: str) -> dict:
        """Generate professional pentest report with CVSS scoring and ATT&CK mapping.
        Example: professional_report(target="example.com", findings_json='[{"vuln_type":"XSS","severity":"high","url":"http://x","param":"q"}]')"""
        import json
        from hellcat.core.session import ProfessionalReport
        try:
            findings = json.loads(findings_json)
        except Exception:
            return {"error": "Invalid JSON"}
        rg = ProfessionalReport()
        rg.set_metadata(target=target, tester="Hellcat")
        rg.add_findings(findings)
        return {"markdown": rg.to_professional_markdown(), "json": rg.to_json()}

    counter.add("bounty", 22)

def register_advanced_tools(mcp: FastMCP, counter: ToolCounter, logger: logging.Logger) -> None:

    @mcp.tool()
    def cicd_scan(repo_url: str) -> dict:
        """Scan GitHub repo CI/CD workflows for security misconfigurations.
        Example: cicd_scan(repo_url="https://github.com/owner/repo")"""
        from hellcat.core.detectors.misc.cicd import CICDScanner
        return {"findings": CICDScanner().scan_url(repo_url)}

    @mcp.tool()
    def verify_exploit(url: str, vuln_type: str, param: str = "", payload: str = "") -> dict:
        """Verify a vulnerability with real exploitation attempt + evidence capture.
        Example: verify_exploit(url="http://target.com/search", vuln_type="sqli", param="q")"""
        from hellcat.core.ai.verifier import ExploitVerifier
        finding = {"url": url, "vuln_type": vuln_type, "param": param, "payload": payload}
        return ExploitVerifier().verify(finding)

    @mcp.tool()
    def map_attack_surface(url: str) -> dict:
        """Auto-discover all endpoints, parameters, forms, JS files, and secrets.
        Example: map_attack_surface(url="http://target.com")"""
        from hellcat.core.ai.verifier import AttackSurfaceMapper
        return AttackSurfaceMapper().map(url)

    counter.add("advanced", 3)
