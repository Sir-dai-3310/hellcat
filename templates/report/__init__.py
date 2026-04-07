"""
Hellcat Bug Bounty Report Templates
=====================================
HackerOne / Bugcrowd / Intigriti ready report generation.
Auto-generates from scan findings with reproduction steps.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

SEVERITY_MAP = {
    "critical": {"hackerone": "critical", "cvss_range": "9.0-10.0", "bounty_range": "$5,000-$50,000"},
    "high":     {"hackerone": "high",     "cvss_range": "7.0-8.9",  "bounty_range": "$2,000-$10,000"},
    "medium":   {"hackerone": "medium",   "cvss_range": "4.0-6.9",  "bounty_range": "$500-$3,000"},
    "low":      {"hackerone": "low",      "cvss_range": "0.1-3.9",  "bounty_range": "$100-$500"},
}

VULN_TEMPLATES: Dict[str, Dict[str, str]] = {
    "sqli": {
        "title": "SQL Injection in {param} parameter on {endpoint}",
        "impact": "An attacker can extract, modify, or delete data from the database. "
                  "In severe cases, this can lead to full database compromise, authentication bypass, "
                  "or remote code execution via stacked queries or file write primitives.",
        "remediation": "1. Use parameterized queries / prepared statements\n"
                       "2. Implement input validation with allowlists\n"
                       "3. Apply principle of least privilege to DB accounts\n"
                       "4. Deploy WAF rules for SQL injection patterns",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection",
                       "https://portswigger.net/web-security/sql-injection"],
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS) via {param} on {endpoint}",
        "impact": "An attacker can execute arbitrary JavaScript in the victim's browser, "
                  "stealing session tokens, performing actions on behalf of the user, "
                  "or redirecting to phishing pages.",
        "remediation": "1. Encode output based on context (HTML, JS, URL, CSS)\n"
                       "2. Implement Content-Security-Policy header\n"
                       "3. Use HttpOnly and Secure flags on cookies\n"
                       "4. Sanitize input with allowlists",
        "references": ["https://owasp.org/www-community/attacks/xss/",
                       "https://portswigger.net/web-security/cross-site-scripting"],
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF) via {param} on {endpoint}",
        "impact": "An attacker can make the server send requests to internal services, "
                  "access cloud metadata endpoints (AWS/GCP/Azure), scan internal networks, "
                  "or bypass firewalls to reach restricted resources.",
        "remediation": "1. Validate and allowlist destination URLs\n"
                       "2. Block requests to private IP ranges (10.x, 172.16.x, 192.168.x)\n"
                       "3. Disable unused URL schemes (file://, gopher://, dict://)\n"
                       "4. Use network segmentation",
        "references": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    },
    "idor": {
        "title": "Insecure Direct Object Reference (IDOR) on {endpoint}",
        "impact": "An attacker can access or modify other users' data by manipulating "
                  "object identifiers (IDs, filenames, etc.) in API requests.",
        "remediation": "1. Implement server-side authorization checks\n"
                       "2. Use indirect references (UUIDs instead of sequential IDs)\n"
                       "3. Validate ownership before granting access",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"],
    },
    "cors": {
        "title": "CORS Misconfiguration on {endpoint}",
        "impact": "An attacker's website can make cross-origin requests and read responses, "
                  "potentially stealing sensitive data or performing authenticated actions.",
        "remediation": "1. Restrict Access-Control-Allow-Origin to trusted domains\n"
                       "2. Never use wildcard (*) with credentials\n"
                       "3. Validate Origin header server-side",
        "references": ["https://portswigger.net/web-security/cors"],
    },
}


class BountyReportGenerator:
    """Generate HackerOne/Bugcrowd submission reports."""

    @staticmethod
    def generate(finding: Dict[str, Any], platform: str = "hackerone") -> Dict[str, Any]:
        vuln_type = finding.get("vuln_type", "").lower().replace(" ", "_").replace("-", "_")
        template = VULN_TEMPLATES.get(vuln_type, {})

        param = finding.get("param", "unknown")
        url = finding.get("url", "")
        endpoint = url.split("?")[0] if url else "target endpoint"
        severity = finding.get("severity", "medium")
        payload = finding.get("payload", "")
        evidence = finding.get("evidence", "")

        title = template.get("title", f"{vuln_type.upper()} vulnerability on {endpoint}")
        title = title.format(param=param, endpoint=endpoint)

        steps = [
            f"1. Navigate to: {url}",
            f"2. Inject the following payload in the '{param}' parameter:",
            f"   ```\n   {payload}\n   ```",
            f"3. Observe the response:",
            f"   ```\n   {evidence[:300]}\n   ```",
            f"4. This confirms the {vuln_type} vulnerability.",
        ]

        sev_info = SEVERITY_MAP.get(severity, SEVERITY_MAP["medium"])

        return {
            "platform": platform,
            "title": title,
            "severity": sev_info.get("hackerone", severity),
            "cvss_range": sev_info.get("cvss_range", ""),
            "estimated_bounty": sev_info.get("bounty_range", ""),
            "description": template.get("impact", "Security vulnerability discovered."),
            "steps_to_reproduce": "\n".join(steps),
            "impact": template.get("impact", ""),
            "remediation": template.get("remediation", "Apply security patches."),
            "references": template.get("references", []),
            "proof_of_concept": {
                "url": url, "parameter": param,
                "payload": payload, "evidence": evidence[:500],
            },
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    @staticmethod
    def generate_markdown(finding: Dict[str, Any]) -> str:
        r = BountyReportGenerator.generate(finding)
        return f"""# {r['title']}

**Severity:** {r['severity'].upper()} ({r['cvss_range']})
**Estimated Bounty:** {r['estimated_bounty']}

## Description

{r['description']}

## Steps to Reproduce

{r['steps_to_reproduce']}

## Impact

{r['impact']}

## Remediation

{r['remediation']}

## Proof of Concept

- **URL:** `{r['proof_of_concept']['url']}`
- **Parameter:** `{r['proof_of_concept']['parameter']}`
- **Payload:** `{r['proof_of_concept']['payload']}`

## References

{chr(10).join(f'- {ref}' for ref in r['references'])}

---
*Generated by Hellcat v1.1*
"""

    @staticmethod
    def batch_generate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [BountyReportGenerator.generate(f) for f in findings if f.get("vulnerable", True)]
