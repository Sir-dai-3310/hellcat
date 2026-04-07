"""
Hellcat AI Nuclei Template Generator
=====================================
Generate Nuclei YAML detection templates from CVE descriptions.
Inspired by projectdiscovery/nuclei-templates-ai.
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("hellcat.nuclei_gen")

NUCLEI_TEMPLATE = '''id: {cve_id_lower}

info:
  name: {name}
  author: hellcat-ai
  severity: {severity}
  description: |
    {description}
  reference:
    - https://nvd.nist.gov/vuln/detail/{cve_id}
  classification:
    cvss-score: {cvss}
    cve-id: {cve_id}
  tags: {tags}

http:
  - method: {method}
    path:
{paths}
    matchers-condition: and
    matchers:
{matchers}
'''


class NucleiTemplateGenerator:
    """Generate Nuclei YAML templates from vulnerability info."""

    @staticmethod
    def from_cve(cve_id: str, description: str, cvss: float = 0.0,
                 affected: str = "", ai_engine: Any = None) -> str:
        """Generate a nuclei template from CVE metadata."""
        desc_lower = description.lower()

        # Auto-detect vuln type and generate appropriate template
        severity = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
        vuln_type = NucleiTemplateGenerator._detect_vuln_type(desc_lower)
        paths = NucleiTemplateGenerator._generate_paths(desc_lower, affected)
        matchers = NucleiTemplateGenerator._generate_matchers(vuln_type, desc_lower)
        tags = f"cve,cve{cve_id.split('-')[1]},{vuln_type}"
        method = "POST" if any(k in desc_lower for k in ("upload", "deserialization", "injection")) else "GET"

        name = f"{cve_id} - {affected}" if affected else cve_id

        template = NUCLEI_TEMPLATE.format(
            cve_id=cve_id, cve_id_lower=cve_id.lower().replace("-", "_"),
            name=name, severity=severity, description=description[:200],
            cvss=cvss, tags=tags, method=method,
            paths="\n".join(f"      - \"{p}\"" for p in paths),
            matchers="\n".join(f"      - {m}" for m in matchers),
        )

        # Optional AI enhancement
        if ai_engine and hasattr(ai_engine, "registry") and ai_engine.registry.active:
            enhanced = ai_engine.registry.complete(
                f"Improve this Nuclei YAML template for {cve_id}:\n{template}\n"
                "Fix any issues and add better matchers. Output ONLY the YAML.",
                system="You are a Nuclei template expert.",
            )
            if "id:" in enhanced and "matchers:" in enhanced:
                return enhanced

        return template

    @staticmethod
    def _detect_vuln_type(desc: str) -> str:
        if any(k in desc for k in ("sql injection", "sqli")):
            return "sqli"
        if any(k in desc for k in ("cross-site scripting", "xss")):
            return "xss"
        if any(k in desc for k in ("remote code execution", "rce", "command injection")):
            return "rce"
        if any(k in desc for k in ("ssrf", "server-side request")):
            return "ssrf"
        if any(k in desc for k in ("path traversal", "directory traversal", "lfi")):
            return "lfi"
        if any(k in desc for k in ("deserialization",)):
            return "deserialization"
        if any(k in desc for k in ("authentication bypass", "auth bypass")):
            return "auth-bypass"
        if any(k in desc for k in ("information disclosure", "information leak")):
            return "info-disclosure"
        return "vulnerability"

    @staticmethod
    def _generate_paths(desc: str, affected: str) -> list:
        paths = ["{{BaseURL}}/"]
        # Extract paths from description
        for m in re.finditer(r'/[\w./-]+', desc):
            path = m.group(0)
            if len(path) > 3:
                paths.append("{{BaseURL}}" + path)
        if not paths[1:]:
            # Common paths based on affected product
            af = affected.lower()
            if "wordpress" in af:
                paths.extend(["{{BaseURL}}/wp-admin/", "{{BaseURL}}/wp-login.php"])
            elif "apache" in af:
                paths.append("{{BaseURL}}/server-status")
            elif "spring" in af:
                paths.append("{{BaseURL}}/actuator")
            else:
                paths.append("{{BaseURL}}/api/")
        return paths[:5]

    @staticmethod
    def _generate_matchers(vuln_type: str, desc: str) -> list:
        base_matchers = ['type: status\n        status:\n          - 200']
        if vuln_type == "sqli":
            base_matchers.append('type: word\n        words:\n          - "SQL syntax"\n          - "mysql_"\n          - "ORA-"\n        condition: or')
        elif vuln_type == "xss":
            base_matchers.append('type: word\n        words:\n          - "<script>"\n        part: body')
        elif vuln_type == "rce":
            base_matchers.append('type: word\n        words:\n          - "uid="\n          - "root:"\n        condition: or')
        elif vuln_type == "lfi":
            base_matchers.append('type: word\n        words:\n          - "root:x:0"\n          - "[extensions]"\n        condition: or')
        elif vuln_type == "auth-bypass":
            base_matchers.append('type: word\n        words:\n          - "admin"\n          - "dashboard"\n        condition: or')
        elif vuln_type == "info-disclosure":
            base_matchers.append('type: regex\n        regex:\n          - "(?i)(password|secret|token|api.?key)"')
        else:
            base_matchers.append('type: word\n        words:\n          - "error"\n        part: body\n        negative: true')
        return base_matchers
