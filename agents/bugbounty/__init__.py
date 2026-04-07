"""
Hellcat Bug Bounty Workflow Manager
====================================
5-phase automated hunting: subdomain enum -> HTTP discovery -> content
discovery -> parameter discovery -> vulnerability hunting.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class BugBountyTarget:
    """Bug bounty program target definition."""
    domain: str = ""
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    program_type: str = "web"
    priority_vulns: List[str] = field(default_factory=lambda: ["rce", "sqli", "xss", "idor", "ssrf"])


PHASE_DEFINITIONS = [
    {
        "name": "subdomain_enum",
        "description": "Subdomain enumeration",
        "tools": [
            {"tool": "amass", "args": ["enum", "-d", "{domain}"], "timeout": 300},
            {"tool": "subfinder", "args": ["-d", "{domain}", "-silent"], "timeout": 120},
        ],
    },
    {
        "name": "http_discovery",
        "description": "HTTP service probing & tech detection",
        "tools": [
            {"tool": "httpx", "args": ["-l", "{subdomains_file}", "-sc", "-td"], "timeout": 180},
        ],
    },
    {
        "name": "content_discovery",
        "description": "Directory/file/endpoint discovery",
        "tools": [
            {"tool": "katana", "args": ["-u", "{target}", "-d", "3", "-jc"], "timeout": 600},
            {"tool": "ffuf", "args": ["-u", "{target}/FUZZ", "-w", "{wordlist}", "-mc", "200,301,302,403"], "timeout": 300},
        ],
    },
    {
        "name": "parameter_discovery",
        "description": "Hidden parameter enumeration",
        "tools": [
            {"tool": "arjun", "args": ["-u", "{target}"], "timeout": 240},
        ],
    },
    {
        "name": "vulnerability_hunting",
        "description": "Active vulnerability testing",
        "tools": [
            {"tool": "nuclei", "args": ["-u", "{target}", "-severity", "critical,high"], "timeout": 600},
            {"tool": "sqlmap", "args": ["-u", "{target}", "--batch", "--level=3"], "timeout": 300},
            {"tool": "xsstrike", "args": ["-u", "{target}"], "timeout": 180},
        ],
    },
]


class BugBountyWorkflowManager:
    """Generate and manage bug bounty hunting workflows."""

    @staticmethod
    def create_workflow(target: BugBountyTarget) -> Dict[str, Any]:
        phases = []
        for p in PHASE_DEFINITIONS:
            steps = []
            for tool_def in p["tools"]:
                args = [a.replace("{domain}", target.domain).replace("{target}", f"https://{target.domain}")
                        for a in tool_def["args"]]
                steps.append({"tool": tool_def["tool"], "args": args, "timeout": tool_def["timeout"]})
            phases.append({"name": p["name"], "description": p["description"], "steps": steps})
        return {
            "target": target.domain,
            "phases": phases,
            "total_phases": len(phases),
            "priority_vulns": target.priority_vulns,
            "estimated_time_minutes": sum(
                sum(s["timeout"] for s in p["steps"]) for p in phases
            ) // 60,
        }

    @staticmethod
    def create_recon_only(domain: str) -> Dict[str, Any]:
        target = BugBountyTarget(domain=domain)
        wf = BugBountyWorkflowManager.create_workflow(target)
        wf["phases"] = wf["phases"][:3]  # Only recon phases
        wf["total_phases"] = 3
        return wf

    @staticmethod
    def list_phases() -> List[str]:
        return [p["name"] for p in PHASE_DEFINITIONS]
