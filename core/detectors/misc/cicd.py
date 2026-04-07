"""
Hellcat CI/CD Security Scanner
================================
Detect GitHub Actions workflow misconfigurations.
Inspired by hackerbrot-claw's 9-class vulnerability pattern index.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List


CICD_PATTERNS = [
    {"id": "pwn_request", "severity": "critical",
     "desc": "pull_request_target with checkout of PR code — allows arbitrary code execution",
     "regex": r"pull_request_target.*\n.*checkout.*\$\{\{.*github\.event\.pull_request"},
    {"id": "script_injection", "severity": "critical",
     "desc": "Unsanitized github context in run step — command injection",
     "regex": r"run:.*\$\{\{\s*github\.event\.(issue|pull_request|comment)\.(title|body|label)"},
    {"id": "artifact_poisoning", "severity": "high",
     "desc": "Downloading artifacts from untrusted workflows without verification",
     "regex": r"actions/download-artifact.*\n.*(?:unzip|tar|extract)"},
    {"id": "excessive_permissions", "severity": "high",
     "desc": "Workflow with write-all permissions",
     "regex": r"permissions:\s*write-all|permissions:\s*\n\s+contents:\s*write"},
    {"id": "secret_in_log", "severity": "high",
     "desc": "Potential secret exposure in logs via echo/print",
     "regex": r"echo\s+.*\$\{\{\s*secrets\."},
    {"id": "unpinned_action", "severity": "medium",
     "desc": "Using action without pinned SHA (supply chain risk)",
     "regex": r"uses:\s+[^@]+@(?:main|master|latest|v\d+)\s"},
    {"id": "self_hosted_runner", "severity": "medium",
     "desc": "Self-hosted runner on public repo (persistence risk)",
     "regex": r"runs-on:\s*self-hosted"},
    {"id": "oidc_miscfg", "severity": "high",
     "desc": "OIDC token request without audience restriction",
     "regex": r"id-token:\s*write(?!\s*\n\s*#\s*audience)"},
    {"id": "env_injection", "severity": "high",
     "desc": "Writing untrusted input to GITHUB_ENV",
     "regex": r"echo.*\$\{\{.*\}\}.*>>.*GITHUB_ENV"},
]


class CICDScanner:
    """Scan CI/CD workflow files for security misconfigs."""

    def scan_text(self, content: str, filename: str = "") -> List[Dict[str, Any]]:
        findings = []
        for pattern in CICD_PATTERNS:
            for m in re.finditer(pattern["regex"], content, re.MULTILINE | re.IGNORECASE):
                line_num = content[:m.start()].count("\n") + 1
                findings.append({
                    "rule": pattern["id"],
                    "severity": pattern["severity"],
                    "description": pattern["desc"],
                    "file": filename,
                    "line": line_num,
                    "match": m.group(0)[:100],
                })
        return findings

    def scan_url(self, repo_url: str) -> List[Dict[str, Any]]:
        """Scan GitHub repo workflows via raw URL."""
        all_findings = []
        workflow_paths = [".github/workflows/ci.yml", ".github/workflows/build.yml",
                          ".github/workflows/release.yml", ".github/workflows/test.yml",
                          ".github/workflows/deploy.yml", ".github/workflows/main.yml"]
        for wf in workflow_paths:
            raw_url = repo_url.replace("github.com", "raw.githubusercontent.com") + f"/main/{wf}"
            try:
                import requests
                resp = requests.get(raw_url, timeout=8)
                if resp.status_code == 200:
                    all_findings.extend(self.scan_text(resp.text, wf))
            except Exception:
                pass
        return all_findings

    def scan_file(self, path: str) -> List[Dict[str, Any]]:
        try:
            with open(path) as f:
                return self.scan_text(f.read(), path)
        except Exception:
            return []

    @staticmethod
    def list_rules() -> List[Dict[str, str]]:
        return [{"id": p["id"], "severity": p["severity"], "desc": p["desc"]}
                for p in CICD_PATTERNS]
