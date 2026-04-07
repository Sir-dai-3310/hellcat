"""
Hellcat Secret Scanner
=======================
Detect leaked credentials, API keys, tokens, and passwords in:
- Web page source (HTML/JS)
- HTTP responses
- Git repositories
- Config files
Inspired by gitleaks/trufflehog/reconFTW leak detection.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hellcat.secrets")


@dataclass
class SecretFinding:
    rule_id: str = ""
    description: str = ""
    match: str = ""
    location: str = ""  # URL, file path, or context
    severity: str = "high"
    line: int = 0
    context: str = ""   # surrounding text

    def to_dict(self) -> Dict[str, Any]:
        return {"rule_id": self.rule_id, "description": self.description,
                "match": self.match[:100] + "..." if len(self.match) > 100 else self.match,
                "location": self.location, "severity": self.severity}


# ---------------------------------------------------------------------------
# Detection rules (regex-based, inspired by gitleaks/trufflehog)
# ---------------------------------------------------------------------------

SECRET_RULES: List[Dict[str, Any]] = [
    # AWS
    {"id": "aws_access_key", "desc": "AWS Access Key ID",
     "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "severity": "critical"},
    {"id": "aws_secret_key", "desc": "AWS Secret Access Key",
     "regex": r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", "severity": "critical"},
    # Google
    {"id": "gcp_api_key", "desc": "Google API Key",
     "regex": r"AIza[0-9A-Za-z_-]{35}", "severity": "high"},
    {"id": "gcp_service_account", "desc": "GCP Service Account Key",
     "regex": r'"type"\s*:\s*"service_account"', "severity": "critical"},
    # GitHub
    {"id": "github_token", "desc": "GitHub Personal Access Token",
     "regex": r"gh[pousr]_[A-Za-z0-9_]{36,255}", "severity": "critical"},
    {"id": "github_classic", "desc": "GitHub Classic Token",
     "regex": r"github_pat_[A-Za-z0-9_]{22,255}", "severity": "critical"},
    # Slack
    {"id": "slack_token", "desc": "Slack Bot/User Token",
     "regex": r"xox[bporas]-[0-9]+-[0-9]+-[A-Za-z0-9]+", "severity": "high"},
    {"id": "slack_webhook", "desc": "Slack Webhook URL",
     "regex": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "severity": "medium"},
    # JWT
    {"id": "jwt_token", "desc": "JSON Web Token",
     "regex": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "severity": "medium"},
    # Private Keys
    {"id": "private_key_rsa", "desc": "RSA Private Key",
     "regex": r"-----BEGIN RSA PRIVATE KEY-----", "severity": "critical"},
    {"id": "private_key_generic", "desc": "Private Key (Generic)",
     "regex": r"-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----", "severity": "critical"},
    # Database
    {"id": "mysql_conn", "desc": "MySQL Connection String",
     "regex": r"mysql://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", "severity": "critical"},
    {"id": "postgres_conn", "desc": "PostgreSQL Connection String",
     "regex": r"postgres(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", "severity": "critical"},
    {"id": "mongodb_conn", "desc": "MongoDB Connection String",
     "regex": r"mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", "severity": "critical"},
    # Generic
    {"id": "password_assign", "desc": "Hardcoded Password Assignment",
     "regex": r"""(?i)(?:password|passwd|pwd|secret|token|apikey|api_key)\s*[=:]\s*['"][^'"]{8,}['"]""", "severity": "high"},
    {"id": "bearer_token", "desc": "Bearer Token in Code",
     "regex": r"""(?i)(?:authorization|bearer)\s*[=:]\s*['"]Bearer\s+[A-Za-z0-9._-]+['"]""", "severity": "high"},
    # Cloud / SaaS
    {"id": "stripe_key", "desc": "Stripe API Key",
     "regex": r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,}", "severity": "critical"},
    {"id": "twilio_key", "desc": "Twilio API Key",
     "regex": r"SK[0-9a-fA-F]{32}", "severity": "high"},
    {"id": "sendgrid_key", "desc": "SendGrid API Key",
     "regex": r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}", "severity": "high"},
    {"id": "mailgun_key", "desc": "Mailgun API Key",
     "regex": r"key-[0-9a-zA-Z]{32}", "severity": "high"},
    # Interesting endpoints/files
    {"id": "env_file", "desc": "Exposed .env file reference",
     "regex": r"""(?:href|src|action)\s*=\s*['"][^'"]*\.env['"]""", "severity": "medium"},
    {"id": "debug_endpoint", "desc": "Debug/Admin Endpoint",
     "regex": r"""(?:href|src|action)\s*=\s*['"][^'"]*(?:/debug|/admin|/phpinfo|/elmah|/trace)['"]""", "severity": "medium"},
]


class SecretScanner:
    """Scan text for leaked secrets and credentials."""

    def __init__(self, custom_rules: Optional[List[Dict]] = None) -> None:
        self._rules = list(SECRET_RULES)
        if custom_rules:
            self._rules.extend(custom_rules)
        self._compiled = [(r, re.compile(r["regex"])) for r in self._rules]

    def scan_text(self, text: str, location: str = "") -> List[SecretFinding]:
        findings = []
        for rule, pattern in self._compiled:
            for m in pattern.finditer(text):
                start = max(0, m.start() - 30)
                end = min(len(text), m.end() + 30)
                findings.append(SecretFinding(
                    rule_id=rule["id"], description=rule["desc"],
                    match=m.group(0), location=location,
                    severity=rule["severity"],
                    context=text[start:end].replace("\n", " ").strip(),
                ))
        return findings

    def scan_url(self, url: str) -> List[SecretFinding]:
        """Fetch URL and scan response for secrets."""
        try:
            import requests
            resp = requests.get(url, timeout=10, verify=False)
            findings = self.scan_text(resp.text, location=url)
            # Also scan response headers
            header_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            findings.extend(self.scan_text(header_text, location=f"{url} [headers]"))
            return findings
        except Exception as exc:
            logger.warning("Secret scan failed for %s: %s", url, exc)
            return []

    def scan_js_files(self, base_url: str, js_urls: List[str]) -> List[SecretFinding]:
        """Scan JavaScript files for embedded secrets."""
        all_findings = []
        for js_url in js_urls:
            if not js_url.startswith("http"):
                from urllib.parse import urljoin
                js_url = urljoin(base_url, js_url)
            all_findings.extend(self.scan_url(js_url))
        return all_findings

    def scan_file(self, file_path: str) -> List[SecretFinding]:
        """Scan local file for secrets."""
        try:
            with open(file_path, "r", errors="replace") as f:
                return self.scan_text(f.read(), location=file_path)
        except Exception:
            return []

    @staticmethod
    def list_rules() -> List[Dict[str, str]]:
        return [{"id": r["id"], "desc": r["desc"], "severity": r["severity"]}
                for r in SECRET_RULES]

    @staticmethod
    def stats() -> Dict[str, Any]:
        sev = {}
        for r in SECRET_RULES:
            sev[r["severity"]] = sev.get(r["severity"], 0) + 1
        return {"total_rules": len(SECRET_RULES), "by_severity": sev}
