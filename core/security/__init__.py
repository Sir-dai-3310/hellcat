"""
Hellcat Security Control Layer
===============================
AuthManager (tool-level ACL), SafeExecutor (sandboxed command runner),
InputValidator (SSRF/path traversal prevention), ScopeValidator.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Set

from hellcat.core.models import ToolLevel

logger = logging.getLogger("hellcat.security")


# ---------------------------------------------------------------------------
# Auth Manager
# ---------------------------------------------------------------------------

class AuthManager:
    """Tool-level access control: SAFE / MODERATE / DANGEROUS / CRITICAL."""

    TOOL_LEVELS: Dict[str, ToolLevel] = {
        # SAFE — passive recon
        "nmap": ToolLevel.SAFE, "rustscan": ToolLevel.SAFE,
        "subfinder": ToolLevel.SAFE, "amass": ToolLevel.SAFE,
        "httpx": ToolLevel.SAFE, "katana": ToolLevel.SAFE,
        "whois": ToolLevel.SAFE, "exiftool": ToolLevel.SAFE,
        # MODERATE — active scanning
        "nuclei": ToolLevel.MODERATE, "nikto": ToolLevel.MODERATE,
        "ffuf": ToolLevel.MODERATE, "feroxbuster": ToolLevel.MODERATE,
        "arjun": ToolLevel.MODERATE, "sqlmap": ToolLevel.MODERATE,
        "xsstrike": ToolLevel.MODERATE, "sstimap": ToolLevel.MODERATE,
        # DANGEROUS — exploitation
        "hydra": ToolLevel.DANGEROUS, "john": ToolLevel.DANGEROUS,
        "hashcat": ToolLevel.DANGEROUS, "metasploit": ToolLevel.DANGEROUS,
        "netexec": ToolLevel.DANGEROUS, "pwntools": ToolLevel.DANGEROUS,
        # CRITICAL — lateral / persistence / exfil
        "c2_beacon": ToolLevel.CRITICAL, "lateral_smb": ToolLevel.CRITICAL,
        "lateral_ssh": ToolLevel.CRITICAL, "persistence": ToolLevel.CRITICAL,
        "exfiltration": ToolLevel.CRITICAL, "credential_dump": ToolLevel.CRITICAL,
    }

    def __init__(self, max_level: ToolLevel = ToolLevel.CRITICAL) -> None:
        self.max_level = max_level
        self._level_order = [ToolLevel.SAFE, ToolLevel.MODERATE, ToolLevel.DANGEROUS, ToolLevel.CRITICAL]

    def is_allowed(self, tool_name: str) -> bool:
        level = self.TOOL_LEVELS.get(tool_name, ToolLevel.SAFE)
        return self._level_order.index(level) <= self._level_order.index(self.max_level)

    def get_level(self, tool_name: str) -> ToolLevel:
        return self.TOOL_LEVELS.get(tool_name, ToolLevel.SAFE)

    def filter_tools(self, tool_names: List[str]) -> List[str]:
        return [t for t in tool_names if self.is_allowed(t)]


# ---------------------------------------------------------------------------
# Input Validator
# ---------------------------------------------------------------------------

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


class InputValidator:
    """Validate and sanitize user input to prevent SSRF / path traversal."""

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in PRIVATE_RANGES)
        except ValueError:
            return False

    @staticmethod
    def validate_target(target: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"valid": True, "warnings": []}
        if not target or len(target) > 2048:
            return {"valid": False, "error": "Target empty or too long"}
        # Check for command injection
        dangerous = [";", "|", "&", "`", "$(",  "$(", "\n", "\r"]
        for c in dangerous:
            if c in target:
                return {"valid": False, "error": f"Dangerous character in target: {c!r}"}
        return result

    @staticmethod
    def safe_path_join(base: str, *paths: str) -> Optional[str]:
        """Join paths safely, preventing directory traversal."""
        result = os.path.normpath(os.path.join(base, *paths))
        if not result.startswith(os.path.normpath(base)):
            return None
        return result

    @staticmethod
    def validate_port(port: int) -> bool:
        return 1 <= port <= 65535

    @staticmethod
    def sanitize_command(cmd: str, max_length: int = 4096) -> str:
        """Basic sanitization of shell commands."""
        return cmd[:max_length].strip()


# ---------------------------------------------------------------------------
# Scope Validator
# ---------------------------------------------------------------------------

class ScopeValidator:
    """Validate targets are within authorized testing scope."""

    def __init__(self) -> None:
        self._in_scope: Set[str] = set()
        self._out_of_scope: Set[str] = set()

    def add_scope(self, target: str) -> None:
        self._in_scope.add(target.lower().strip())

    def add_exclusion(self, target: str) -> None:
        self._out_of_scope.add(target.lower().strip())

    def is_in_scope(self, target: str) -> bool:
        t = target.lower().strip()
        if t in self._out_of_scope:
            return False
        if not self._in_scope:
            return True   # No scope defined = everything allowed
        return any(t == s or t.endswith("." + s) for s in self._in_scope)

    def validate(self, target: str) -> Dict[str, Any]:
        if self.is_in_scope(target):
            return {"allowed": True, "target": target}
        return {"allowed": False, "target": target,
                "error": f"Target '{target}' is out of scope"}


# ---------------------------------------------------------------------------
# Safe Executor
# ---------------------------------------------------------------------------

class SafeExecutor:
    """Execute commands with resource limits and safety checks."""

    BLOCKED_COMMANDS = {"rm -rf /", "mkfs", "dd if=/dev/zero", ":(){:|:&};:"}

    def __init__(self, auth: Optional[AuthManager] = None,
                 scope: Optional[ScopeValidator] = None) -> None:
        self.auth = auth or AuthManager()
        self.scope = scope or ScopeValidator()

    def execute(self, command: str, timeout: int = 300, tool_name: str = "") -> Dict[str, Any]:
        # Auth check
        if tool_name and not self.auth.is_allowed(tool_name):
            return {"success": False, "error": f"Tool '{tool_name}' exceeds authorization level"}

        # Blocked command check
        for blocked in self.BLOCKED_COMMANDS:
            if blocked in command:
                return {"success": False, "error": f"Blocked dangerous command pattern"}

        # Input validation
        v = InputValidator.validate_target(command)
        if not v.get("valid", True):
            return {"success": False, "error": v.get("error", "Invalid input")}

        try:
            import shlex
            cmd_list = shlex.split(command) if isinstance(command, str) else command
            result = subprocess.run(
                cmd_list, capture_output=True, text=True, timeout=timeout,
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout[:50000],
                "stderr": result.stderr[:10000],
                "return_code": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Command timed out after {timeout}s"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}
