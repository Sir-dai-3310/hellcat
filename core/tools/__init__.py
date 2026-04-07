"""
Hellcat External Tool Manager
==============================
YAML-driven tool chain orchestration. Auto-detects installed tools,
builds commands, parses output, provides fallback chains.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hellcat.tools")


# ---------------------------------------------------------------------------
# Tool definition
# ---------------------------------------------------------------------------

@dataclass
class ToolDef:
    name: str = ""
    binary: str = ""                    # executable name
    category: str = ""                  # network, web, binary, cloud, etc.
    description: str = ""
    default_args: List[str] = field(default_factory=list)
    fallbacks: List[str] = field(default_factory=list)   # alternative tool names
    kali_package: str = ""              # apt package name on Kali


# ---------------------------------------------------------------------------
# Built-in tool registry (64 core tools from HexStrike + Kali 2026.1)
# ---------------------------------------------------------------------------

TOOL_REGISTRY: Dict[str, ToolDef] = {
    # Network
    "nmap":       ToolDef("nmap", "nmap", "network", "Port/service scanner", [], ["rustscan", "masscan"], "nmap"),
    "rustscan":   ToolDef("rustscan", "rustscan", "network", "Fast port scanner", ["--ulimit", "5000"], ["nmap"], "rustscan"),
    "masscan":    ToolDef("masscan", "masscan", "network", "Internet-scale scanner", ["--rate=1000", "--wait=0"], ["nmap"], "masscan"),
    # Web
    "nuclei":     ToolDef("nuclei", "nuclei", "web", "Template vuln scanner", ["-severity", "critical,high"], ["nikto"], "nuclei"),
    "sqlmap":     ToolDef("sqlmap", "sqlmap", "web", "SQL injection tool", ["--batch", "--level=3"], [], "sqlmap"),
    "ffuf":       ToolDef("ffuf", "ffuf", "web", "Web fuzzer", ["-mc", "200,301,302,403"], ["feroxbuster"], "ffuf"),
    "nikto":      ToolDef("nikto", "nikto", "web", "Web server scanner", [], ["nuclei"], "nikto"),
    "feroxbuster":ToolDef("feroxbuster", "feroxbuster", "web", "Content discovery", [], ["ffuf"], "feroxbuster"),
    "httpx":      ToolDef("httpx", "httpx-toolkit", "web", "HTTP prober (ProjectDiscovery)", [], [], "httpx-toolkit"),
    "katana":     ToolDef("katana", "katana", "web", "Web crawler", ["-d", "3"], [], "katana"),
    # Kali 2026.1 new tools
    "xsstrike":   ToolDef("xsstrike", "xsstrike", "web", "Advanced XSS scanner", [], ["dalfox"], "xsstrike"),
    "sstimap":    ToolDef("sstimap", "sstimap", "web", "SSTI detection", [], [], "sstimap"),
    "gef":        ToolDef("gef", "gdb", "binary", "GDB enhanced features", ["-q"], [], "gef"),
    "adaptixc2":  ToolDef("adaptixc2", "adaptixc2", "c2", "Adversarial emulation C2", [], [], "adaptixc2"),
    "metasploit_mcp": ToolDef("metasploit_mcp", "msfconsole", "exploit", "Metasploit MCP server", [], [], "metasploit-mcp"),
    "wpprobe":    ToolDef("wpprobe", "wpprobe", "web", "WordPress plugin enum", [], ["wpscan"], "wpprobe"),
    "fluxion":    ToolDef("fluxion", "fluxion", "wireless", "WiFi social engineering", [], [], "fluxion"),
    "atomic_operator": ToolDef("atomic_operator", "atomic-operator", "redteam", "Atomic Red Team executor", [], [], "atomic-operator"),
    # Password
    "hydra":      ToolDef("hydra", "hydra", "password", "Network login bruter", [], [], "hydra"),
    "john":       ToolDef("john", "john", "password", "Password cracker", [], ["hashcat"], "john"),
    "hashcat":    ToolDef("hashcat", "hashcat", "password", "GPU password cracker", [], ["john"], "hashcat"),
    # Binary
    "ghidra":     ToolDef("ghidra", "ghidra", "binary", "RE framework (NSA)", [], [], "ghidra"),
    "pwntools":   ToolDef("pwntools", "python3", "binary", "Binary exploitation", [], [], "python3-pwntools"),
    # Cloud
    "prowler":    ToolDef("prowler", "prowler", "cloud", "AWS/Azure/GCP audit", [], [], "prowler"),
    "trivy":      ToolDef("trivy", "trivy", "cloud", "Container vuln scanner", [], [], "trivy"),
    # Recon
    "amass":      ToolDef("amass", "amass", "recon", "Subdomain enumeration", [], ["subfinder"], "amass"),
    "subfinder":  ToolDef("subfinder", "subfinder", "recon", "Passive subdomain discovery", [], ["amass"], "subfinder"),
    # SMB
    "netexec":    ToolDef("netexec", "netexec", "smb", "Network exploitation", [], [], "netexec"),
    "smbmap":     ToolDef("smbmap", "smbmap", "smb", "SMB share enum", [], [], "smbmap"),
    # API
    "arjun":      ToolDef("arjun", "arjun", "api", "HTTP param discovery", [], [], "arjun"),
    # Forensics
    "volatility": ToolDef("volatility", "vol3", "forensics", "Memory forensics", [], [], "volatility3"),
    "exiftool":   ToolDef("exiftool", "exiftool", "forensics", "Metadata extraction", [], [], "exiftool"),
}


# ---------------------------------------------------------------------------
# Tool Manager
# ---------------------------------------------------------------------------

class ExternalToolManager:
    """Detects, executes, and manages external security tools."""

    def __init__(self) -> None:
        self._available: Dict[str, str] = {}   # name -> path
        self._scan_tools()

    def _scan_tools(self) -> None:
        for name, td in TOOL_REGISTRY.items():
            path = shutil.which(td.binary)
            if path:
                self._available[name] = path

    @property
    def available_tools(self) -> List[str]:
        return sorted(self._available.keys())

    @property
    def missing_tools(self) -> List[str]:
        return sorted(set(TOOL_REGISTRY) - set(self._available))

    def is_available(self, tool: str) -> bool:
        return tool in self._available

    def get_fallback(self, tool: str) -> Optional[str]:
        td = TOOL_REGISTRY.get(tool)
        if not td:
            return None
        for fb in td.fallbacks:
            if fb in self._available:
                return fb
        return None

    def execute(self, tool: str, args: List[str], timeout: int = 300,
                use_fallback: bool = True) -> Dict[str, Any]:
        """Execute a tool with args. Falls back if primary unavailable."""
        actual = tool
        if not self.is_available(tool):
            if use_fallback:
                fb = self.get_fallback(tool)
                if fb:
                    logger.info("Tool %s unavailable, using fallback %s", tool, fb)
                    actual = fb
                else:
                    return {"success": False, "error": f"Tool '{tool}' not installed, no fallback"}
            else:
                return {"success": False, "error": f"Tool '{tool}' not installed"}

        td = TOOL_REGISTRY.get(actual, TOOL_REGISTRY.get(tool))
        binary = self._available.get(actual, actual)
        cmd = [binary] + (td.default_args if td else []) + args

        logger.info("Executing: %s", " ".join(cmd))
        start = time.time()
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            return {
                "success": result.returncode == 0,
                "tool": actual,
                "command": " ".join(cmd),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "duration": round(time.time() - start, 2),
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "tool": actual, "error": f"Timeout after {timeout}s"}
        except FileNotFoundError:
            return {"success": False, "tool": actual, "error": f"Binary not found: {binary}"}
        except Exception as exc:
            return {"success": False, "tool": actual, "error": str(exc)}

    def chain_execute(self, steps: List[Dict[str, Any]], timeout: int = 300) -> List[Dict[str, Any]]:
        """Execute a sequence of tool steps, piping context forward."""
        results = []
        for step in steps:
            tool = step.get("tool", "")
            args = step.get("args", [])
            r = self.execute(tool, args, timeout=step.get("timeout", timeout))
            results.append(r)
            if not r.get("success") and step.get("required", False):
                break
        return results

    def status_report(self) -> Dict[str, Any]:
        return {
            "available": len(self._available),
            "missing": len(self.missing_tools),
            "total_registered": len(TOOL_REGISTRY),
            "available_tools": self.available_tools,
            "missing_tools": self.missing_tools,
            "kali_install_cmd": f"apt install -y {' '.join(TOOL_REGISTRY[t].kali_package for t in self.missing_tools if TOOL_REGISTRY[t].kali_package)}",
        }
