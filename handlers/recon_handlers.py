"""Hellcat Recon Handler — MCP tools for reconnaissance."""
from __future__ import annotations
import logging
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from fastmcp import FastMCP
    from hellcat.hellcat_mcp import ToolCounter

def register_recon_tools(mcp: FastMCP, counter: ToolCounter, logger: logging.Logger) -> None:
    @mcp.tool()
    def full_recon(target: str, quick_mode: bool = False) -> dict:
        """Run full 10-phase reconnaissance against target."""
        from hellcat.core.ai.intelligence import HellcatIntelligence
        return HellcatIntelligence().assess(target, {"quick_mode": quick_mode})

    @mcp.tool()
    def port_scan(target: str, ports: str = "1-1000", scan_type: str = "-sV") -> dict:
        """Scan ports on target using nmap/rustscan."""
        from hellcat.core.tools import ExternalToolManager
        return ExternalToolManager().execute("nmap", [scan_type, "-p", ports, target], timeout=120)

    @mcp.tool()
    def subdomain_enum(domain: str) -> dict:
        """Enumerate subdomains using subfinder."""
        from hellcat.core.tools import ExternalToolManager
        return ExternalToolManager().execute("subfinder", ["-d", domain, "-silent", "-timeout", "30"], timeout=120)

    @mcp.tool()
    def tech_detect(target: str) -> dict:
        """Detect technology stack of target using httpx-toolkit.
        Example: tech_detect(target="http://127.0.0.1:8888")"""
        import subprocess
        try:
            proc = subprocess.run(
                f'echo "{target}" | httpx-toolkit -sc -title -td -server -silent',
                shell=True, capture_output=True, text=True, timeout=30,
            )
            output = proc.stdout.strip()
            return {"success": bool(output), "tool": "httpx-toolkit",
                    "stdout": output or "(no response)", "stderr": proc.stderr.strip()[:200]}
        except FileNotFoundError:
            return {"success": False, "error": "httpx-toolkit not installed. Run: apt install httpx-toolkit"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    counter.add("recon", 4)
