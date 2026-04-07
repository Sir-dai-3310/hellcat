"""
Hellcat Kali 2026.1 Adapter
=============================
Environment detection, auto-installer, tool availability checker,
kernel 6.18 feature adaptation.
"""
from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from hellcat.core.tools import TOOL_REGISTRY

logger = logging.getLogger("hellcat.kali")


class KaliAdapter:
    """Detect Kali environment and manage tool installation."""

    KALI_2026_NEW_TOOLS = [
        "adaptixc2", "atomic_operator", "fluxion", "gef",
        "metasploit_mcp", "sstimap", "wpprobe", "xsstrike",
    ]

    @staticmethod
    def is_kali() -> bool:
        try:
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release") as f:
                    return "kali" in f.read().lower()
        except Exception:
            pass
        return "kali" in platform.platform().lower()

    @staticmethod
    def kali_version() -> str:
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("VERSION="):
                        return line.split("=")[1].strip().strip('"')
        except Exception:
            pass
        return "unknown"

    @staticmethod
    def kernel_version() -> str:
        return platform.release()

    @staticmethod
    def check_tools() -> Dict[str, Any]:
        available, missing = [], []
        for name, td in TOOL_REGISTRY.items():
            if shutil.which(td.binary):
                available.append(name)
            else:
                missing.append(name)
        return {"available": available, "missing": missing,
                "total": len(TOOL_REGISTRY)}

    @staticmethod
    def generate_install_script(tools: Optional[List[str]] = None) -> str:
        """Generate apt install command for missing tools."""
        if tools is None:
            check = KaliAdapter.check_tools()
            tools = check["missing"]
        packages = []
        for t in tools:
            td = TOOL_REGISTRY.get(t)
            if td and td.kali_package:
                packages.append(td.kali_package)
        if not packages:
            return "# All tools already installed"
        return f"sudo apt update && sudo apt install -y {' '.join(sorted(set(packages)))}"

    @staticmethod
    def auto_install(dry_run: bool = True) -> Dict[str, Any]:
        """Install missing tools via apt (Kali only)."""
        if not KaliAdapter.is_kali() and not dry_run:
            return {"success": False, "error": "Not running on Kali Linux"}
        check = KaliAdapter.check_tools()
        cmd = KaliAdapter.generate_install_script(check["missing"])
        if dry_run:
            return {"dry_run": True, "command": cmd, "missing": len(check["missing"])}
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True,
                                    text=True, timeout=600)
            return {"success": result.returncode == 0, "stdout": result.stdout[-2000:],
                    "stderr": result.stderr[-1000:]}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    @staticmethod
    def check_2026_features() -> Dict[str, Any]:
        """Check Kali 2026.1 specific features."""
        kernel = KaliAdapter.kernel_version()
        new_tools_available = [t for t in KaliAdapter.KALI_2026_NEW_TOOLS
                               if shutil.which(TOOL_REGISTRY.get(t, type("", (), {"binary": t})).binary if TOOL_REGISTRY.get(t) else t)]
        return {
            "is_kali": KaliAdapter.is_kali(),
            "version": KaliAdapter.kali_version(),
            "kernel": kernel,
            "kernel_6_18": kernel.startswith("6.18"),
            "new_tools_available": new_tools_available,
            "new_tools_missing": [t for t in KaliAdapter.KALI_2026_NEW_TOOLS if t not in new_tools_available],
        }

    @staticmethod
    def full_report() -> Dict[str, Any]:
        tools = KaliAdapter.check_tools()
        features = KaliAdapter.check_2026_features()
        return {
            "environment": features,
            "tools": {
                "available": len(tools["available"]),
                "missing": len(tools["missing"]),
                "total": tools["total"],
            },
            "install_cmd": KaliAdapter.generate_install_script(),
        }
