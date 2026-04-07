"""Hellcat CVE + AI + Orchestration + External handlers."""
from __future__ import annotations
import logging
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from fastmcp import FastMCP
    from hellcat.hellcat_mcp import ToolCounter

def register_cve_tools(mcp: FastMCP, counter: ToolCounter, logger: logging.Logger) -> None:
    @mcp.tool()
    def cve_search(query: str) -> dict:
        """Search offline CVE PoC database (10K+ CVEs, 22K+ PoC links).
        Example: cve_search(query="CVE-2025-0108")"""
        from hellcat.agents.cve import CVEIntelligenceManager
        mgr = CVEIntelligenceManager()
        pocs = mgr.poc_lookup(query)
        if pocs:
            return {"cve_id": query, "poc_count": len(pocs), "pocs": pocs[:10], "source": "offline_index"}
        return {"results": mgr.search(query), "source": "nvd_cache"}

    @mcp.tool()
    def cve_auto_exploit(cve_id: str, target: str) -> dict:
        """Auto-exploit a CVE: checks built-in templates → offline PoC index → AI generation.
        Example: cve_auto_exploit(cve_id="CVE-2026-33017", target="http://target.com")"""
        from hellcat.agents.cve import CVEIntelligenceManager
        return CVEIntelligenceManager().auto_exploit(cve_id, target)

    @mcp.tool()
    def cve_match_target(open_ports: str = "", banners: str = "") -> dict:
        """Match known 2026 CVE templates against target fingerprint.
        Example: cve_match_target(open_ports="22,80,443", banners="OpenSSH,Apache")"""
        from hellcat.agents.cve import CVEIntelligenceManager
        ports = [int(p) for p in open_ports.split(",") if p.strip().isdigit()]
        blist = [b.strip() for b in banners.split(",") if b.strip()]
        return {"matches": CVEIntelligenceManager().match_target({"open_ports": ports, "banners": blist})}

    counter.add("cve", 3)

def register_ai_tools(mcp: FastMCP, counter: ToolCounter, logger: logging.Logger) -> None:
    @mcp.tool()
    def smart_analyze(target: str) -> dict:
        """AI-powered target analysis with MCTS attack path planning.
        Returns: tool recommendations, attack chain, risk assessment."""
        from hellcat.core.ai.intelligence import HellcatIntelligence
        return HellcatIntelligence().assess(target)

    @mcp.tool()
    def generate_poc(cve_id: str) -> dict:
        """Find PoC for a CVE. First checks offline DB (instant), then AI generation.
        Example: generate_poc(cve_id="CVE-2025-0108")"""
        from hellcat.agents.cve import CVEIntelligenceManager
        mgr = CVEIntelligenceManager()
        # Fast path: offline PoC lookup
        pocs = mgr.poc_lookup(cve_id)
        if pocs:
            return {"cve_id": cve_id, "status": "found", "poc_count": len(pocs),
                    "pocs": pocs[:5], "source": "offline_index"}
        # Slow path: AI generation (only if provider available)
        from hellcat.core.ai.engine import AIEngine
        engine = AIEngine()
        if engine.registry.active:
            code = engine.generate_poc(cve_id)
            return {"cve_id": cve_id, "status": "ai_generated", "poc_code": code}
        return {"cve_id": cve_id, "status": "not_found",
                "hint": "No offline PoC found. Set OPENAI_API_KEY or ANTHROPIC_API_KEY for AI generation."}

    @mcp.tool()
    def smart_payload(vuln_type: str, waf_detected: bool = False) -> dict:
        """Generate penetration testing payloads for a vulnerability type.
        vuln_type: xss, sqli, ssti, xxe, rce, lfi, cmd_injection
        Example: smart_payload(vuln_type="xss", waf_detected=true)"""
        from hellcat.modules.payload import PayloadGenerator
        if waf_detected:
            payloads = PayloadGenerator.get_waf_bypass(vuln_type)
            if not payloads:
                payloads = PayloadGenerator.get_payloads(vuln_type, "advanced")
            return {"vuln_type": vuln_type, "mode": "waf_bypass", "payloads": payloads, "count": len(payloads)}
        payloads = PayloadGenerator.get_payloads(vuln_type, "advanced", limit=15)
        return {"vuln_type": vuln_type, "mode": "standard", "payloads": payloads, "count": len(payloads)}

    counter.add("ai", 3)

def register_orchestration_tools(mcp: FastMCP, counter: ToolCounter, logger: logging.Logger) -> None:
    @mcp.tool()
    def auto_pentest(target: str, scope: str = "full") -> dict:
        """Full automated penetration test with MCTS planning."""
        from hellcat.core.ai.intelligence import HellcatIntelligence
        iters = 200 if scope == "quick" else 500
        return HellcatIntelligence().assess(target, {"scope": scope, "mcts_iterations": iters})

    @mcp.tool()
    def attack_chain_plan(target: str) -> dict:
        """Generate MCTS-optimized attack chain for a target."""
        from hellcat.core.ai.intelligence import HellcatIntelligence
        from hellcat.core.models import AttackState
        state = AttackState(target=target)
        return HellcatIntelligence().plan_attack(state, iterations=200)

    counter.add("orchestration", 2)

def register_external_tools(mcp: FastMCP, counter: ToolCounter, logger: logging.Logger) -> None:
    @mcp.tool()
    def ext_nmap_scan(target: str, args: str = "-sV -T4") -> dict:
        """Run nmap with custom arguments. Timeout: 120s.
        Example: ext_nmap_scan(target="10.0.0.1", args="-sV -p 1-1000")"""
        from hellcat.core.tools import ExternalToolManager
        return ExternalToolManager().execute("nmap", args.split() + [target], timeout=120)

    @mcp.tool()
    def ext_nuclei_scan(target: str, severity: str = "critical,high") -> dict:
        """Run nuclei template scanner. Timeout: 300s.
        Example: ext_nuclei_scan(target="http://target.com", severity="critical,high")"""
        from hellcat.core.tools import ExternalToolManager
        return ExternalToolManager().execute("nuclei", ["-u", target, "-severity", severity, "-timeout", "5"], timeout=300)

    @mcp.tool()
    def ext_tool_status() -> dict:
        """Check available/missing external security tools on this system."""
        from hellcat.core.tools import ExternalToolManager
        return ExternalToolManager().status_report()

    counter.add("external", 3)
