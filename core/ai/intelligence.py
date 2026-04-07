"""
Hellcat Intelligence — Unified Decision Layer
==============================================
Merges MCTS planner + AI engine + knowledge graph + tool effectiveness
into a single orchestration brain.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from hellcat.core.ai.engine import AIEngine, TOOL_EFFECTIVENESS
from hellcat.core.ai.mcts_planner import MCTSPlanner
from hellcat.core.knowledge import KnowledgeManager
from hellcat.core.models import AttackChain, AttackState, TargetProfile, TargetType
from hellcat.core.tools import ExternalToolManager

logger = logging.getLogger("hellcat.intelligence")


class HellcatIntelligence:
    """Unified decision engine — the brain of Hellcat."""

    def __init__(self) -> None:
        self.ai = AIEngine()
        self.mcts = MCTSPlanner(seed=None)
        self.knowledge = KnowledgeManager()
        self.tools = ExternalToolManager()

    # -- Full assessment pipeline -------------------------------------------

    def assess(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        ctx = context or {}

        # 1. AI target analysis
        analysis = self.ai.analyze_target(target, ctx)

        # 2. Filter by available tools
        avail = set(self.tools.available_tools)
        analysis["recommended_tools"] = [
            t for t in analysis.get("recommended_tools", [])
            if t["tool"] in avail or self.tools.get_fallback(t["tool"])
        ]

        # 3. MCTS attack planning
        state = AttackState(target=target, target_type=analysis.get("target_type", "unknown"))
        for port, svc in ctx.get("open_ports", {}).items():
            state.add_open_port(int(port), svc)
        for v in ctx.get("vulnerabilities", []):
            state.add_vulnerability(v)
        for c in ctx.get("credentials", []):
            state.add_credential(c)

        mcts_plan = self.mcts.plan(state, iterations=ctx.get("mcts_iterations", 300))

        # 4. Knowledge graph update
        tid = self.knowledge.store_target(target, analysis.get("target_type", ""))

        # 5. Generate attack chain
        chain = self.ai.generate_attack_plan(target, {**analysis, **ctx})

        return {
            "target": target,
            "analysis": analysis,
            "mcts_plan": mcts_plan,
            "attack_chain": chain.to_dict(),
            "knowledge_stats": self.knowledge.stats(),
            "tool_status": {
                "available": len(self.tools.available_tools),
                "total": self.tools.status_report()["total_registered"],
            },
        }

    # -- Quick helpers -------------------------------------------------------

    def select_tools(self, target: str) -> List[Dict[str, Any]]:
        analysis = self.ai.analyze_target(target)
        return analysis.get("recommended_tools", [])

    def plan_attack(self, state: AttackState, iterations: int = 300) -> Dict[str, Any]:
        return self.mcts.plan(state, iterations)

    def generate_poc(self, cve_id: str, info: Optional[Dict] = None) -> str:
        return self.ai.generate_poc(cve_id, info)

    def smart_payload(self, vuln_type: str, ctx: Optional[Dict] = None) -> List[str]:
        return self.ai.smart_payload(vuln_type, ctx)
