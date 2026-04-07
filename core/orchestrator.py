"""
Hellcat Multi-Agent Orchestrator
=================================
Inspired by BlacksmithAI's hierarchical agent architecture.
Specialized agents for recon/scan/exploit/post-exploit coordinated
by a central orchestrator.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("hellcat.agents")


class AgentRole(Enum):
    RECON = "recon"
    SCANNER = "scanner"
    EXPLOITER = "exploiter"
    POST_EXPLOIT = "post_exploit"
    REPORTER = "reporter"


@dataclass
class AgentTask:
    id: str = ""
    role: AgentRole = AgentRole.RECON
    action: str = ""
    target: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None
    error: str = ""
    start_time: float = 0.0
    end_time: float = 0.0


class BaseAgent:
    """Abstract agent with role-based specialization."""
    role: AgentRole = AgentRole.RECON
    name: str = "base"

    def execute(self, task: AgentTask) -> Dict[str, Any]:
        raise NotImplementedError


class ReconAgent(BaseAgent):
    role = AgentRole.RECON
    name = "recon_agent"

    def execute(self, task: AgentTask) -> Dict[str, Any]:
        from hellcat.core.engine import ScanEngine
        engine = ScanEngine()
        if task.action == "full_recon":
            result = engine.execute("full_scan", task.target, task.params)
        elif task.action == "passive_recon":
            result = engine.execute("passive_recon", task.target, task.params)
        else:
            result = engine.execute("quick_scan", task.target, task.params)
        return result.to_dict()


class ScannerAgent(BaseAgent):
    role = AgentRole.SCANNER
    name = "scanner_agent"

    def execute(self, task: AgentTask) -> Dict[str, Any]:
        from hellcat.core.engine import ScanEngine
        result = ScanEngine().execute("web_audit", task.target, task.params)
        return result.to_dict()


class ExploiterAgent(BaseAgent):
    role = AgentRole.EXPLOITER
    name = "exploiter_agent"

    def execute(self, task: AgentTask) -> Dict[str, Any]:
        from hellcat.agents.cve import CVEIntelligenceManager
        mgr = CVEIntelligenceManager()
        # Match CVEs against target
        target_info = task.params.get("target_info", {})
        matches = mgr.match_target(target_info)
        exploits = []
        for m in matches[:3]:
            r = mgr.auto_exploit(m["cve_id"], task.target)
            exploits.append(r)
        return {"matches": matches, "exploits": exploits}


class PostExploitAgent(BaseAgent):
    role = AgentRole.POST_EXPLOIT
    name = "post_exploit_agent"

    def execute(self, task: AgentTask) -> Dict[str, Any]:
        from hellcat.core.exfiltration import CredentialDumper
        from hellcat.core.persistence import PersistenceGenerator
        os_type = task.params.get("os_type", "linux")
        return {
            "cred_techniques": CredentialDumper.get_techniques(os_type),
            "persist_methods": PersistenceGenerator.list_methods(os_type),
        }


class ReporterAgent(BaseAgent):
    role = AgentRole.REPORTER
    name = "reporter_agent"

    def execute(self, task: AgentTask) -> Dict[str, Any]:
        from hellcat.core.session import ReportGenerator
        rg = ReportGenerator()
        rg.set_metadata(target=task.target, tester="Hellcat")
        for f in task.params.get("findings", []):
            rg.add_finding(f)
        return {"markdown": rg.to_markdown(), "json": rg.to_json()}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    """Coordinate specialized agents in hierarchical pipeline."""

    AGENT_MAP = {
        AgentRole.RECON: ReconAgent,
        AgentRole.SCANNER: ScannerAgent,
        AgentRole.EXPLOITER: ExploiterAgent,
        AgentRole.POST_EXPLOIT: PostExploitAgent,
        AgentRole.REPORTER: ReporterAgent,
    }

    def __init__(self) -> None:
        self._agents: Dict[AgentRole, BaseAgent] = {
            role: cls() for role, cls in self.AGENT_MAP.items()
        }
        self._tasks: List[AgentTask] = []
        self._results: Dict[str, Dict] = {}

    def create_pipeline(self, target: str, scope: str = "full") -> List[AgentTask]:
        """Create ordered task pipeline for a target."""
        tasks = []
        tasks.append(AgentTask(id="recon_1", role=AgentRole.RECON,
                               action="full_recon" if scope == "full" else "quick_scan",
                               target=target))
        tasks.append(AgentTask(id="scan_1", role=AgentRole.SCANNER,
                               action="web_audit", target=target,
                               depends_on=["recon_1"]))
        tasks.append(AgentTask(id="exploit_1", role=AgentRole.EXPLOITER,
                               action="auto_exploit", target=target,
                               depends_on=["scan_1"]))
        tasks.append(AgentTask(id="post_1", role=AgentRole.POST_EXPLOIT,
                               action="post_exploit", target=target,
                               depends_on=["exploit_1"]))
        tasks.append(AgentTask(id="report_1", role=AgentRole.REPORTER,
                               action="generate_report", target=target,
                               depends_on=["scan_1", "exploit_1"]))
        self._tasks = tasks
        return tasks

    def execute_pipeline(self, target: str, scope: str = "full") -> Dict[str, Any]:
        """Execute full agent pipeline."""
        tasks = self.create_pipeline(target, scope)
        start = time.time()

        for task in tasks:
            # Check dependencies
            for dep in task.depends_on:
                if dep in self._results:
                    task.params.update(self._results[dep])

            # Forward findings to reporter
            if task.role == AgentRole.REPORTER:
                all_findings = []
                for r in self._results.values():
                    all_findings.extend(r.get("findings", []))
                task.params["findings"] = all_findings

            # Execute
            agent = self._agents.get(task.role)
            if not agent:
                task.status = "skipped"
                continue

            task.status = "running"
            task.start_time = time.time()
            try:
                task.result = agent.execute(task)
                task.status = "completed"
                self._results[task.id] = task.result or {}
            except Exception as exc:
                task.status = "failed"
                task.error = str(exc)
                logger.error("Agent %s failed: %s", agent.name, exc)
            task.end_time = time.time()

        return {
            "target": target,
            "scope": scope,
            "duration": round(time.time() - start, 2),
            "tasks": [{"id": t.id, "role": t.role.value, "status": t.status,
                        "duration": round(t.end_time - t.start_time, 2) if t.end_time else 0,
                        "error": t.error} for t in tasks],
            "results": self._results,
        }
