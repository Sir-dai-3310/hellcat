"""
Hellcat Reasoning Engine + Task Tree + Result Parser
=====================================================
Inspired by PentestGPT/CAI's three-module architecture:
- ReasoningModule: maintains task tree, decides next action
- ParsingModule: extracts structured data from raw tool output
- TaskTree: tracks attack progress across multi-step operations
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hellcat.reasoning")


# ---------------------------------------------------------------------------
# Task Tree (attack state tracker)
# ---------------------------------------------------------------------------

class TaskStatus(Enum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class TaskNode:
    id: str = ""
    name: str = ""
    description: str = ""
    status: TaskStatus = TaskStatus.PENDING
    parent_id: str = ""
    children: List[str] = field(default_factory=list)
    tool: str = ""
    raw_output: str = ""
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    priority: int = 5  # 1=highest


class TaskTree:
    """Hierarchical task state tracker for attack progress."""

    def __init__(self) -> None:
        self._nodes: Dict[str, TaskNode] = {}
        self._counter = 0

    def add_task(self, name: str, description: str = "", parent_id: str = "",
                 tool: str = "", priority: int = 5) -> str:
        self._counter += 1
        tid = f"T{self._counter:04d}"
        node = TaskNode(id=tid, name=name, description=description,
                        parent_id=parent_id, tool=tool, priority=priority)
        self._nodes[tid] = node
        if parent_id and parent_id in self._nodes:
            self._nodes[parent_id].children.append(tid)
        return tid

    def update_status(self, task_id: str, status: TaskStatus,
                      raw_output: str = "", parsed_data: Optional[Dict] = None) -> None:
        node = self._nodes.get(task_id)
        if not node:
            return
        node.status = status
        if raw_output:
            node.raw_output = raw_output
        if parsed_data:
            node.parsed_data = parsed_data
        if status == TaskStatus.COMPLETED:
            node.completed_at = time.time()

    def get_pending(self) -> List[TaskNode]:
        pending = [n for n in self._nodes.values() if n.status == TaskStatus.PENDING]
        # Check parent dependencies
        ready = []
        for n in pending:
            if not n.parent_id or self._nodes.get(n.parent_id, TaskNode()).status == TaskStatus.COMPLETED:
                ready.append(n)
        return sorted(ready, key=lambda n: n.priority)

    def get_next(self) -> Optional[TaskNode]:
        pending = self.get_pending()
        return pending[0] if pending else None

    def get_completed_data(self) -> Dict[str, Any]:
        """Aggregate parsed data from all completed tasks."""
        data: Dict[str, Any] = {"ports": [], "services": {}, "vulns": [],
                                 "subdomains": [], "endpoints": [], "creds": []}
        for n in self._nodes.values():
            if n.status != TaskStatus.COMPLETED:
                continue
            pd = n.parsed_data
            data["ports"].extend(pd.get("ports", []))
            data["services"].update(pd.get("services", {}))
            data["vulns"].extend(pd.get("vulns", []))
            data["subdomains"].extend(pd.get("subdomains", []))
            data["endpoints"].extend(pd.get("endpoints", []))
            data["creds"].extend(pd.get("creds", []))
        # Deduplicate
        data["ports"] = sorted(set(data["ports"]))
        data["subdomains"] = sorted(set(data["subdomains"]))
        return data

    def summary(self) -> Dict[str, Any]:
        status_counts = {}
        for n in self._nodes.values():
            status_counts[n.status.value] = status_counts.get(n.status.value, 0) + 1
        return {"total": len(self._nodes), "by_status": status_counts,
                "tasks": [{"id": n.id, "name": n.name, "status": n.status.value,
                           "tool": n.tool} for n in self._nodes.values()]}


# ---------------------------------------------------------------------------
# Parsing Module (extract structured data from raw tool output)
# ---------------------------------------------------------------------------

class ResultParser:
    """Extract structured data from raw tool output."""

    @staticmethod
    def parse_nmap(output: str) -> Dict[str, Any]:
        ports = []
        services = {}
        for m in re.finditer(r"(\d+)/tcp\s+(\w+)\s+(\S+)\s*(.*)", output):
            port = int(m.group(1))
            state = m.group(2)
            service = m.group(3)
            version = m.group(4).strip()
            if state == "open":
                ports.append(port)
                services[port] = {"service": service, "version": version}
        os_match = re.search(r"OS:\s*(.+?)(?:;|$)", output)
        return {"ports": ports, "services": services,
                "os": os_match.group(1).strip() if os_match else ""}

    @staticmethod
    def parse_nuclei(output: str) -> Dict[str, Any]:
        vulns = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            # nuclei format: [template-id] [protocol] [severity] url
            m = re.match(r"\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.*)", line)
            if m:
                vulns.append({"template": m.group(1), "protocol": m.group(2),
                              "severity": m.group(3), "url": m.group(4).strip()})
        return {"vulns": vulns}

    @staticmethod
    def parse_subfinder(output: str) -> Dict[str, Any]:
        subs = [line.strip() for line in output.strip().split("\n") if line.strip()]
        return {"subdomains": subs}

    @staticmethod
    def parse_ffuf(output: str) -> Dict[str, Any]:
        endpoints = []
        for m in re.finditer(r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", output):
            endpoints.append({"path": m.group(1), "status": int(m.group(2)),
                              "size": int(m.group(3))})
        return {"endpoints": endpoints}

    @staticmethod
    def parse_httpx(output: str) -> Dict[str, Any]:
        results = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            entry = {"url": parts[0] if parts else ""}
            for p in parts[1:]:
                if p.startswith("[") and p.endswith("]"):
                    entry["info"] = p.strip("[]")
            results.append(entry)
        return {"http_services": results}

    @staticmethod
    def parse_generic(output: str) -> Dict[str, Any]:
        return {"raw_lines": len(output.strip().split("\n")),
                "raw_size": len(output)}

    PARSERS = {
        "nmap": parse_nmap.__func__,
        "nuclei": parse_nuclei.__func__,
        "subfinder": parse_subfinder.__func__,
        "ffuf": parse_ffuf.__func__,
        "httpx": parse_httpx.__func__,
        "httpx-toolkit": parse_httpx.__func__,
    }

    @classmethod
    def parse(cls, tool: str, output: str) -> Dict[str, Any]:
        parser = cls.PARSERS.get(tool, cls.parse_generic.__func__)
        try:
            return parser(output)
        except Exception as exc:
            logger.warning("Parse failed for %s: %s", tool, exc)
            return cls.parse_generic(output)


# ---------------------------------------------------------------------------
# Reasoning Module
# ---------------------------------------------------------------------------

class ReasoningModule:
    """Decide next action based on task tree and knowledge."""

    PHASE_ORDER = ["recon", "enum", "vuln_scan", "exploit", "post_exploit", "report"]

    PHASE_TASKS = {
        "recon": [
            ("port_scan", "nmap", "Scan target ports and services", 1),
            ("subdomain_enum", "subfinder", "Enumerate subdomains", 2),
        ],
        "enum": [
            ("dir_discovery", "ffuf", "Discover directories and files", 3),
            ("tech_detect", "httpx-toolkit", "Detect technology stack", 3),
        ],
        "vuln_scan": [
            ("nuclei_scan", "nuclei", "Template-based vulnerability scan", 4),
            ("detector_scan", "hellcat_detectors", "Built-in detector scan", 4),
            ("cve_match", "hellcat_cve", "Match known CVE templates", 4),
        ],
        "exploit": [
            ("auto_exploit", "hellcat_exploit", "Attempt exploitation", 6),
        ],
        "post_exploit": [
            ("cred_dump", "hellcat_creds", "Credential harvesting", 7),
            ("persist", "hellcat_persist", "Establish persistence", 8),
        ],
        "report": [
            ("generate_report", "hellcat_report", "Generate findings report", 9),
        ],
    }

    def __init__(self) -> None:
        self.tree = TaskTree()
        self.parser = ResultParser()
        self._current_phase = "recon"

    def initialize(self, target: str, scope: str = "full") -> Dict[str, Any]:
        """Build initial task tree for a target."""
        phases = self.PHASE_ORDER if scope == "full" else self.PHASE_ORDER[:3]
        parent_id = ""
        for phase in phases:
            for name, tool, desc, priority in self.PHASE_TASKS.get(phase, []):
                tid = self.tree.add_task(name, desc, parent_id=parent_id,
                                         tool=tool, priority=priority)
                if not parent_id:
                    parent_id = tid
                    # Only first task has no parent; rest chain after recon
            if phase == "recon" and self.tree._nodes:
                parent_id = list(self.tree._nodes.keys())[0]
        return self.tree.summary()

    def get_next_action(self) -> Optional[Dict[str, Any]]:
        """Recommend next action based on current state."""
        node = self.tree.get_next()
        if not node:
            return None
        accumulated = self.tree.get_completed_data()
        return {
            "task_id": node.id,
            "action": node.name,
            "tool": node.tool,
            "description": node.description,
            "context": {
                "known_ports": accumulated["ports"],
                "known_vulns": len(accumulated["vulns"]),
                "known_subdomains": len(accumulated["subdomains"]),
            },
        }

    def record_result(self, task_id: str, tool: str, raw_output: str) -> Dict[str, Any]:
        """Parse tool output and update task tree."""
        parsed = self.parser.parse(tool, raw_output)
        self.tree.update_status(task_id, TaskStatus.COMPLETED,
                                raw_output=raw_output[:5000], parsed_data=parsed)
        # Generate follow-up tasks based on findings
        followups = self._generate_followups(task_id, parsed)
        return {"parsed": parsed, "followup_tasks": followups}

    def _generate_followups(self, parent_id: str, parsed: Dict) -> List[str]:
        """Dynamically add tasks based on discoveries (Subscan concept)."""
        new_tasks = []
        # If new ports found, add service-specific scans
        for port in parsed.get("ports", []):
            svc = parsed.get("services", {}).get(port, {}).get("service", "")
            if svc in ("http", "https"):
                tid = self.tree.add_task(f"web_scan_port_{port}",
                    f"Web vulnerability scan on port {port}",
                    parent_id=parent_id, tool="nuclei", priority=4)
                new_tasks.append(tid)
            elif svc == "ssh":
                tid = self.tree.add_task(f"ssh_audit_{port}",
                    f"SSH configuration audit on port {port}",
                    parent_id=parent_id, tool="nmap", priority=5)
                new_tasks.append(tid)
        # If vulns found, add exploit tasks
        for vuln in parsed.get("vulns", []):
            if vuln.get("severity") in ("critical", "high"):
                tid = self.tree.add_task(f"exploit_{vuln.get('template', 'unknown')}",
                    f"Exploit {vuln.get('template', '')}",
                    parent_id=parent_id, tool="hellcat_exploit", priority=2)
                new_tasks.append(tid)
        return new_tasks

    def status(self) -> Dict[str, Any]:
        return {
            "phase": self._current_phase,
            "tree": self.tree.summary(),
            "accumulated": self.tree.get_completed_data(),
        }
