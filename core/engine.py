"""
Hellcat YAML Scan Engine System
================================
Inspired by reNgine's configurable engine approach.
Define recon/scan/exploit pipelines in YAML, execute as automated workflows.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hellcat.engine")

try:
    import yaml
except ImportError:
    yaml = None

# ---------------------------------------------------------------------------
# Built-in engine templates
# ---------------------------------------------------------------------------

BUILTIN_ENGINES = {
    "full_scan": {
        "name": "Full Scan",
        "description": "Complete recon + vuln scan + exploit attempt",
        "phases": [
            {"name": "recon", "tools": [
                {"tool": "nmap", "args": ["-sV", "-sC", "-T4", "-p-", "{target}"], "timeout": 600},
                {"tool": "subfinder", "args": ["-d", "{target}", "-silent"], "timeout": 120},
            ]},
            {"name": "discovery", "tools": [
                {"tool": "ffuf", "args": ["-u", "http://{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200,301,302,403"], "timeout": 300},
                {"tool": "httpx-toolkit", "args": ["-sc", "-td", "-title", "-silent"], "stdin": "{subdomains}", "timeout": 60},
            ]},
            {"name": "vuln_scan", "tools": [
                {"tool": "nuclei", "args": ["-u", "http://{target}", "-severity", "critical,high,medium", "-timeout", "5"], "timeout": 600},
            ]},
            {"name": "deep_scan", "detectors": ["sqli", "xss", "ssrf", "cors", "path_traversal"]},
        ],
    },
    "quick_scan": {
        "name": "Quick Scan",
        "description": "Fast port scan + top vulns only",
        "phases": [
            {"name": "recon", "tools": [
                {"tool": "nmap", "args": ["-sV", "-T4", "--top-ports", "100", "{target}"], "timeout": 60},
            ]},
            {"name": "vuln_scan", "tools": [
                {"tool": "nuclei", "args": ["-u", "http://{target}", "-severity", "critical,high", "-timeout", "3"], "timeout": 120},
            ]},
        ],
    },
    "passive_recon": {
        "name": "Passive Recon",
        "description": "OSINT only, no active probing",
        "phases": [
            {"name": "subdomain", "tools": [
                {"tool": "subfinder", "args": ["-d", "{target}", "-silent"], "timeout": 120},
                {"tool": "amass", "args": ["enum", "-passive", "-d", "{target}"], "timeout": 300},
            ]},
        ],
    },
    "web_audit": {
        "name": "Web Application Audit",
        "description": "Deep web app testing with all detectors",
        "phases": [
            {"name": "crawl", "tools": [
                {"tool": "ffuf", "args": ["-u", "{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/big.txt", "-mc", "200,301,302,403"], "timeout": 600},
            ]},
            {"name": "detect", "detectors": ["sqli", "xss", "ssrf", "ssti", "cors", "idor", "path_traversal", "auth_bypass", "dom_xss", "graphql"]},
            {"name": "fuzz", "intruder": {
                "params": "auto",
                "payloads": ["sqli", "xss"],
                "max_per_param": 15,
            }},
        ],
    },
    "bug_bounty": {
        "name": "Bug Bounty Hunter",
        "description": "Full bug bounty workflow: recon -> enum -> vuln -> report",
        "phases": [
            {"name": "subdomain_enum", "tools": [
                {"tool": "subfinder", "args": ["-d", "{target}", "-silent"], "timeout": 120},
            ]},
            {"name": "http_probe", "tools": [
                {"tool": "httpx-toolkit", "args": ["-sc", "-td", "-title", "-silent"], "stdin": "{subdomains}", "timeout": 60},
            ]},
            {"name": "content_discovery", "tools": [
                {"tool": "ffuf", "args": ["-u", "http://{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200,301,302,403"], "timeout": 300},
            ]},
            {"name": "vuln_hunt", "tools": [
                {"tool": "nuclei", "args": ["-u", "http://{target}", "-severity", "critical,high"], "timeout": 300},
            ]},
            {"name": "deep_detect", "detectors": ["sqli", "xss", "ssrf", "idor", "cors"]},
            {"name": "report", "format": "hackerone"},
        ],
    },
}


# ---------------------------------------------------------------------------
# Engine loader
# ---------------------------------------------------------------------------

@dataclass
class PhaseResult:
    """Result from a single scan engine phase."""
    name: str = ""
    status: str = "pending"  # pending, running, completed, failed
    start_time: float = 0.0
    end_time: float = 0.0
    results: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time else 0.0


@dataclass
class ScanResult:
    """Aggregated result from a scan engine execution."""
    engine: str = ""
    target: str = ""
    status: str = "pending"
    phases: List[PhaseResult] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine": self.engine, "target": self.target, "status": self.status,
            "duration": round(self.end_time - self.start_time, 2) if self.end_time else 0,
            "phases": [{"name": p.name, "status": p.status, "duration": round(p.duration, 2),
                        "results_count": len(p.results), "errors": p.errors} for p in self.phases],
            "total_findings": len(self.findings),
        }


class ScanEngine:
    """YAML-configurable scan engine executor."""

    def __init__(self) -> None:
        self._engines: Dict[str, Dict] = dict(BUILTIN_ENGINES)
        self._custom_dir = os.path.join(os.path.dirname(__file__), "..", "..", "config", "engines")

    def load_custom_engines(self) -> int:
        """Load custom YAML engine files from config/engines/."""
        if not yaml or not os.path.exists(self._custom_dir):
            return 0
        loaded = 0
        for f in os.listdir(self._custom_dir):
            if f.endswith((".yml", ".yaml")):
                try:
                    with open(os.path.join(self._custom_dir, f)) as fh:
                        eng = yaml.safe_load(fh)
                    if isinstance(eng, dict) and "name" in eng and "phases" in eng:
                        key = f.rsplit(".", 1)[0]
                        self._engines[key] = eng
                        loaded += 1
                except Exception as exc:
                    logger.warning("Failed to load engine %s: %s", f, exc)
        return loaded

    def list_engines(self) -> List[Dict[str, str]]:
        return [{"id": k, "name": v.get("name", k), "description": v.get("description", "")}
                for k, v in self._engines.items()]

    def get_engine(self, name: str) -> Optional[Dict]:
        return self._engines.get(name)

    def execute(self, engine_name: str, target: str,
                options: Optional[Dict] = None) -> ScanResult:
        """Execute a scan engine against a target."""
        engine = self._engines.get(engine_name)
        if not engine:
            return ScanResult(engine=engine_name, target=target, status="error")

        opts = options or {}
        scan = ScanResult(engine=engine_name, target=target, status="running",
                          start_time=time.time())

        for phase_def in engine.get("phases", []):
            phase = PhaseResult(name=phase_def.get("name", "unnamed"), status="running",
                                start_time=time.time())
            try:
                if "tools" in phase_def:
                    self._run_tools_phase(phase, phase_def["tools"], target, opts)
                elif "detectors" in phase_def:
                    self._run_detector_phase(phase, phase_def["detectors"], target, opts)
                elif "intruder" in phase_def:
                    self._run_intruder_phase(phase, phase_def["intruder"], target, opts)
                phase.status = "completed"
            except Exception as exc:
                phase.status = "failed"
                phase.errors.append(str(exc))
            phase.end_time = time.time()
            scan.phases.append(phase)
            scan.findings.extend(phase.results)

        scan.status = "completed"
        scan.end_time = time.time()
        return scan

    def _run_tools_phase(self, phase: PhaseResult, tools: List[Dict],
                         target: str, opts: Dict) -> None:
        from hellcat.core.tools import ExternalToolManager
        mgr = ExternalToolManager()
        for tool_def in tools:
            tool = tool_def.get("tool", "")
            args = [a.replace("{target}", target) for a in tool_def.get("args", [])]
            timeout = tool_def.get("timeout", 120)
            result = mgr.execute(tool, args, timeout=timeout)
            phase.results.append(result)

    def _run_detector_phase(self, phase: PhaseResult, detector_names: List[str],
                            target: str, opts: Dict) -> None:
        from hellcat.core.detectors import DetectorFactory
        # Ensure detectors are registered
        try:
            from hellcat.core.detectors.injection.sqli_xss import SQLiDetector, XSSDetector  # noqa
            from hellcat.core.detectors.injection.dom_xss import DOMXSSDetector  # noqa
            from hellcat.core.detectors.auth import CORSDetector  # noqa
            from hellcat.core.detectors.request import SSRFDetector  # noqa
        except Exception:
            pass
        available = [n for n in detector_names if DetectorFactory.exists(n)]
        if not available:
            return
        comp = DetectorFactory.create_composite(available)
        url = target if target.startswith("http") else f"http://{target}"
        results = comp.detect(url, params=opts.get("params", {}))
        for r in results:
            phase.results.append(r.to_dict())

    def _run_intruder_phase(self, phase: PhaseResult, intruder_cfg: Dict,
                            target: str, opts: Dict) -> None:
        from hellcat.modules.web_scanner import Intruder, Repeater, HTTPRequest
        from hellcat.modules.payload import PayloadGenerator
        payload_types = intruder_cfg.get("payloads", ["xss"])
        max_per = intruder_cfg.get("max_per_param", 10)
        params = opts.get("params", intruder_cfg.get("params", {}))
        if isinstance(params, str) and params == "auto":
            params = {"id": "1", "q": "test"}  # placeholder
        url = target if target.startswith("http") else f"http://{target}"
        intr = Intruder(Repeater(timeout=10))
        for pt in payload_types:
            payloads = PayloadGenerator.get_extended(pt, max_per)
            results = intr.fuzz_params(url, params, payloads)
            summary = intr.summary(results)
            if summary.get("anomalies"):
                phase.results.extend(summary["anomalies"])


# ---------------------------------------------------------------------------
# R8: Incremental Scan Mode (inspired by reconFTW --incremental)
# ---------------------------------------------------------------------------

class IncrementalScanner:
    """Only report new/changed findings since last scan."""

    def __init__(self) -> None:
        self._previous: Dict[str, set] = {}  # target -> set of fingerprints

    def scan(self, engine_name: str, target: str,
             options: Optional[Dict] = None) -> Dict[str, Any]:
        eng = ScanEngine()
        result = eng.execute(engine_name, target, options)

        # Compute fingerprints for current findings
        current_fps = set()
        for phase in result.phases:
            for r in phase.results:
                fp = str(r)[:200]
                current_fps.add(fp)

        # Diff against previous
        prev_fps = self._previous.get(target, set())
        new_fps = current_fps - prev_fps
        self._previous[target] = current_fps

        return {
            "target": target,
            "engine": engine_name,
            "total_findings": len(current_fps),
            "new_findings": len(new_fps),
            "unchanged": len(current_fps) - len(new_fps),
            "scan": result.to_dict(),
            "incremental": True,
        }


# ---------------------------------------------------------------------------
# R9: Multi-Mode Scanner (inspired by Sn1per modes)
# ---------------------------------------------------------------------------

SCAN_MODES = {
    "stealth": {
        "description": "Minimal footprint — passive recon only, no active probing",
        "engine": "passive_recon",
        "rate_limit": 0.5,
        "user_agent": "Mozilla/5.0 (compatible; Googlebot/2.1)",
    },
    "normal": {
        "description": "Balanced scan — recon + top-port scan + basic vuln check",
        "engine": "quick_scan",
        "rate_limit": 0.1,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    },
    "aggressive": {
        "description": "Full assault — all ports, all detectors, all payloads",
        "engine": "full_scan",
        "rate_limit": 0.0,
        "user_agent": "Hellcat/1.3 SecurityScanner",
    },
}


class MultiModeScanner:
    """Stealth/Normal/Aggressive scan mode selector."""

    @staticmethod
    def scan(target: str, mode: str = "normal",
             options: Optional[Dict] = None) -> Dict[str, Any]:
        mode_cfg = SCAN_MODES.get(mode, SCAN_MODES["normal"])
        eng = ScanEngine()
        opts = options or {}
        opts["rate_limit"] = mode_cfg["rate_limit"]
        opts["user_agent"] = mode_cfg["user_agent"]
        result = eng.execute(mode_cfg["engine"], target, opts)
        return {
            "mode": mode,
            "mode_description": mode_cfg["description"],
            "engine_used": mode_cfg["engine"],
            "scan": result.to_dict(),
        }

    @staticmethod
    def list_modes() -> List[Dict[str, str]]:
        return [{"mode": k, "description": v["description"], "engine": v["engine"]}
                for k, v in SCAN_MODES.items()]


# ---------------------------------------------------------------------------
# R10: Knowledge Graph <-> Reasoning Engine Integration
# ---------------------------------------------------------------------------

class IntegratedPipeline:
    """Full pipeline: Reasoning -> Tools -> KG -> Reasoning."""

    def __init__(self) -> None:
        from hellcat.core.reasoning import ReasoningModule
        from hellcat.core.knowledge import KnowledgeManager
        self.reasoning = ReasoningModule()
        self.knowledge = KnowledgeManager()

    def run(self, target: str, max_steps: int = 10,
            scope: str = "full") -> Dict[str, Any]:
        """Execute adaptive pipeline with KG feedback loop."""
        self.reasoning.initialize(target, scope)
        target_id = self.knowledge.store_target(target)
        steps_executed = 0
        all_findings = []

        for _ in range(max_steps):
            action = self.reasoning.get_next_action()
            if not action:
                break

            task_id = action["task_id"]
            tool = action["tool"]
            steps_executed += 1

            # Execute tool
            from hellcat.core.tools import ExternalToolManager
            mgr = ExternalToolManager()
            if mgr.is_available(tool):
                result = mgr.execute(tool, [target], timeout=60)
                raw = result.get("stdout", "")
            else:
                raw = ""

            # Parse and record
            record = self.reasoning.record_result(task_id, tool, raw)
            parsed = record.get("parsed", {})

            # Store in Knowledge Graph
            for port in parsed.get("ports", []):
                svc = parsed.get("services", {}).get(port, {}).get("service", "unknown")
                self.knowledge.store_service(target_id, port, svc)

            for vuln in parsed.get("vulns", []):
                vid = self.knowledge.store_vulnerability(
                    target_id, vuln.get("template", "unknown"),
                    vuln.get("severity", "medium"))
                all_findings.append(vuln)

            for sub in parsed.get("subdomains", []):
                self.knowledge.store_entity("subdomain", sub, {"parent": target})

        return {
            "target": target,
            "steps_executed": steps_executed,
            "findings": all_findings,
            "knowledge_stats": self.knowledge.stats(),
            "task_tree": self.reasoning.status(),
        }
