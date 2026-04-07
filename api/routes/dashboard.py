"""
Hellcat Web Dashboard API Routes
==================================
Inspired by reNgine's UI. Lightweight Flask endpoints for:
- Scan engine management
- Continuous monitoring control
- Agent orchestration
- Task tree visualization
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/v2")

# Singleton instances (persist across requests)
_reasoning = None
_monitor = None

def _get_reasoning():
    global _reasoning
    if _reasoning is None:
        from hellcat.core.reasoning import ReasoningModule
        _reasoning = ReasoningModule()
    return _reasoning

def _get_monitor():
    global _monitor
    if _monitor is None:
        from hellcat.core.monitor import ContinuousMonitor
        _monitor = ContinuousMonitor(60)
    return _monitor


# ---------------------------------------------------------------------------
# Scan Engine endpoints
# ---------------------------------------------------------------------------

@dashboard_bp.route("/engines", methods=["GET"])
def list_engines():
    """List all available scan engines (built-in + custom YAML)."""
    from hellcat.core.engine import ScanEngine
    eng = ScanEngine()
    eng.load_custom_engines()
    return jsonify({"engines": eng.list_engines()})


@dashboard_bp.route("/engines/<engine_id>/run", methods=["POST"])
def run_engine(engine_id: str):
    """Execute a scan engine against a target.
    POST {"target": "example.com", "options": {}}"""
    data = request.get_json(force=True) or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "target required"}), 400
    from hellcat.core.engine import ScanEngine
    eng = ScanEngine()
    result = eng.execute(engine_id, target, data.get("options", {}))
    return jsonify(result.to_dict())


# ---------------------------------------------------------------------------
# Agent Orchestrator endpoints
# ---------------------------------------------------------------------------

@dashboard_bp.route("/orchestrate", methods=["POST"])
def orchestrate():
    """Run full multi-agent pipeline.
    POST {"target": "example.com", "scope": "full"}"""
    data = request.get_json(force=True) or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "target required"}), 400
    from hellcat.core.orchestrator import Orchestrator
    orch = Orchestrator()
    result = orch.execute_pipeline(target, data.get("scope", "full"))
    return jsonify(result)


# ---------------------------------------------------------------------------
# Reasoning / Task Tree endpoints
# ---------------------------------------------------------------------------

@dashboard_bp.route("/reasoning/init", methods=["POST"])
def reasoning_init():
    """Initialize reasoning engine with task tree.
    POST {"target": "example.com", "scope": "full"}"""
    data = request.get_json(force=True) or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "target required"}), 400
    rm = _get_reasoning()
    summary = rm.initialize(target, data.get("scope", "full"))
    return jsonify(summary)


@dashboard_bp.route("/reasoning/next", methods=["GET"])
def reasoning_next():
    """Get next recommended action from reasoning engine."""
    rm = _get_reasoning()
    action = rm.get_next_action()
    return jsonify(action or {"message": "No pending tasks. POST /reasoning/init first."})


# ---------------------------------------------------------------------------
# Monitor endpoints
# ---------------------------------------------------------------------------

@dashboard_bp.route("/monitor/targets", methods=["POST"])
def add_monitor_target():
    """Add target for continuous monitoring.
    POST {"target": "example.com", "interval_minutes": 60}"""
    data = request.get_json(force=True) or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "target required"}), 400
    mon = _get_monitor()
    mon.add_target(target)
    return jsonify({"status": "added", "target": target})


@dashboard_bp.route("/monitor/webhooks", methods=["POST"])
def add_webhook():
    """Add notification webhook.
    POST {"name": "slack", "url": "https://hooks.slack.com/..."}"""
    data = request.get_json(force=True) or {}
    name = data.get("name", "")
    url = data.get("url", "")
    if not name or not url:
        return jsonify({"error": "name and url required"}), 400
    mon = _get_monitor()
    mon.add_webhook(name, url)
    return jsonify({"status": "added", "webhook": name})


# ---------------------------------------------------------------------------
# Stats / Overview
# ---------------------------------------------------------------------------

@dashboard_bp.route("/stats", methods=["GET"])
def dashboard_stats():
    """Get overall Hellcat system statistics."""
    from hellcat.core.tools import ExternalToolManager
    from hellcat.core.detectors import DetectorFactory
    from hellcat.core.engine import ScanEngine
    from hellcat.modules.payload import PayloadGenerator

    try:
        from hellcat.core.detectors.injection.sqli_xss import SQLiDetector  # noqa
        from hellcat.core.detectors.injection.dom_xss import DOMXSSDetector  # noqa
        from hellcat.core.detectors.auth import CORSDetector  # noqa
        from hellcat.core.detectors.request import SSRFDetector  # noqa
    except Exception:
        pass

    tools = ExternalToolManager()
    tr = tools.status_report()
    eng = ScanEngine()

    return jsonify({
        "version": "1.2.0",
        "tools": {"available": tr["available"], "total": tr["total_registered"]},
        "detectors": DetectorFactory.list_detectors(),
        "engines": [e["id"] for e in eng.list_engines()],
        "payload_types": PayloadGenerator.list_types(),
        "capabilities": {
            "mcp_tools": 30,
            "scan_engines": len(eng.list_engines()),
            "detectors": len(DetectorFactory.list_detectors()),
            "c2_tunnels": 3,
            "lateral_modules": 4,
            "persistence_methods": 15,
            "lotl_techniques": 18,
            "identity_chains": 3,
        },
    })
