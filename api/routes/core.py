"""
Hellcat Core API Routes
========================
Main endpoints for scanning, tool execution, CVE lookup, intelligence.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

core_bp = Blueprint("core", __name__, url_prefix="/api")


@core_bp.route("/scan", methods=["POST"])
def scan_target():
    """Full intelligent scan of a target.
    POST {"target": "10.0.0.1", "options": {"mcts_iterations": 200}}
    """
    data = request.get_json(force=True) or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "target required"}), 400
    opts = data.get("options", {})

    from hellcat.core.ai.intelligence import HellcatIntelligence
    intel = HellcatIntelligence()
    result = intel.assess(target, opts)
    return jsonify(result)


@core_bp.route("/tool/exec", methods=["POST"])
def exec_tool():
    """Execute an external tool.
    POST {"tool": "nmap", "args": ["-sV", "-p", "22,80", "10.0.0.1"]}
    """
    data = request.get_json(force=True) or {}
    tool = data.get("tool", "")
    args = data.get("args", [])
    timeout = data.get("timeout", 120)
    if not tool:
        return jsonify({"error": "tool required"}), 400

    from hellcat.core.tools import ExternalToolManager
    mgr = ExternalToolManager()
    result = mgr.execute(tool, args, timeout=timeout)
    return jsonify(result)


@core_bp.route("/tool/status", methods=["GET"])
def tool_status():
    """Check available/missing tools."""
    from hellcat.core.tools import ExternalToolManager
    return jsonify(ExternalToolManager().status_report())


@core_bp.route("/cve/lookup", methods=["POST"])
def cve_lookup():
    """Lookup CVE PoCs.
    POST {"cve_id": "CVE-2025-0108"}
    """
    data = request.get_json(force=True) or {}
    cve_id = data.get("cve_id", "")
    if not cve_id:
        return jsonify({"error": "cve_id required"}), 400

    from hellcat.agents.cve import CVEIntelligenceManager
    mgr = CVEIntelligenceManager()
    pocs = mgr.poc_lookup(cve_id)
    exploit = mgr.auto_exploit(cve_id, data.get("target", ""))
    return jsonify({"cve_id": cve_id, "pocs": pocs, "exploit": exploit})


@core_bp.route("/cve/match", methods=["POST"])
def cve_match():
    """Match CVE templates against target info.
    POST {"open_ports": [22, 80, 443], "banners": ["Apache", "OpenSSH"]}
    """
    data = request.get_json(force=True) or {}
    from hellcat.agents.cve import CVEIntelligenceManager
    return jsonify({"matches": CVEIntelligenceManager().match_target(data)})


@core_bp.route("/detect", methods=["POST"])
def detect_vulns():
    """Run built-in detectors against URL.
    POST {"url": "http://target/page", "params": {"id": "1"}, "detectors": "sqli,xss"}
    """
    data = request.get_json(force=True) or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "url required"}), 400

    params = data.get("params", {})
    det_names = [d.strip() for d in data.get("detectors", "sqli,xss").split(",")]

    from hellcat.core.detectors import DetectorFactory
    # Ensure detectors are registered
    try:
        from hellcat.core.detectors.injection import sqli_xss  # noqa: F401
        from hellcat.core.detectors.auth import __init__  # noqa: F401
    except Exception:
        pass

    available = [n for n in det_names if DetectorFactory.exists(n)]
    if not available:
        return jsonify({"error": f"No detectors available for: {det_names}"}), 400

    comp = DetectorFactory.create_composite(available)
    results = comp.detect(url, params=params)
    return jsonify({
        "url": url,
        "detectors_used": available,
        "findings": [r.to_dict() for r in results],
        "total": len(results),
        "vulnerable": sum(1 for r in results if r.vulnerable),
    })


@core_bp.route("/payload/generate", methods=["POST"])
def gen_payload():
    """Generate payloads for a vuln type.
    POST {"vuln_type": "xss", "complexity": "waf_bypass"}
    """
    data = request.get_json(force=True) or {}
    vtype = data.get("vuln_type", "xss")
    complexity = data.get("complexity", "basic")

    from hellcat.modules.payload import PayloadGenerator
    payloads = PayloadGenerator.get_payloads(vtype, complexity, limit=20)
    return jsonify({"vuln_type": vtype, "complexity": complexity,
                    "payloads": payloads, "count": len(payloads)})
