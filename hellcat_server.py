"""
Hellcat Flask API Server
========================
Secondary interface (REST + WebSocket) alongside the primary MCP stdio server.
Exposes tool endpoints, intelligence, workflows, process management, and telemetry.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict

from flask import Flask, jsonify, request

logger = logging.getLogger("hellcat.server")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_HOST = os.environ.get("HELLCAT_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("HELLCAT_PORT", "8888"))
DEBUG_MODE = os.environ.get("HELLCAT_DEBUG", "0").lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    """Application factory — returns a configured Flask instance."""
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    # -- Middleware stack (auth + rate limit + CORS + audit) -----------------
    try:
        from hellcat.api.middleware import register_middleware
        register_middleware(app)
    except ImportError as exc:
        logger.warning("Middleware unavailable: %s", exc)

    # -- Health endpoint (always available) ----------------------------------
    @app.route("/health", methods=["GET"])
    @app.route("/mcp/health", methods=["GET"])
    def health_check() -> tuple:
        return jsonify({
            "status": "healthy",
            "name": "Hellcat",
            "version": "1.0.0-alpha",
            "timestamp": time.time(),
        }), 200

    # -- Blueprint registration (lazy, non-fatal) ----------------------------
    _register_blueprints(app)

    # -- Error handlers ------------------------------------------------------
    @app.errorhandler(404)
    def not_found(_e: Exception) -> tuple:
        return jsonify({"error": "endpoint not found"}), 404

    @app.errorhandler(500)
    def internal_error(_e: Exception) -> tuple:
        return jsonify({"error": "internal server error"}), 500

    logger.info("Hellcat Flask app created — host=%s port=%d", API_HOST, API_PORT)
    return app


# ---------------------------------------------------------------------------
# Blueprint loader
# ---------------------------------------------------------------------------

_BLUEPRINT_REGISTRY: list[tuple[str, str, str]] = [
    # (display, module, blueprint_attr)
    ("core",            "hellcat.api.routes.core",           "core_bp"),
    ("dashboard",       "hellcat.api.routes.dashboard",      "dashboard_bp"),
    ("intelligence",    "hellcat.api.routes.intelligence",   "intelligence_bp"),
    ("tools_network",   "hellcat.api.routes.tools_network",  "tools_network_bp"),
    ("tools_web",       "hellcat.api.routes.tools_web",      "tools_web_bp"),
    ("tools_binary",    "hellcat.api.routes.tools_binary",   "tools_binary_bp"),
    ("tools_cloud",     "hellcat.api.routes.tools_cloud",    "tools_cloud_bp"),
    ("tools_api",       "hellcat.api.routes.tools_api",      "tools_api_bp"),
    ("tools_exploit",   "hellcat.api.routes.tools_exploit",  "tools_exploit_bp"),
    ("bugbounty",       "hellcat.api.routes.bugbounty",      "bugbounty_bp"),
    ("ctf",             "hellcat.api.routes.ctf",            "ctf_bp"),
    ("vuln_intel",      "hellcat.api.routes.vuln_intel",     "vuln_intel_bp"),
    ("processes",       "hellcat.api.routes.processes",       "processes_bp"),
    ("reports",         "hellcat.api.routes.reports",         "reports_bp"),
]


def _register_blueprints(app: Flask) -> None:
    import importlib
    for display, module_path, bp_attr in _BLUEPRINT_REGISTRY:
        try:
            mod = importlib.import_module(module_path)
            bp = getattr(mod, bp_attr)
            app.register_blueprint(bp)
            logger.debug("Blueprint [%s] registered", display)
        except (ImportError, AttributeError) as exc:
            logger.warning("Blueprint [%s] skipped: %s", display, exc)
        except Exception as exc:
            logger.error("Blueprint [%s] failed: %s", display, exc)


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

def run_server() -> None:
    """Start the Flask dev server (use gunicorn in production)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )
    app = create_app()
    app.run(host=API_HOST, port=API_PORT, debug=DEBUG_MODE)


if __name__ == "__main__":
    run_server()
