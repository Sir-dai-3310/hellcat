"""Hellcat Detector Handler — MCP tools for vulnerability detection."""
from __future__ import annotations
import logging
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from fastmcp import FastMCP
    from hellcat.hellcat_mcp import ToolCounter

def register_detector_tools(mcp: FastMCP, counter: ToolCounter, logger: logging.Logger) -> None:
    @mcp.tool()
    def vuln_scan(target: str, detectors: str = "sqli,xss") -> dict:
        """Run built-in vulnerability detectors against a URL (must be http/https).
        Example: vuln_scan(target="http://target.com/page?id=1", detectors="sqli,xss")"""
        if not target.startswith(("http://", "https://")):
            return {"error": "target must be a full HTTP URL (e.g. http://target.com/page?id=1)"}
        from hellcat.core.detectors import DetectorFactory
        try:
            from hellcat.core.detectors.injection.sqli_xss import SQLiDetector, XSSDetector  # noqa
        except Exception:
            pass
        try:
            from hellcat.core.detectors.auth import CORSDetector  # noqa
        except Exception:
            pass
        names = [d.strip() for d in detectors.split(",")]
        avail = [n for n in names if DetectorFactory.exists(n)]
        if not avail:
            return {"error": f"No detectors found for: {names}", "available": DetectorFactory.list_detectors()}
        comp = DetectorFactory.create_composite(avail)
        results = comp.detect(target)
        return {"findings": [r.to_dict() for r in results], "count": len(results), "detectors_used": avail}

    @mcp.tool()
    def sqli_scan(url: str, params: str = "") -> dict:
        """SQL injection scan. URL must include http:// and parameter.
        Example: sqli_scan(url="http://target.com/page", params="id=1&name=test")"""
        if not url.startswith(("http://", "https://")):
            return {"error": "url must start with http:// or https://"}
        from hellcat.core.detectors import DetectorFactory
        try:
            from hellcat.core.detectors.injection.sqli_xss import SQLiDetector  # noqa
        except Exception:
            pass
        p = dict(x.split("=", 1) for x in params.split("&") if "=" in x) if params else {}
        if not p:
            return {"error": "params required (e.g. params='id=1&name=test')", "hint": "SQLi needs injectable parameters"}
        if not DetectorFactory.exists("sqli"):
            return {"error": "sqli detector not registered"}
        det = DetectorFactory.create("sqli")
        results = det.detect(url, params=p)
        return {"findings": [r.to_dict() for r in results], "count": len(results)}

    @mcp.tool()
    def xss_scan(url: str, params: str = "") -> dict:
        """Cross-site scripting scan. URL must include http:// and parameter.
        Example: xss_scan(url="http://target.com/search", params="q=test")"""
        if not url.startswith(("http://", "https://")):
            return {"error": "url must start with http:// or https://"}
        from hellcat.core.detectors import DetectorFactory
        try:
            from hellcat.core.detectors.injection.sqli_xss import XSSDetector  # noqa
        except Exception:
            pass
        p = dict(x.split("=", 1) for x in params.split("&") if "=" in x) if params else {}
        if not p:
            return {"error": "params required (e.g. params='q=test')", "hint": "XSS needs injectable parameters"}
        if not DetectorFactory.exists("xss"):
            return {"error": "xss detector not registered"}
        det = DetectorFactory.create("xss")
        results = det.detect(url, params=p)
        return {"findings": [r.to_dict() for r in results], "count": len(results)}

    counter.add("detector", 3)
