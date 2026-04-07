"""
Hellcat HTTP Proxy & Repeater Engine
=====================================
Burp-like HTTP request interception, modification, replay, and
parameter intruder. No mitmproxy dependency — pure requests-based
for maximum portability.
"""
from __future__ import annotations

import copy
import json
import logging
import re
import time
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

logger = logging.getLogger("hellcat.proxy")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

@dataclass
class HTTPRequest:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "method": self.method, "url": self.url,
                "headers": self.headers, "params": self.params,
                "body": self.body, "cookies": self.cookies}

    def clone(self) -> HTTPRequest:
        return copy.deepcopy(self)


@dataclass
class HTTPResponse:
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"status_code": self.status_code, "headers": self.headers,
                "body_length": len(self.body), "elapsed": round(self.elapsed, 3),
                "body_preview": self.body[:500]}


@dataclass
class RequestResponsePair:
    request: HTTPRequest = field(default_factory=HTTPRequest)
    response: Optional[HTTPResponse] = None
    tags: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"request": self.request.to_dict(),
                "response": self.response.to_dict() if self.response else None,
                "tags": self.tags, "notes": self.notes}


# ---------------------------------------------------------------------------
# Repeater — send/modify/resend individual requests
# ---------------------------------------------------------------------------

class Repeater:
    """Send/modify/replay HTTP requests (like Burp Repeater)."""

    def __init__(self, timeout: int = 15, verify_ssl: bool = False,
                 proxy: Optional[str] = None) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.history: List[RequestResponsePair] = []
        self._session = requests.Session()
        if proxy:
            self._session.proxies = {"http": proxy, "https": proxy}
        self._session.verify = verify_ssl

    def send(self, req: HTTPRequest) -> RequestResponsePair:
        """Send an HTTP request and record the exchange."""
        try:
            resp = self._session.request(
                method=req.method, url=req.url,
                headers=req.headers or None,
                params=req.params or None,
                data=req.body or None,
                cookies=req.cookies or None,
                timeout=self.timeout, allow_redirects=False,
            )
            http_resp = HTTPResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:50000],
                elapsed=resp.elapsed.total_seconds(),
                size=len(resp.content),
            )
        except Exception as exc:
            http_resp = HTTPResponse(status_code=0, body=f"Error: {exc}")

        pair = RequestResponsePair(request=req, response=http_resp)
        self.history.append(pair)
        return pair

    def send_raw(self, method: str, url: str, headers: Optional[Dict] = None,
                 params: Optional[Dict] = None, body: str = "",
                 cookies: Optional[Dict] = None) -> RequestResponsePair:
        """Convenience: build HTTPRequest from raw args and send."""
        req = HTTPRequest(method=method.upper(), url=url,
                          headers=headers or {}, params=params or {},
                          body=body, cookies=cookies or {})
        return self.send(req)

    def replay(self, index: int = -1) -> RequestResponsePair:
        """Replay a request from history."""
        if not self.history:
            return RequestResponsePair()
        pair = self.history[index]
        return self.send(pair.request.clone())

    def modify_and_send(self, index: int = -1, **changes: Any) -> RequestResponsePair:
        """Clone a historical request, apply changes, send."""
        if not self.history:
            return RequestResponsePair()
        req = self.history[index].request.clone()
        for key, val in changes.items():
            if hasattr(req, key):
                setattr(req, key, val)
        return self.send(req)

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [p.to_dict() for p in self.history[-limit:]]

    def clear_history(self) -> None:
        self.history.clear()

    def compare(self, idx_a: int, idx_b: int) -> Dict[str, Any]:
        """Compare two responses (useful for blind injection)."""
        if idx_a >= len(self.history) or idx_b >= len(self.history):
            return {"error": "Index out of range"}
        a = self.history[idx_a].response
        b = self.history[idx_b].response
        if not a or not b:
            return {"error": "Missing response"}
        return {
            "status_diff": a.status_code != b.status_code,
            "status_a": a.status_code, "status_b": b.status_code,
            "size_diff": abs(a.size - b.size),
            "time_diff": round(abs(a.elapsed - b.elapsed), 3),
            "body_same": a.body == b.body,
        }


# ---------------------------------------------------------------------------
# Intruder — parameter fuzzing / brute forcing
# ---------------------------------------------------------------------------

class Intruder:
    """Parameter fuzzing engine (like Burp Intruder)."""

    def __init__(self, repeater: Optional[Repeater] = None) -> None:
        self.repeater = repeater or Repeater()

    def sniper(self, base_req: HTTPRequest, param: str,
               payloads: List[str], location: str = "params") -> List[Dict[str, Any]]:
        """Sniper mode: replace one parameter with each payload."""
        results = []
        for payload in payloads:
            req = base_req.clone()
            if location == "params":
                req.params[param] = payload
            elif location == "body":
                req.body = req.body.replace(f"{{{param}}}", payload)
            elif location == "headers":
                req.headers[param] = payload
            elif location == "url":
                req.url = req.url.replace(f"{{{param}}}", payload)
            pair = self.repeater.send(req)
            resp = pair.response
            results.append({
                "payload": payload,
                "status": resp.status_code if resp else 0,
                "size": resp.size if resp else 0,
                "time": resp.elapsed if resp else 0,
                "body_preview": resp.body[:200] if resp else "",
            })
        return results

    def battering_ram(self, base_req: HTTPRequest,
                      payloads: List[str], markers: List[str]) -> List[Dict[str, Any]]:
        """Battering ram: same payload in all marker positions."""
        results = []
        for payload in payloads:
            req = base_req.clone()
            for marker in markers:
                req.params = {k: v.replace(marker, payload) for k, v in req.params.items()}
                req.body = req.body.replace(marker, payload)
                req.url = req.url.replace(marker, payload)
            pair = self.repeater.send(req)
            resp = pair.response
            results.append({
                "payload": payload,
                "status": resp.status_code if resp else 0,
                "size": resp.size if resp else 0,
                "time": resp.elapsed if resp else 0,
            })
        return results

    def fuzz_params(self, url: str, params: Dict[str, str],
                    payloads: List[str], method: str = "GET") -> Dict[str, List[Dict]]:
        """Fuzz all parameters with all payloads, report anomalies."""
        all_results: Dict[str, List[Dict]] = {}

        # Baseline
        base_req = HTTPRequest(method=method, url=url, params=params)
        base_pair = self.repeater.send(base_req)
        base_status = base_pair.response.status_code if base_pair.response else 0
        base_size = base_pair.response.size if base_pair.response else 0

        for param in params:
            results = self.sniper(base_req, param, payloads, "params")
            # Mark anomalies
            for r in results:
                r["anomaly"] = (
                    r["status"] != base_status
                    or abs(r["size"] - base_size) > 100
                    or r["time"] > 3.0
                )
            all_results[param] = results

        return all_results

    def summary(self, results: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Summarize fuzz results, highlight anomalies."""
        summary: Dict[str, Any] = {"total_requests": 0, "anomalies": []}
        for param, items in results.items():
            summary["total_requests"] += len(items)
            for r in items:
                if r.get("anomaly"):
                    summary["anomalies"].append({
                        "param": param, "payload": r["payload"],
                        "status": r["status"], "size": r["size"],
                        "time": r["time"],
                    })
        summary["anomaly_count"] = len(summary["anomalies"])
        return summary

    def cluster_bomb(self, base_req: HTTPRequest,
                     param_payloads: Dict[str, List[str]],
                     location: str = "params") -> List[Dict[str, Any]]:
        """Cluster Bomb: cartesian product of payloads across multiple params.
        param_payloads = {"user": ["admin","root"], "pass": ["123","password"]}
        Generates: admin/123, admin/password, root/123, root/password"""
        import itertools
        params = list(param_payloads.keys())
        payload_lists = [param_payloads[p] for p in params]
        results = []
        for combo in itertools.product(*payload_lists):
            req = base_req.clone()
            combo_dict = dict(zip(params, combo))
            if location == "params":
                req.params.update(combo_dict)
            elif location == "body":
                for k, v in combo_dict.items():
                    req.body = req.body.replace(f"{{{k}}}", v)
            pair = self.repeater.send(req)
            resp = pair.response
            results.append({
                "payloads": combo_dict,
                "status": resp.status_code if resp else 0,
                "size": resp.size if resp else 0,
                "time": resp.elapsed if resp else 0,
                "body_preview": resp.body[:150] if resp else "",
            })
        return results

    def pitchfork(self, base_req: HTTPRequest,
                  param_payloads: Dict[str, List[str]],
                  location: str = "params") -> List[Dict[str, Any]]:
        """Pitchfork: paired iteration (param1[i] + param2[i] together).
        All payload lists must be same length."""
        params = list(param_payloads.keys())
        lists = [param_payloads[p] for p in params]
        min_len = min(len(l) for l in lists) if lists else 0
        results = []
        for i in range(min_len):
            req = base_req.clone()
            combo_dict = {p: lists[j][i] for j, p in enumerate(params)}
            if location == "params":
                req.params.update(combo_dict)
            pair = self.repeater.send(req)
            resp = pair.response
            results.append({
                "payloads": combo_dict,
                "status": resp.status_code if resp else 0,
                "size": resp.size if resp else 0,
                "time": resp.elapsed if resp else 0,
            })
        return results
