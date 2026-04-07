"""
Hellcat Continuous Monitoring + Notifications
==============================================
Inspired by reNgine: scheduled scans, diff detection, webhook alerts.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("hellcat.monitor")


@dataclass
class ScanSnapshot:
    target: str = ""
    timestamp: float = field(default_factory=time.time)
    open_ports: List[int] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        raw = json.dumps({"ports": sorted(self.open_ports),
                          "subs": sorted(self.subdomains),
                          "findings": len(self.findings)}, sort_keys=True)
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return self.fingerprint


class DiffDetector:
    """Compare two scan snapshots and report changes."""

    @staticmethod
    def diff(old: ScanSnapshot, new: ScanSnapshot) -> Dict[str, Any]:
        new_ports = set(new.open_ports) - set(old.open_ports)
        closed_ports = set(old.open_ports) - set(new.open_ports)
        new_subs = set(new.subdomains) - set(old.subdomains)
        removed_subs = set(old.subdomains) - set(new.subdomains)
        new_findings = len(new.findings) - len(old.findings)
        changed = bool(new_ports or closed_ports or new_subs or removed_subs or new_findings)
        return {
            "changed": changed,
            "new_ports": sorted(new_ports),
            "closed_ports": sorted(closed_ports),
            "new_subdomains": sorted(new_subs),
            "removed_subdomains": sorted(removed_subs),
            "finding_delta": new_findings,
            "old_fingerprint": old.fingerprint,
            "new_fingerprint": new.fingerprint,
        }


class WebhookNotifier:
    """Send alerts to Discord/Slack/Telegram webhooks."""

    def __init__(self) -> None:
        self._hooks: Dict[str, str] = {}  # name -> url

    def add_webhook(self, name: str, url: str) -> None:
        self._hooks[name] = url

    def notify(self, message: str, data: Optional[Dict] = None) -> Dict[str, bool]:
        results = {}
        for name, url in self._hooks.items():
            try:
                import requests
                if "discord" in url:
                    payload = {"content": message}
                elif "slack" in url:
                    payload = {"text": message}
                elif "telegram" in url:
                    # url format: https://api.telegram.org/bot<token>/sendMessage?chat_id=<id>
                    payload = {"text": message}
                else:
                    payload = {"message": message, "data": data or {}}
                resp = requests.post(url, json=payload, timeout=10)
                results[name] = resp.status_code < 400
            except Exception as exc:
                logger.warning("Webhook %s failed: %s", name, exc)
                results[name] = False
        return results

    def notify_changes(self, target: str, diff: Dict[str, Any]) -> Dict[str, bool]:
        if not diff.get("changed"):
            return {}
        parts = [f"🔔 **Hellcat Monitor Alert** — `{target}`"]
        if diff["new_ports"]:
            parts.append(f"🆕 New ports: {diff['new_ports']}")
        if diff["closed_ports"]:
            parts.append(f"❌ Closed ports: {diff['closed_ports']}")
        if diff["new_subdomains"]:
            parts.append(f"🌐 New subdomains: {diff['new_subdomains'][:5]}")
        if diff["finding_delta"] > 0:
            parts.append(f"⚠️ {diff['finding_delta']} new findings")
        return self.notify("\n".join(parts), diff)


class ContinuousMonitor:
    """Scheduled periodic scanning with change detection."""

    def __init__(self, interval_minutes: int = 60) -> None:
        self.interval = interval_minutes * 60
        self.notifier = WebhookNotifier()
        self._targets: Dict[str, ScanSnapshot] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def add_target(self, target: str) -> None:
        if target not in self._targets:
            self._targets[target] = ScanSnapshot(target=target)

    def add_webhook(self, name: str, url: str) -> None:
        self.notifier.add_webhook(name, url)

    def scan_target(self, target: str) -> Dict[str, Any]:
        """Run quick scan and compare with previous snapshot."""
        from hellcat.core.engine import ScanEngine
        engine = ScanEngine()
        result = engine.execute("quick_scan", target)

        # Build new snapshot
        new_snap = ScanSnapshot(target=target)
        for phase in result.phases:
            for r in phase.results:
                stdout = r.get("stdout", "")
                # Extract ports from nmap output
                import re
                for m in re.finditer(r"(\d+)/tcp\s+open", stdout):
                    new_snap.open_ports.append(int(m.group(1)))
        new_snap.findings = result.findings
        new_snap.compute_fingerprint()

        # Compare with previous
        old_snap = self._targets.get(target, ScanSnapshot(target=target))
        old_snap.compute_fingerprint()
        diff = DiffDetector.diff(old_snap, new_snap)

        # Update snapshot
        self._targets[target] = new_snap

        # Notify if changed
        if diff["changed"]:
            self.notifier.notify_changes(target, diff)

        return {"target": target, "diff": diff, "scan": result.to_dict()}

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("Continuous monitor started (interval=%dm)", self.interval // 60)

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            for target in list(self._targets.keys()):
                try:
                    self.scan_target(target)
                except Exception as exc:
                    logger.error("Monitor scan failed for %s: %s", target, exc)
            time.sleep(self.interval)

    def status(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "targets": list(self._targets.keys()),
            "interval_minutes": self.interval // 60,
            "webhooks": list(self.notifier._hooks.keys()),
        }
