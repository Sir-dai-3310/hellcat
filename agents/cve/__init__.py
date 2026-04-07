"""
Hellcat CVE Intelligence Manager
=================================
Multi-source CVE sync (NVD/Nuclei/ExploitDB), auto-exploit,
AI PoC generation, vulnerability correlation, offline PoC lookup.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

from hellcat.core.cve import CVETemplateManager
from hellcat.core.models import CVERecord, Severity

logger = logging.getLogger("hellcat.cve_intel")


class CVEDatabase:
    """In-memory CVE record storage with search and filter."""
    def __init__(self) -> None:
        self._records: Dict[str, CVERecord] = {}
        self._last_sync: float = 0.0

    def add(self, record: CVERecord) -> None:
        self._records[record.cve_id] = record

    def get(self, cve_id: str) -> Optional[CVERecord]:
        return self._records.get(cve_id)

    def search(self, query: str, limit: int = 20) -> List[CVERecord]:
        q = query.lower()
        return [r for r in self._records.values()
                if q in r.cve_id.lower() or q in r.description.lower()][:limit]

    def filter_exploitable(self) -> List[CVERecord]:
        return [r for r in self._records.values() if r.exploit_available]

    @property
    def count(self) -> int:
        return len(self._records)

    def stats(self) -> Dict[str, Any]:
        sev: Dict[str, int] = {}
        exp = 0
        for r in self._records.values():
            sev[r.severity.value] = sev.get(r.severity.value, 0) + 1
            if r.exploit_available:
                exp += 1
        return {"total": self.count, "exploitable": exp, "by_severity": sev}


class NVDSyncer:
    """Fetch CVE records from NVD API."""
    BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def sync(self, keyword: str = "", limit: int = 50) -> List[CVERecord]:
        records: List[CVERecord] = []
        try:
            import requests
            params: Dict[str, Any] = {"resultsPerPage": min(limit, 100)}
            if keyword:
                params["keywordSearch"] = keyword
            resp = requests.get(self.BASE, params=params, timeout=30)
            if resp.status_code != 200:
                return records
            for vuln in resp.json().get("vulnerabilities", [])[:limit]:
                cve = vuln.get("cve", {})
                desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                cvss = 0.0
                for k in ("cvssMetricV31", "cvssMetricV30"):
                    if k in cve.get("metrics", {}):
                        cvss = cve["metrics"][k][0].get("cvssData", {}).get("baseScore", 0.0)
                        break
                sev = (Severity.CRITICAL if cvss >= 9 else Severity.HIGH if cvss >= 7
                       else Severity.MEDIUM if cvss >= 4 else Severity.LOW if cvss > 0 else Severity.INFO)
                records.append(CVERecord(cve_id=cve.get("id", ""), description=desc,
                                         cvss_score=cvss, severity=sev))
        except Exception as exc:
            logger.warning("NVD sync: %s", exc)
        return records


class AutoExploitEngine:
    """Three-tier exploit: template -> offline PoC -> AI generation."""
    def __init__(self, ai_engine: Any = None) -> None:
        self._ai = ai_engine
        self._offline = OfflinePoCLookup()

    def search_and_exploit(self, cve_id: str, target: str) -> Dict[str, Any]:
        # 1. Built-in 2026 templates (fastest)
        tpl = CVETemplateManager.get(cve_id)
        if tpl:
            return {"status": "template_found", "cve_id": cve_id, "template": tpl.name,
                    "check": tpl.check_payload, "exploit": tpl.exploit_payload}

        # 2. Offline PoC index (22K+ curated links, instant)
        pocs = self._offline.lookup(cve_id)
        if pocs:
            return {"status": "poc_found", "cve_id": cve_id,
                    "poc_count": len(pocs), "pocs": pocs[:5]}

        # 3. AI PoC generation (slowest, requires API key)
        if self._ai:
            try:
                poc = self._ai.generate_poc(cve_id, {"target": target})
                return {"status": "ai_generated", "cve_id": cve_id, "poc_code": poc}
            except Exception:
                pass
        return {"status": "no_exploit", "cve_id": cve_id}


class VulnerabilityCorrelator:
    """Discover exploit chains from multiple vulnerability findings."""
    PATHS = [
        (["sqli"], ["rce"], "SQLi -> RCE via stacked queries"),
        (["ssrf"], ["cloud_metadata"], "SSRF -> Cloud credential theft"),
        (["lfi", "path_traversal"], ["rce"], "LFI -> Log poisoning -> RCE"),
        (["xss"], ["session_hijack"], "XSS -> Session hijacking"),
        (["idor"], ["data_exfil"], "IDOR -> Mass data exfiltration"),
        (["auth_bypass"], ["privesc"], "Auth bypass -> Privilege escalation"),
        (["open_redirect"], ["phishing", "oauth_theft"], "Open Redirect -> OAuth token theft"),
        (["crlf"], ["xss", "cache_poison"], "CRLF -> Response splitting -> Cache poisoning"),
        (["prototype_pollution"], ["xss", "rce"], "Prototype Pollution -> XSS/RCE gadget"),
        (["http_smuggling"], ["cache_poison", "auth_bypass"], "Smuggling -> Request routing bypass"),
        (["subdomain_takeover"], ["phishing", "cookie_theft"], "Subdomain Takeover -> Cookie/session theft"),
        (["ssrf", "open_redirect"], ["cloud_rce"], "SSRF+Redirect -> Internal service RCE"),
        (["api_idor", "sqli"], ["full_dump"], "API IDOR + SQLi -> Full database dump"),
        (["secret_leak"], ["account_takeover"], "Leaked API key -> Account takeover"),
    ]

    @classmethod
    def correlate(cls, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        types = {v.get("vuln_type", "").lower() for v in vulns}
        return [{"trigger": t, "escalation": e, "desc": d}
                for t, e, d in cls.PATHS if any(x in types for x in t)]


class CVEIntelligenceManager:
    """Unified CVE intelligence: search, sync, exploit, correlate."""
    def __init__(self, ai_engine: Any = None) -> None:
        self.db = CVEDatabase()
        self.nvd = NVDSyncer()
        self.exploit = AutoExploitEngine(ai_engine)
        self.correlator = VulnerabilityCorrelator()
        self.offline_poc = OfflinePoCLookup()

    def sync(self, keyword: str = "", limit: int = 50) -> Dict[str, Any]:
        recs = self.nvd.sync(keyword, limit)
        for r in recs:
            self.db.add(r)
        self.db._last_sync = time.time()
        return {"synced": len(recs), "total": self.db.count}

    def search(self, query: str) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.db.search(query)]

    def auto_exploit(self, cve_id: str, target: str) -> Dict[str, Any]:
        return self.exploit.search_and_exploit(cve_id, target)

    def correlate(self, findings: List[Dict]) -> List[Dict]:
        return self.correlator.correlate(findings)

    def match_target(self, info: Dict) -> List[Dict]:
        return [{"cve_id": t.cve_id, "name": t.name, "cvss": t.cvss}
                for t in CVETemplateManager.match_target(info)]

    def poc_lookup(self, cve_id: str) -> List[Dict[str, Any]]:
        """Offline PoC lookup from curated index (22K+ links, 10K+ CVEs)."""
        return self.offline_poc.lookup(cve_id)

    def poc_stats(self) -> Dict[str, Any]:
        return self.offline_poc.stats()


# ---------------------------------------------------------------------------
# Offline PoC Lookup (from cve-main curated index)
# ---------------------------------------------------------------------------

class OfflinePoCLookup:
    """Fast CVE -> PoC URL lookup from pre-filtered github.txt index.
    Only contains dedicated PoC repos (repo name matches CVE ID),
    with aggregator/spider repos blacklisted.
    Source: trickest/cve project, filtered by poc_scoring quality rules.
    """

    def __init__(self, index_path: Optional[str] = None) -> None:
        self._index: Dict[str, List[str]] = {}
        self._loaded = False
        self._path = index_path or self._default_path()

    @staticmethod
    def _default_path() -> str:
        here = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(here, "..", "..", "config", "poc_index.tsv")

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        path = self._path
        if not os.path.exists(path):
            logger.warning("PoC index not found: %s", path)
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or "\t" not in line:
                        continue
                    cve_id, url = line.split("\t", 1)
                    self._index.setdefault(cve_id.strip(), []).append(url.strip())
            logger.info("PoC index loaded: %d CVEs, %d links",
                        len(self._index), sum(len(v) for v in self._index.values()))
        except Exception as exc:
            logger.error("Failed to load PoC index: %s", exc)

    def lookup(self, cve_id: str) -> List[Dict[str, Any]]:
        """Return list of PoC repos for a CVE ID."""
        self._ensure_loaded()
        cve_id = cve_id.strip().upper()
        urls = self._index.get(cve_id, [])
        results = []
        for url in urls:
            parts = url.replace("https://github.com/", "").split("/")
            repo_name = parts[1] if len(parts) >= 2 else ""
            owner = parts[0] if len(parts) >= 1 else ""
            results.append({
                "cve_id": cve_id,
                "url": url,
                "repo": f"{owner}/{repo_name}",
                "source": "offline_index",
            })
        return results

    def has_poc(self, cve_id: str) -> bool:
        self._ensure_loaded()
        return cve_id.strip().upper() in self._index

    def stats(self) -> Dict[str, Any]:
        self._ensure_loaded()
        return {
            "total_cves": len(self._index),
            "total_links": sum(len(v) for v in self._index.values()),
            "loaded": self._loaded,
            "index_path": self._path,
        }
