"""
Hellcat CTF Solver Workflow
============================
7-category challenge support (Web/Crypto/Pwn/Forensics/Rev/Misc/OSINT).
Auto-categorize, suggest tools, generate solving strategies.
GEF integrated as default Pwn debugger (Kali 2026.1).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class CTFChallenge:
    """CTF challenge metadata."""
    name: str = ""
    category: str = ""    # web, crypto, pwn, forensics, rev, misc, osint
    description: str = ""
    points: int = 0
    difficulty: str = "unknown"  # easy, medium, hard, insane
    files: List[str] = field(default_factory=list)
    url: str = ""
    hints: List[str] = field(default_factory=list)


CATEGORY_TOOLS: Dict[str, Dict[str, List[str]]] = {
    "web": {
        "recon": ["httpx", "ffuf", "katana", "nikto"],
        "vuln_scan": ["nuclei", "sqlmap", "xsstrike", "sstimap"],
        "exploit": ["burpsuite", "browser_agent", "curl"],
    },
    "crypto": {
        "hash": ["john", "hashcat", "hash-identifier"],
        "cipher": ["openssl", "python3", "cyberchef"],
        "rsa": ["rsactftool", "python3"],
    },
    "pwn": {
        "analysis": ["checksec", "file", "strings", "gef"],
        "exploit_dev": ["pwntools", "gef", "ropper", "one_gadget"],
        "debugging": ["gef", "strace", "ltrace"],
    },
    "forensics": {
        "memory": ["volatility3", "strings"],
        "disk": ["autopsy", "foremost", "binwalk"],
        "steganography": ["steghide", "zsteg", "exiftool"],
    },
    "rev": {
        "static": ["ghidra", "radare2", "strings", "objdump"],
        "dynamic": ["gef", "strace", "ltrace"],
        "symbolic": ["angr", "z3"],
    },
    "misc": {
        "general": ["python3", "cyberchef", "xxd"],
        "network": ["wireshark", "tshark", "tcpdump"],
    },
    "osint": {
        "search": ["sherlock", "theharvester", "amass"],
        "domain": ["whois", "dig", "nslookup"],
    },
}

DIFFICULTY_TIME: Dict[str, int] = {
    "easy": 15, "medium": 45, "hard": 120, "insane": 300, "unknown": 60,
}

SOLVING_STRATEGIES: Dict[str, List[Dict[str, str]]] = {
    "web": [
        {"step": "Enumerate endpoints", "tool": "ffuf/katana"},
        {"step": "Identify tech stack", "tool": "httpx/wappalyzer"},
        {"step": "Test injection points", "tool": "sqlmap/xsstrike/sstimap"},
        {"step": "Check auth bypass", "tool": "nuclei/manual"},
        {"step": "Exploit and capture flag", "tool": "curl/browser"},
    ],
    "pwn": [
        {"step": "Check binary protections", "tool": "checksec"},
        {"step": "Analyze with GEF/Ghidra", "tool": "gef/ghidra"},
        {"step": "Find vulnerability", "tool": "gef + manual analysis"},
        {"step": "Build exploit with pwntools", "tool": "pwntools"},
        {"step": "Find gadgets if needed", "tool": "ropper/one_gadget"},
        {"step": "Test and submit flag", "tool": "pwntools"},
    ],
    "crypto": [
        {"step": "Identify cipher/hash type", "tool": "hash-identifier/analysis"},
        {"step": "Check for known weaknesses", "tool": "factordb/rsactftool"},
        {"step": "Implement attack", "tool": "python3/sage"},
        {"step": "Decrypt and get flag", "tool": "python3"},
    ],
    "forensics": [
        {"step": "Identify file type", "tool": "file/binwalk"},
        {"step": "Extract metadata", "tool": "exiftool"},
        {"step": "Check for hidden data", "tool": "steghide/zsteg/foremost"},
        {"step": "Analyze memory if dump", "tool": "volatility3"},
        {"step": "Find flag in extracted data", "tool": "grep/strings"},
    ],
    "rev": [
        {"step": "Static analysis", "tool": "ghidra/strings"},
        {"step": "Dynamic analysis", "tool": "gef/strace"},
        {"step": "Understand logic", "tool": "manual/ghidra"},
        {"step": "Patch or keygen", "tool": "python3/ghidra"},
    ],
}


class CTFWorkflowManager:
    """Generate CTF challenge solving workflows."""

    @staticmethod
    def create_workflow(challenge: CTFChallenge) -> Dict[str, Any]:
        cat = challenge.category.lower() if challenge.category else "misc"
        tools = CATEGORY_TOOLS.get(cat, CATEGORY_TOOLS["misc"])
        strategies = SOLVING_STRATEGIES.get(cat, [{"step": "Analyze challenge", "tool": "manual"}])
        all_tools = [t for group in tools.values() for t in group]
        est_time = DIFFICULTY_TIME.get(challenge.difficulty, 60)

        return {
            "challenge": challenge.name,
            "category": cat,
            "difficulty": challenge.difficulty,
            "points": challenge.points,
            "tools_by_phase": tools,
            "all_tools": list(dict.fromkeys(all_tools)),
            "strategies": strategies,
            "estimated_time_minutes": est_time,
            "automation_level": "high" if cat in ("web", "forensics") else "medium",
        }

    @staticmethod
    def suggest_category(description: str, files: List[str] = None) -> str:
        desc = description.lower()
        fnames = " ".join(files or []).lower()
        if any(k in desc for k in ("sql", "xss", "http", "web", "login", "cookie", "session")):
            return "web"
        if any(k in desc for k in ("rsa", "aes", "cipher", "encrypt", "decrypt", "hash")):
            return "crypto"
        if any(k in desc + fnames for k in ("elf", "binary", "overflow", "pwn", ".so")):
            return "pwn"
        if any(k in desc + fnames for k in ("memory", "dump", "pcap", "image", "disk", "forensic")):
            return "forensics"
        if any(k in desc + fnames for k in ("reverse", "crack", "keygen", "obfuscat")):
            return "rev"
        if any(k in desc for k in ("osint", "find", "person", "location", "social")):
            return "osint"
        return "misc"

    @staticmethod
    def list_categories() -> List[str]:
        return list(CATEGORY_TOOLS.keys())
