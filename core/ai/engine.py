"""
Hellcat Multi-Model AI Engine
=============================
Unified interface to OpenAI / Anthropic / Ollama backends.
Used for attack planning, PoC generation, smart payload crafting,
and target analysis.  Falls back gracefully when a provider is unavailable.
"""
from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from hellcat.core.models import (
    AttackChain, AttackStep, RiskLevel, TargetProfile, TargetType,
)

logger = logging.getLogger("hellcat.ai")

# Constants
DEFAULT_TEMPERATURE = 0.3
DEFAULT_MAX_TOKENS = 4096
AI_TIMEOUT = 120


# ---------------------------------------------------------------------------
# Provider abstraction
# ---------------------------------------------------------------------------

class BaseProvider(ABC):
    name: str = "base"

    @abstractmethod
    def complete(self, prompt: str, system: str = "", **kw: Any) -> str: ...

    @abstractmethod
    def is_available(self) -> bool: ...


class OpenAIProvider(BaseProvider):
    name = "openai"

    def __init__(self) -> None:
        self._key = os.environ.get("OPENAI_API_KEY", "")
        self._model = os.environ.get("HELLCAT_OPENAI_MODEL", "gpt-4o")
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            import openai
            self._client = openai.OpenAI(api_key=self._key)
        return self._client

    def is_available(self) -> bool:
        return bool(self._key)

    def complete(self, prompt: str, system: str = "", **kw: Any) -> str:
        msgs: list[dict] = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        resp = self._get_client().chat.completions.create(
            model=kw.get("model", self._model),
            messages=msgs,
            temperature=kw.get("temperature", 0.3),
            max_tokens=kw.get("max_tokens", 4096),
        )
        return resp.choices[0].message.content or ""


class AnthropicProvider(BaseProvider):
    name = "anthropic"

    def __init__(self) -> None:
        self._key = os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = os.environ.get("HELLCAT_ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self._key)
        return self._client

    def is_available(self) -> bool:
        return bool(self._key)

    def complete(self, prompt: str, system: str = "", **kw: Any) -> str:
        resp = self._get_client().messages.create(
            model=kw.get("model", self._model),
            max_tokens=kw.get("max_tokens", 4096),
            system=system or "You are a cybersecurity expert.",
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text if resp.content else ""


class OllamaProvider(BaseProvider):
    name = "ollama"

    def __init__(self) -> None:
        self._base = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self._model = os.environ.get("HELLCAT_OLLAMA_MODEL", "llama3")

    def is_available(self) -> bool:
        try:
            import requests
            r = requests.get(f"{self._base}/api/tags", timeout=2)
            return r.status_code == 200
        except Exception:
            return False

    def complete(self, prompt: str, system: str = "", **kw: Any) -> str:
        import requests
        payload = {
            "model": kw.get("model", self._model),
            "prompt": prompt,
            "system": system or "You are a cybersecurity expert.",
            "stream": False,
        }
        r = requests.post(f"{self._base}/api/generate", json=payload, timeout=120)
        return r.json().get("response", "")


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

class ProviderRegistry:
    """Auto-detects and manages available LLM providers."""

    def __init__(self) -> None:
        self._providers: list[BaseProvider] = []
        self._active: Optional[BaseProvider] = None
        self._init_providers()

    def _init_providers(self) -> None:
        candidates = [OpenAIProvider(), AnthropicProvider(), OllamaProvider()]
        for p in candidates:
            try:
                if p.is_available():
                    self._providers.append(p)
                    logger.info("AI provider available: %s", p.name)
            except Exception:
                pass
        if self._providers:
            self._active = self._providers[0]
            logger.info("Active AI provider: %s", self._active.name)
        else:
            logger.warning("No AI provider available — AI features disabled")

    @property
    def active(self) -> Optional[BaseProvider]:
        return self._active

    @property
    def available_providers(self) -> list[str]:
        return [p.name for p in self._providers]

    def set_active(self, name: str) -> bool:
        for p in self._providers:
            if p.name == name:
                self._active = p
                return True
        return False

    def complete(self, prompt: str, system: str = "", **kw: Any) -> str:
        if not self._active:
            return "[AI unavailable] No provider configured"
        try:
            return self._active.complete(prompt, system, **kw)
        except Exception as exc:
            logger.error("AI completion failed (%s): %s", self._active.name, exc)
            # Fallback to next provider
            for p in self._providers:
                if p is not self._active:
                    try:
                        return p.complete(prompt, system, **kw)
                    except Exception:
                        continue
            return f"[AI error] {exc}"


# ---------------------------------------------------------------------------
# Tool effectiveness ratings (merged from both projects)
# ---------------------------------------------------------------------------

TOOL_EFFECTIVENESS: Dict[str, Dict[str, float]] = {
    "web_application": {
        "nmap": 0.8, "nuclei": 0.95, "sqlmap": 0.9, "ffuf": 0.85,
        "xsstrike": 0.88, "sstimap": 0.85, "nikto": 0.75, "dalfox": 0.87,
        "katana": 0.8, "feroxbuster": 0.82,
    },
    "network_host": {
        "nmap": 0.95, "masscan": 0.92, "rustscan": 0.90,
        "hydra": 0.85, "netexec": 0.88, "enum4linux": 0.82,
    },
    "api_endpoint": {
        "ffuf": 0.85, "arjun": 0.95, "nuclei": 0.88,
        "sqlmap": 0.82, "graphql_scanner": 0.90,
    },
    "cloud_service": {
        "prowler": 0.95, "scout_suite": 0.92, "trivy": 0.90, "checkov": 0.88,
    },
    "binary_file": {
        "ghidra": 0.95, "radare2": 0.90, "angr": 0.88,
        "gef": 0.92, "checksec": 0.85, "pwntools": 0.90,
    },
}

# Technology signatures for detection
TECH_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "apache":    {"headers": ["Apache", "X-Powered-By: PHP"], "ports": [80, 443, 8080]},
    "nginx":     {"headers": ["nginx"], "ports": [80, 443]},
    "iis":       {"headers": ["Microsoft-IIS"], "ports": [80, 443]},
    "nodejs":    {"headers": ["X-Powered-By: Express"], "ports": [3000, 8080]},
    "wordpress": {"paths": ["/wp-admin", "/wp-login.php", "/wp-content"]},
    "django":    {"headers": ["csrftoken"], "paths": ["/admin/"]},
    "spring":    {"headers": ["X-Application-Context"], "paths": ["/actuator"]},
    "react":     {"indicators": ["__NEXT_DATA__", "react-root", "_reactRootContainer"]},
}


# ---------------------------------------------------------------------------
# AI Decision Engine
# ---------------------------------------------------------------------------

class AIEngine:
    """Hellcat's central AI decision-making engine."""

    def __init__(self) -> None:
        self.registry = ProviderRegistry()

    # -- Target analysis -----------------------------------------------------

    def analyze_target(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Identify target type, tech stack, attack surface."""
        ctx = context or {}
        target_type = self._identify_target_type(target)
        recommended = TOOL_EFFECTIVENESS.get(target_type, {})
        top_tools = sorted(recommended.items(), key=lambda x: x[1], reverse=True)[:10]

        analysis: Dict[str, Any] = {
            "target": target,
            "target_type": target_type,
            "recommended_tools": [{"tool": t, "effectiveness": e} for t, e in top_tools],
            "attack_surface": self._estimate_attack_surface(target_type, ctx),
            "risk_level": self._assess_risk_level(target_type, ctx),
        }

        # Optional AI enhancement
        if self.registry.active and ctx.get("ai_enhance", False):
            ai_result = self._ai_enhance(target, target_type, ctx)
            analysis["ai_insights"] = ai_result

        return analysis

    def _identify_target_type(self, target: str) -> str:
        t = target.lower()
        if any(t.startswith(p) for p in ("http://", "https://", "www.")):
            return "web_application"
        if "/api/" in t or t.endswith("/graphql"):
            return "api_endpoint"
        if any(c in t for c in ("aws", "azure", "gcp", "s3")):
            return "cloud_service"
        parts = t.replace(":", ".").split(".")
        if all(p.isdigit() for p in parts if p):
            return "network_host"
        if "." in t and not "/" in t:
            return "web_application"
        return "unknown"

    def _estimate_attack_surface(self, target_type: str, ctx: Dict) -> Dict[str, Any]:
        scores = {
            "web_application": 0.8, "network_host": 0.6, "api_endpoint": 0.7,
            "cloud_service": 0.5, "binary_file": 0.4, "unknown": 0.3,
        }
        return {"score": scores.get(target_type, 0.3), "ports_found": len(ctx.get("open_ports", []))}

    def _assess_risk_level(self, target_type: str, ctx: Dict) -> str:
        vulns = len(ctx.get("vulnerabilities", []))
        if vulns >= 5:
            return "critical"
        if vulns >= 3:
            return "high"
        if vulns >= 1:
            return "medium"
        return "low"

    # -- Attack plan generation ----------------------------------------------

    def generate_attack_plan(self, target: str, recon_data: Dict[str, Any]) -> AttackChain:
        """Generate ordered attack chain from recon data."""
        target_type = recon_data.get("target_type", self._identify_target_type(target))
        profile = TargetProfile(
            target=target,
            target_type=TargetType(target_type) if target_type in [t.value for t in TargetType] else TargetType.UNKNOWN,
            open_ports=recon_data.get("open_ports", []),
            technologies=recon_data.get("technologies", []),
        )
        chain = AttackChain(target_profile=profile)

        # Phase 1: Extended recon
        chain.add_step(AttackStep(
            tool="nmap", parameters={"scan_type": "-sV -sC", "target": target},
            expected_outcome="Service enumeration", success_probability=0.95,
            execution_time_estimate=60,
        ))

        # Phase 2: Vulnerability scanning
        if target_type == "web_application":
            chain.add_step(AttackStep(
                tool="nuclei", parameters={"target": target, "severity": "critical,high"},
                expected_outcome="CVE detection", success_probability=0.85,
                execution_time_estimate=120,
            ))
            chain.add_step(AttackStep(
                tool="sqlmap", parameters={"target": target, "level": 3, "risk": 2},
                expected_outcome="SQL injection", success_probability=0.6,
                execution_time_estimate=180,
            ))

        # Phase 3: Exploitation
        chain.add_step(AttackStep(
            tool="auto_exploit", parameters={"target": target},
            expected_outcome="Initial access", success_probability=0.4,
            execution_time_estimate=300,
        ))

        chain.calculate_success_probability()
        return chain

    # -- PoC generation ------------------------------------------------------

    def generate_poc(self, cve_id: str, target_info: Optional[Dict] = None) -> str:
        """Use LLM to generate exploit PoC code for a given CVE."""
        prompt = (
            f"Generate a Python proof-of-concept exploit for {cve_id}.\n"
            f"Target info: {json.dumps(target_info or {}, indent=2)}\n"
            "Include: imports, target URL parameter, exploit function, main block.\n"
            "Output ONLY the Python code, no explanation."
        )
        return self.registry.complete(
            prompt,
            system="You are an expert exploit developer for authorized penetration testing.",
        )

    # -- Smart payload -------------------------------------------------------

    def smart_payload(self, vuln_type: str, context: Optional[Dict] = None) -> List[str]:
        """AI-enhanced payload generation for a given vulnerability type."""
        ctx_str = json.dumps(context or {})
        prompt = (
            f"Generate 10 advanced {vuln_type} payloads for penetration testing.\n"
            f"Context: {ctx_str}\n"
            "Consider WAF bypass, encoding variants, and edge cases.\n"
            "Output as JSON array of strings."
        )
        raw = self.registry.complete(prompt, system="Cybersecurity payload expert.")
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            # Extract array from response
            start = raw.find("[")
            end = raw.rfind("]") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(raw[start:end])
                except Exception:
                    pass
            return [raw.strip()]

    # -- AI enhancement helper -----------------------------------------------

    def _ai_enhance(self, target: str, target_type: str, ctx: Dict) -> str:
        prompt = (
            f"Analyze target: {target} (type: {target_type})\n"
            f"Known info: {json.dumps({k: v for k, v in ctx.items() if k != 'ai_enhance'}, default=str)}\n"
            "Provide: attack vectors, priority tools, risk assessment. Be concise."
        )
        return self.registry.complete(prompt)
