"""
Hellcat Identity Attack Chain (2026 Tactics)
============================================
AiTM proxy, MFA fatigue, SIM swap simulation, Cloud IAM enumeration,
OAuth token theft — based on Scattered Spider TTPs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class IdentityAttackStep:
    name: str = ""
    technique: str = ""
    mitre_id: str = ""
    description: str = ""
    tools: List[str] = field(default_factory=list)
    success_probability: float = 0.0
    detection_risk: float = 0.0
    prerequisites: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pre-built attack chains
# ---------------------------------------------------------------------------

AITM_CHAIN: List[IdentityAttackStep] = [
    IdentityAttackStep(
        "phishing_setup", "Adversary-in-the-Middle", "T1557.001",
        "Deploy AiTM proxy (evilginx2/modlishka) to intercept auth tokens",
        ["evilginx2", "modlishka", "muraena"], 0.7, 0.6,
    ),
    IdentityAttackStep(
        "credential_harvest", "Credential Harvesting", "T1056.004",
        "Capture username, password, and session tokens via proxy",
        ["evilginx2"], 0.8, 0.4,
        ["phishing_setup"],
    ),
    IdentityAttackStep(
        "session_hijack", "Session Hijacking", "T1550.004",
        "Replay captured session cookie to bypass MFA",
        ["browser", "requests"], 0.9, 0.3,
        ["credential_harvest"],
    ),
]

MFA_FATIGUE_CHAIN: List[IdentityAttackStep] = [
    IdentityAttackStep(
        "cred_obtain", "Valid Credentials", "T1078",
        "Obtain valid username/password via phishing or credential stuffing",
        ["hydra", "custom"], 0.5, 0.5,
    ),
    IdentityAttackStep(
        "mfa_push_spam", "MFA Fatigue", "T1621",
        "Send repeated MFA push notifications until user approves",
        ["custom"], 0.35, 0.7,
        ["cred_obtain"],
    ),
    IdentityAttackStep(
        "account_access", "Account Access", "T1078",
        "Login with approved MFA to gain full account access",
        ["browser"], 0.9, 0.2,
        ["mfa_push_spam"],
    ),
]

CLOUD_IAM_CHAIN: List[IdentityAttackStep] = [
    IdentityAttackStep(
        "iam_enum", "Cloud Account Discovery", "T1087.004",
        "Enumerate IAM users, roles, policies in AWS/Azure/GCP",
        ["prowler", "scout_suite", "pacu"], 0.85, 0.3,
    ),
    IdentityAttackStep(
        "privesc_iam", "Cloud Privilege Escalation", "T1548",
        "Exploit overpermissioned roles or policy misconfigurations",
        ["pacu", "prowler"], 0.4, 0.5,
        ["iam_enum"],
    ),
    IdentityAttackStep(
        "token_theft", "Cloud Token Theft", "T1528",
        "Steal OAuth/OIDC tokens or service account keys",
        ["custom", "trufflehog"], 0.5, 0.4,
        ["iam_enum"],
    ),
    IdentityAttackStep(
        "lateral_cloud", "Cloud Lateral Movement", "T1550.001",
        "Use stolen tokens to access other cloud resources",
        ["awscli", "az", "gcloud"], 0.6, 0.3,
        ["token_theft"],
    ),
]

ALL_CHAINS: Dict[str, List[IdentityAttackStep]] = {
    "aitm": AITM_CHAIN,
    "mfa_fatigue": MFA_FATIGUE_CHAIN,
    "cloud_iam": CLOUD_IAM_CHAIN,
}


class IdentityAttackManager:
    """Manage and generate identity-based attack chains."""

    @staticmethod
    def get_chain(name: str) -> List[IdentityAttackStep]:
        return ALL_CHAINS.get(name, [])

    @staticmethod
    def list_chains() -> List[str]:
        return list(ALL_CHAINS.keys())

    @staticmethod
    def get_chain_summary(name: str) -> Dict[str, Any]:
        chain = ALL_CHAINS.get(name, [])
        if not chain:
            return {"error": f"Chain '{name}' not found"}
        total_prob = 1.0
        for step in chain:
            total_prob *= step.success_probability
        return {
            "name": name,
            "steps": len(chain),
            "total_success_probability": round(total_prob, 4),
            "avg_detection_risk": round(sum(s.detection_risk for s in chain) / len(chain), 2),
            "required_tools": list({t for s in chain for t in s.tools}),
            "mitre_techniques": [s.mitre_id for s in chain],
            "step_names": [s.name for s in chain],
        }

    @staticmethod
    def get_all_summaries() -> List[Dict[str, Any]]:
        return [IdentityAttackManager.get_chain_summary(n) for n in ALL_CHAINS]
