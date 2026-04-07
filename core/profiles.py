"""
Hellcat Tool Profiles
=====================
Context-window-aware tool loading: compact / default / full / custom.
Inspired by HexStrike's profile-based loading — adapted for Hellcat's MCP architecture.

Profiles control which handler categories are loaded, keeping the MCP tool list
within the AI client's context window limits.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set

logger = logging.getLogger("hellcat.profiles")


class ProfileMode(Enum):
    COMPACT = "compact"      # minimal — 2-3 categories, ~20 tools
    DEFAULT = "default"      # recommended — core categories, ~60 tools
    FULL = "full"            # everything registered, ~120+ tools
    CUSTOM = "custom"        # user-specified include/exclude


# Handler category → (display, module, function)
ALL_HANDLER_CATEGORIES: Dict[str, tuple[str, str, str]] = {
    "recon":        ("Recon",             "hellcat.handlers.recon_handlers",     "register_recon_tools"),
    "detector":     ("Detector",          "hellcat.handlers.detector_handlers",  "register_detector_tools"),
    "cve":          ("CVE",               "hellcat.handlers.cve_handlers",       "register_cve_tools"),
    "redteam":      ("Red Team",          "hellcat.handlers.redteam_handlers",   "register_redteam_tools"),
    "ai":           ("AI Assisted",       "hellcat.handlers.cve_handlers",       "register_ai_tools"),
    "orchestration":("Orchestration",     "hellcat.handlers.cve_handlers",       "register_orchestration_tools"),
    "external":     ("External Tools",    "hellcat.handlers.cve_handlers",       "register_external_tools"),
    "bounty":       ("Bounty Hunter",     "hellcat.handlers.bounty_handlers",    "register_bounty_tools"),
    "advanced":     ("Advanced",          "hellcat.handlers.bounty_handlers",    "register_advanced_tools"),
}

# Profile definitions
PROFILE_CATEGORIES: Dict[ProfileMode, FrozenSet[str]] = {
    ProfileMode.COMPACT: frozenset({"recon", "detector"}),
    ProfileMode.DEFAULT: frozenset({"recon", "detector", "cve", "redteam", "bounty"}),
    ProfileMode.FULL: frozenset(ALL_HANDLER_CATEGORIES.keys()),
}


@dataclass
class ProfileConfig:
    mode: ProfileMode = ProfileMode.DEFAULT
    include: Set[str] = field(default_factory=set)
    exclude: Set[str] = field(default_factory=set)

    @property
    def active_categories(self) -> Set[str]:
        if self.mode == ProfileMode.CUSTOM:
            base = self.include or set(ALL_HANDLER_CATEGORIES.keys())
        else:
            base = set(PROFILE_CATEGORIES.get(self.mode, PROFILE_CATEGORIES[ProfileMode.DEFAULT]))
        return base - self.exclude

    def handler_list(self) -> List[tuple[str, str, str]]:
        """Return ordered (display, module, function) tuples for active categories."""
        return [
            ALL_HANDLER_CATEGORIES[cat]
            for cat in ALL_HANDLER_CATEGORIES
            if cat in self.active_categories
        ]


def resolve_profile(profile_name: Optional[str] = None) -> ProfileConfig:
    """
    Resolve profile from:
      1. Explicit argument
      2. HELLCAT_PROFILE env var
      3. Default
    Supports: compact, default, full, or custom:cat1,cat2,-cat3
    """
    raw = profile_name or os.environ.get("HELLCAT_PROFILE", "default")
    raw = raw.strip().lower()

    if raw in ("compact", "default", "full"):
        mode = ProfileMode(raw)
        return ProfileConfig(mode=mode)

    if raw.startswith("custom:"):
        parts = raw[7:].split(",")
        include = {p.strip() for p in parts if not p.strip().startswith("-")}
        exclude = {p.strip().lstrip("-") for p in parts if p.strip().startswith("-")}
        return ProfileConfig(mode=ProfileMode.CUSTOM, include=include, exclude=exclude)

    logger.warning("Unknown profile '%s', falling back to default", raw)
    return ProfileConfig(mode=ProfileMode.DEFAULT)


def profile_summary(config: ProfileConfig) -> str:
    cats = sorted(config.active_categories)
    total = len(ALL_HANDLER_CATEGORIES)
    return (
        f"Profile: {config.mode.value} "
        f"({len(cats)}/{total} categories: {', '.join(cats)})"
    )
