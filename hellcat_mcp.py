"""
Hellcat MCP Entry Point
=======================
FastMCP stdio server — primary interface for AI editors
(Claude Desktop / Cursor / Copilot / Windsurf).
"""
from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

from fastmcp import FastMCP

if TYPE_CHECKING:
    pass

logger = logging.getLogger("hellcat.mcp")

# ---------------------------------------------------------------------------
# MCP instance
# ---------------------------------------------------------------------------

mcp = FastMCP("Hellcat")


# ---------------------------------------------------------------------------
# Tool counter (tracks registered tools per category)
# ---------------------------------------------------------------------------

class ToolCounter:
    """Counts MCP tools registered per handler category."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    def add(self, category: str, count: int = 1) -> None:
        self._counts[category] = self._counts.get(category, 0) + count

    @property
    def total(self) -> int:
        return sum(self._counts.values())

    def summary(self) -> str:
        lines = [f"  {cat}: {n}" for cat, n in sorted(self._counts.items())]
        lines.append(f"  TOTAL: {self.total}")
        return "\n".join(lines)


_counter = ToolCounter()


# ---------------------------------------------------------------------------
# Handler registration
# ---------------------------------------------------------------------------

def register_all_tools(profile: str | None = None) -> None:
    """Import and register handler categories filtered by profile."""
    from hellcat.handlers import register_all_handlers
    register_all_handlers(mcp, _counter, logger, profile_name=profile)
    logger.info("Hellcat MCP tools registered:\n%s", _counter.summary())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )
    # Parse --profile flag
    profile = None
    for i, arg in enumerate(sys.argv):
        if arg == "--profile" and i + 1 < len(sys.argv):
            profile = sys.argv[i + 1]
    register_all_tools(profile=profile)

    if len(sys.argv) > 1 and sys.argv[1] == "--stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
