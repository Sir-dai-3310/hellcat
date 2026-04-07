"""
Hellcat Handler Registry
========================
Master registration function that loads handler categories
based on the active tool profile (compact / default / full / custom).
"""
from __future__ import annotations

import importlib
import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from hellcat.hellcat_mcp import ToolCounter


def register_all_handlers(
    mcp: FastMCP,
    counter: ToolCounter,
    logger: logging.Logger,
    profile_name: Optional[str] = None,
) -> None:
    """Register handler categories filtered by the active profile.

    Args:
        mcp: FastMCP server instance.
        counter: ToolCounter for tracking registrations.
        logger: Logger instance.
        profile_name: Optional profile override (compact/default/full/custom:...).
    """
    from hellcat.core.profiles import resolve_profile, profile_summary

    config = resolve_profile(profile_name)
    logger.info(profile_summary(config))

    for display_name, module_path, func_name in config.handler_list():
        try:
            mod = importlib.import_module(module_path)
            register_func = getattr(mod, func_name)
            register_func(mcp, counter, logger)
        except (ImportError, AttributeError, TypeError) as exc:
            logger.warning("Handler [%s] registration skipped: %s", display_name, exc)
        except Exception as exc:
            logger.error("Handler [%s] registration failed: %s", display_name, exc)
