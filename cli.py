"""
Hellcat CLI
===========
Command-line interface: hellcat server | mcp | scan | install | status | version
                        | history | profile | dashboard
"""
from __future__ import annotations

import logging
import sys
from typing import Optional

try:
    import click
except ImportError:
    print("Install click: pip install click")
    sys.exit(1)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def cli(verbose: bool) -> None:
    """Hellcat — AI-Driven Autonomous Penetration Testing Framework"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )


# ═══════════════════════════════════════════════════════════════════════════
# Core commands
# ═══════════════════════════════════════════════════════════════════════════

@cli.command()
@click.option("--host", default=None, help="Override HELLCAT_HOST")
@click.option("--port", default=None, type=int, help="Override HELLCAT_PORT")
def server(host: Optional[str], port: Optional[int]) -> None:
    """Start Flask API server (+Celery if Redis available)."""
    import os
    if host:
        os.environ["HELLCAT_HOST"] = host
    if port:
        os.environ["HELLCAT_PORT"] = str(port)
    from hellcat.hellcat_server import run_server
    run_server()


@cli.command()
@click.option("--profile", "-p", default=None,
              help="Tool profile: compact | default | full | custom:cat1,cat2,-cat3")
def mcp(profile: Optional[str]) -> None:
    """Start MCP stdio server (for AI editors)."""
    from hellcat.hellcat_mcp import main as mcp_main
    if profile:
        import os
        os.environ["HELLCAT_PROFILE"] = profile
    mcp_main()


@cli.command()
@click.argument("target")
@click.option("--quick", is_flag=True, help="Quick scan (top ports only)")
def scan(target: str, quick: bool) -> None:
    """Quick scan a target using Hellcat intelligence."""
    from hellcat.core.ai.intelligence import HellcatIntelligence
    from hellcat.core.run_history import get_history_store

    store = get_history_store()
    rec = store.start_run(tool="scan", target=target, tags=["cli", "quick" if quick else "full"])

    intel = HellcatIntelligence()
    click.echo(f"[*] Scanning {target} ...")
    import time
    t0 = time.time()
    result = intel.assess(target, {"quick_mode": quick})
    duration = (time.time() - t0) * 1000

    click.echo(f"[+] Target type: {result['analysis']['target_type']}")
    click.echo(f"[+] Risk level: {result['analysis']['risk_level']}")
    tools = result["analysis"].get("recommended_tools", [])[:5]
    for t in tools:
        click.echo(f"    -> {t['tool']} (effectiveness: {t['effectiveness']:.0%})")
    plan = result.get("mcts_plan", {})
    actions = plan.get("recommended_actions", [])[:5]
    if actions:
        click.echo(f"[+] MCTS recommended ({plan.get('root_visits',0)} iterations):")
        for name, visits, reward in actions:
            click.echo(f"    -> {name} (visits={visits}, reward={reward:.2f})")
    click.echo(f"[+] Tools available: {result['tool_status']['available']}/{result['tool_status']['total']}")

    store.finish_run(rec.id, status="success", duration_ms=duration,
                     findings_count=len(result.get("analysis", {}).get("recommended_tools", [])))


@cli.command()
def install() -> None:
    """Check & install missing tools (Kali auto-installer)."""
    from hellcat.core.tools import ExternalToolManager
    mgr = ExternalToolManager()
    report = mgr.status_report()
    click.echo(f"[*] Tools: {report['available']}/{report['total_registered']} available")
    if report["missing_tools"]:
        click.echo(f"[!] Missing ({report['missing']}): {', '.join(report['missing_tools'][:15])}")
        click.echo(f"[*] Install command:")
        click.echo(f"    {report['kali_install_cmd']}")
    else:
        click.echo("[+] All tools available!")


@cli.command()
def status() -> None:
    """Show system status and tool availability."""
    from hellcat.core.tools import ExternalToolManager
    from hellcat.core.tasks import is_celery_available
    from hellcat.core.run_history import get_history_store
    mgr = ExternalToolManager()
    report = mgr.status_report()
    store = get_history_store()

    click.echo("=== Hellcat Status ===")
    click.echo(f"Version : 1.0.0-alpha")
    click.echo(f"Tools   : {report['available']}/{report['total_registered']} available")
    click.echo(f"Celery  : {'active' if is_celery_available() else 'unavailable (async disabled)'}")

    # AI providers
    from hellcat.core.ai.engine import ProviderRegistry
    reg = ProviderRegistry()
    providers = reg.available_providers
    click.echo(f"AI      : {', '.join(providers) if providers else 'none (AI features disabled)'}")
    click.echo(f"History : {store.count} runs recorded")
    click.echo(f"Missing : {', '.join(report['missing_tools'][:10])}")


@cli.command()
def version() -> None:
    """Show version info."""
    click.echo("Hellcat v1.0.0-alpha")
    click.echo("AI-Driven Autonomous Penetration Testing Framework")
    click.echo("Author: Coff0xc | License: MIT")
    click.echo("Kali 2026.1 compatible")


# ═══════════════════════════════════════════════════════════════════════════
# New commands (inspired by HexStrike)
# ═══════════════════════════════════════════════════════════════════════════

@cli.command()
@click.option("--tool", "-t", default="", help="Filter by tool name")
@click.option("--target", default="", help="Filter by target")
@click.option("--status", "-s", default="", help="Filter by status")
@click.option("--limit", "-n", default=20, type=int, help="Max results")
@click.option("--stats", is_flag=True, help="Show run statistics only")
@click.option("--export", "export_path", default=None, help="Export to JSON file")
def history(tool: str, target: str, status: str, limit: int,
            stats: bool, export_path: Optional[str]) -> None:
    """Browse run history — search, filter, export past executions."""
    from hellcat.core.run_history import get_history_store
    store = get_history_store()

    if stats:
        s = store.stats()
        click.echo(f"=== Run History Stats ===")
        click.echo(f"Total runs  : {s['total_runs']}")
        click.echo(f"By status   : {s['by_status']}")
        click.echo(f"Top tools   : {s['top_tools']}")
        click.echo(f"Avg duration: {s['avg_duration_ms']:.0f}ms")
        return

    if export_path:
        import json
        data = store.export_json()
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        click.echo(f"[+] Exported {len(data)} records to {export_path}")
        return

    records = store.query(tool=tool, target=target, status=status, limit=limit)
    if not records:
        click.echo("[*] No matching runs found.")
        return

    click.echo(f"{'ID':<14} {'Tool':<16} {'Target':<24} {'Status':<10} {'Duration':<10} {'Time'}")
    click.echo("-" * 90)
    for rec in records:
        dur = f"{rec.duration_ms:.0f}ms" if rec.duration_ms else "-"
        t = rec.started_at[11:19] if rec.started_at else "-"
        click.echo(f"{rec.id:<14} {rec.tool:<16} {rec.target[:23]:<24} {rec.status:<10} {dur:<10} {t}")


@cli.command()
@click.argument("name", default="default")
def profile(name: str) -> None:
    """Show or set the MCP tool loading profile (compact/default/full/custom:...)."""
    from hellcat.core.profiles import resolve_profile, profile_summary, ALL_HANDLER_CATEGORIES

    if name == "list":
        click.echo("=== Available Categories ===")
        for cat, (display, _, _) in ALL_HANDLER_CATEGORIES.items():
            click.echo(f"  {cat:<16} {display}")
        click.echo()
        click.echo("Profiles: compact | default | full | custom:cat1,cat2,-cat3")
        return

    config = resolve_profile(name)
    click.echo(profile_summary(config))
    click.echo("Active categories:")
    for cat in sorted(config.active_categories):
        display = ALL_HANDLER_CATEGORIES[cat][0]
        click.echo(f"  + {cat:<16} {display}")


@cli.command()
def dashboard() -> None:
    """Open the web dashboard (starts server if not running)."""
    import webbrowser
    from hellcat.hellcat_server import API_HOST, API_PORT
    url = f"http://{API_HOST}:{API_PORT}/health"
    try:
        import requests
        resp = requests.get(url, timeout=2)
        if resp.status_code == 200:
            click.echo(f"[+] Server running at http://{API_HOST}:{API_PORT}")
            webbrowser.open(f"http://{API_HOST}:{API_PORT}")
            return
    except Exception:
        pass
    click.echo(f"[*] Server not running. Start with: hellcat server")
    click.echo(f"[*] Then open: http://{API_HOST}:{API_PORT}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
