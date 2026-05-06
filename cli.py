"""
VulneraX — Click CLI
======================
Command-line interface for VulneraX.

Usage
-----
  python main.py scan <target> [--quick | --full | --custom]
  python main.py gui
  python main.py api
  python main.py plugins
  python main.py deps
"""

from __future__ import annotations

import sys
from typing import Optional

import click

from utils.logger import setup_logging


# ─────────────────────────────────────────────────────────────────────
# Root group
# ─────────────────────────────────────────────────────────────────────
@click.group()
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
@click.pass_context
def cli(ctx: click.Context, debug: bool) -> None:
    """VulneraX — Intelligent Automated Vulnerability Assessment Framework."""
    import logging
    level = logging.DEBUG if debug else logging.INFO
    console_level = logging.DEBUG if debug else logging.CRITICAL
    setup_logging(level=level, console_level=console_level)
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug


# ─────────────────────────────────────────────────────────────────────
# scan command
# ─────────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("target")
@click.option("--quick", "scan_type", flag_value="quick", help="Quick scan (Nmap + Nuclei).")
@click.option("--full",  "scan_type", flag_value="full",  default=True, help="Full scan (all tools).")
@click.option("--custom","scan_type", flag_value="custom", help="Custom scanner selection.")
@click.option(
    "--scanners", "-s", default="",
    help="Comma-separated scanners for --custom mode. E.g. nmap,nuclei",
)
@click.option("--output", "-o", default="scan_results", help="Output directory for reports.")
@click.option("--format", "fmt", type=click.Choice(["html", "json", "csv", "all"]),
              default="all", help="Report format.")
def scan(
    target: str,
    scan_type: str,
    scanners: str,
    output: str,
    fmt: str,
) -> None:
    """
    Run a vulnerability scan against TARGET.

    TARGET can be a URL, IP address, or domain name.

    Examples:

    \b
        vulnerax scan https://example.com --full
        vulnerax scan 192.168.1.1 --quick
        vulnerax scan example.com --custom --scanners nmap,nuclei
    """
    import yaml
    from utils.config_loader import load_config
    cfg = load_config()

    # Override output dir if specified
    if output != "scan_results":
        cfg.setdefault("reports", {})["output_dir"] = output

    # Parse custom scanners
    custom_list = [s.strip() for s in scanners.split(",") if s.strip()] if scanners else []

    click.echo(f"\n{'='*60}")
    click.echo(f"  VulneraX — Starting scan")
    click.echo(f"  Target     : {target}")
    click.echo(f"  Scan Type  : {scan_type.upper()}")
    if custom_list:
        click.echo(f"  Scanners   : {', '.join(custom_list)}")
    click.echo(f"{'='*60}\n")

    from core.orchestrator import Orchestrator
    from reports.report_generator import ReportGenerator

    def _progress(message: str, percent: int) -> None:
        bar_len = 30
        filled = int(bar_len * percent / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        click.echo(f"\r  [{bar}] {percent:3d}%  {message[:55]:<55}", nl=False)

    try:
        orch = Orchestrator(progress_callback=_progress)
        result = orch.run(target=target, scan_type=scan_type,
                          custom_scanners=custom_list or None)
        click.echo()  # newline after progress bar

        # Print summary table
        click.echo(f"\n{'-'*60}")
        click.echo(f"  Scan complete - {result.total} finding(s)")
        click.echo(f"  Critical: {result.critical_count}  "
                   f"High: {result.high_count}  "
                   f"Medium: {result.by_severity.get('medium',0)}  "
                   f"Low: {result.by_severity.get('low',0)}")
        click.echo(f"  Tools used: {', '.join(result.tools_used) or 'none'}")
        click.echo(f"{'-'*60}\n")

        # Generate reports
        if fmt != "all":
            from utils.config_loader import load_config as _lc
            _lc.cache_clear()

        paths = ReportGenerator().generate(result)
        click.echo("  Reports:")
        for f, p in paths.items():
            click.echo(f"    [{f.upper()}] {p}")
        click.echo()

        if result.errors:
            click.echo(click.style("  Errors during scan:", fg="yellow"))
            for err in result.errors:
                click.echo(click.style(f"    • {err}", fg="yellow"))

    except KeyboardInterrupt:
        click.echo("\n\n[!] Scan interrupted by user.")
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        click.echo(click.style(f"\n[!] Fatal error: {exc}", fg="red"))
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────
# gui command
# ─────────────────────────────────────────────────────────────────────
@cli.command()
def gui() -> None:
    """Launch the VulneraX graphical user interface."""
    click.echo("Launching GUI…")
    from gui.app import launch
    launch()


# ─────────────────────────────────────────────────────────────────────
# api command
# ─────────────────────────────────────────────────────────────────────
@cli.command()
@click.option("--host", default="0.0.0.0", help="API bind host.")
@click.option("--port", default=8000,      help="API bind port.", type=int)
@click.option("--reload", is_flag=True,   help="Enable auto-reload (dev mode).")
def api(host: str, port: int, reload: bool) -> None:
    """Start the VulneraX REST API server."""
    try:
        import uvicorn
    except ImportError:
        click.echo(click.style("[!] uvicorn not installed. Run: pip install uvicorn", fg="red"))
        sys.exit(1)

    click.echo(f"Starting VulneraX API on http://{host}:{port}")
    click.echo(f"Docs: http://{host}:{port}/docs")
    uvicorn.run("api.server:app", host=host, port=port, reload=reload)


# ─────────────────────────────────────────────────────────────────────
# plugins command
# ─────────────────────────────────────────────────────────────────────
@cli.command()
def plugins() -> None:
    """List all auto-discovered scanner plugins."""
    from plugins import list_plugins
    found = list_plugins()
    if not found:
        click.echo("No external plugins discovered.")
        return

    click.echo(f"\n  {'NAME':<20} {'VERSION':<10} {'AUTHOR':<20} DESCRIPTION")
    click.echo("  " + "-" * 80)
    for p in found:
        click.echo(
            f"  {p['name']:<20} {p['version']:<10} "
            f"{p['author']:<20} {p['description'][:40]}"
        )
    click.echo()


# ─────────────────────────────────────────────────────────────────────
# deps command
# ─────────────────────────────────────────────────────────────────────
@cli.command()
def deps() -> None:
    """Check all external tool dependencies."""
    from utils.dependency_checker import check_all, summarise
    statuses = check_all()
    click.echo(summarise(statuses))
    missing_required = [s for s in statuses if not s.found and not s.optional]
    if missing_required:
        click.echo(click.style(
            f"\n[!] {len(missing_required)} required tool(s) missing.", fg="red"
        ))
        sys.exit(1)
    else:
        click.echo(click.style("\n[✔] All required tools are available.", fg="green"))
