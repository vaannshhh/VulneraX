"""
VulneraX — Report Generator Orchestrator
==========================================
Single entry-point that generates all configured report formats
(HTML, JSON, CSV) from a completed ScanResult.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List

from core.ai_layer import enrich_all, generate_executive_summary
from reports.csv_report import CSVReporter
from reports.html_report import HTMLReporter
from reports.json_report import JSONReporter
from utils.config_loader import load_config
from utils.logger import get_logger
from utils.schema import ScanResult

log = get_logger("vulnerax.report")


class ReportGenerator:
    """
    Orchestrates all output formats for a completed scan.

    Usage::

        generator = ReportGenerator()
        paths = generator.generate(result)
        # {'html': '/path/to/report.html', 'json': '...', 'csv': '...'}
    """

    def __init__(self) -> None:
        cfg = load_config()
        report_cfg = cfg.get("reports", {})
        self._output_dir = Path(report_cfg.get("output_dir", "scan_results"))
        self._formats: List[str] = report_cfg.get("formats", ["html", "json", "csv"])

    # ------------------------------------------------------------------
    def generate(self, result: ScanResult) -> Dict[str, str]:
        """
        Enrich findings with AI layer, then write all enabled report formats.

        Args:
            result: A completed ScanResult (from Orchestrator.run()).

        Returns:
            Dict mapping format name → absolute file path.
        """
        # Enrich with AI descriptions + remediation
        result.vulnerabilities = enrich_all(result.vulnerabilities)
        result.executive_summary = generate_executive_summary(result)  # type: ignore[attr-defined]

        scan_dir = self._output_dir / result.scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)

        paths: Dict[str, str] = {}
        base = str(scan_dir / f"report_{result.scan_id[:8]}")

        if "json" in self._formats:
            paths["json"] = JSONReporter().generate(result, base + ".json")

        if "csv" in self._formats:
            paths["csv"] = CSVReporter().generate(result, base + ".csv")

        if "html" in self._formats:
            paths["html"] = HTMLReporter().generate(result, base + ".html")

        log.info("Reports saved to: %s", scan_dir)
        for fmt, p in paths.items():
            log.info("  [%s] %s", fmt.upper(), p)

        return paths
