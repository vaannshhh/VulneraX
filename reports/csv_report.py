"""
VulneraX — CSV Report Generator
==================================
Writes all vulnerabilities to a flat CSV file suitable for spreadsheet import.
"""

from __future__ import annotations

import csv
from pathlib import Path

from utils.logger import get_logger
from utils.schema import ScanResult

log = get_logger("vulnerax.report.csv")

_FIELDS = [
    "scan_id", "target", "id", "name", "source", "severity",
    "cvss_score", "url", "port", "protocol", "cve",
    "confirmed_by", "boosted", "description", "remediation",
]


class CSVReporter:
    """Writes all vulnerabilities from a ScanResult to a CSV file."""

    def generate(self, result: ScanResult, output_path: str) -> str:
        """
        Write scan findings to *output_path* as CSV.

        Args:
            result:      Completed ScanResult.
            output_path: Destination file path.

        Returns:
            Absolute path to the written file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for vuln in result.sorted_vulnerabilities:
                row = vuln.to_dict()
                row["scan_id"] = result.scan_id
                row["target"] = result.target
                row["confirmed_by"] = "; ".join(row.get("confirmed_by", []))
                row["id"] = row.pop("id", vuln.vuln_id)
                writer.writerow(row)

        log.info("CSV report written to %s (%d rows)", path, result.total)
        return str(path.resolve())
