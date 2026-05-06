"""
VulneraX — JSON Report Generator
==================================
Serialises a ScanResult to a structured JSON file.
"""

from __future__ import annotations

import json
from pathlib import Path

from utils.logger import get_logger
from utils.schema import ScanResult

log = get_logger("vulnerax.report.json")


class JSONReporter:
    """Writes a ScanResult as a formatted JSON file."""

    def generate(self, result: ScanResult, output_path: str) -> str:
        """
        Write the scan result to *output_path* as JSON.

        Args:
            result:      Completed ScanResult.
            output_path: Destination file path.

        Returns:
            Absolute path to the written file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        payload = result.to_dict()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)

        log.info("JSON report written to %s", path)
        return str(path.resolve())
