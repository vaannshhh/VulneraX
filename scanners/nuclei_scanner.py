"""
VulneraX — Nuclei Scanner
===========================
Runs Nuclei (projectdiscovery) and parses its JSONL output.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, List, Optional

from scanners.base_scanner import BaseScanner
from utils.config_loader import load_config
from utils.schema import Vulnerability, normalize_severity


class NucleiScanner(BaseScanner):
    """Fast template-based vulnerability scanner by ProjectDiscovery."""

    name = "nuclei"
    description = "Template-based vulnerability scanner (ProjectDiscovery Nuclei)"

    def __init__(
        self,
        target: str,
        timeout: int = 180,
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ) -> None:
        cfg = load_config()
        nuclei_cfg = cfg.get("tools", {}).get("nuclei", {})
        timeout = nuclei_cfg.get("timeout", timeout)
        self._flags = nuclei_cfg.get("flags", "-silent")
        super().__init__(target, timeout, progress_callback)

    # ------------------------------------------------------------------
    def run(self) -> List[Vulnerability]:
        binary = shutil.which("nuclei")
        if not binary:
            raise FileNotFoundError("nuclei binary not found in PATH")

        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False, mode="w"
        ) as tmp:
            out_path = tmp.name

        cmd = [
            binary,
            "-u", self.target,
            "-json",
            "-o", out_path,
            *self._flags.split(),
        ]
        self._emit(f"[NUCLEI] Command: {' '.join(cmd)}", 5)
        subprocess.run(cmd, timeout=self.timeout, capture_output=True, check=False)
        return self._parse_jsonl(out_path)

    # ------------------------------------------------------------------
    def _parse_jsonl(self, file_path: str) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        path = Path(file_path)
        if not path.exists():
            return findings

        with open(file_path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                info = data.get("info", {})
                severity = normalize_severity(info.get("severity", "info"))
                cve_list = info.get("classification", {}).get("cve-id", []) or []
                cve = cve_list[0] if cve_list else None
                refs = info.get("reference", []) or []
                tags = info.get("tags", []) or []

                findings.append(
                    Vulnerability(
                        name=info.get("name", data.get("template-id", "Unknown")),
                        source=self.name,
                        description=info.get("description", ""),
                        severity=severity,
                        url=data.get("matched-at", self.target),
                        cve=cve,
                        remediation=_remediation_for(info),
                        references=refs if isinstance(refs, list) else [refs],
                        tags=tags if isinstance(tags, list) else [tags],
                        raw=data,
                    )
                )

        self.log.info("Nuclei found %d findings.", len(findings))
        return findings


def _remediation_for(info: dict) -> str:
    """Build a remediation string from Nuclei info block."""
    remediation = info.get("remediation", "")
    if remediation:
        return remediation
    refs = info.get("reference", [])
    if refs:
        ref_str = refs[0] if isinstance(refs, list) else refs
        return f"Refer to: {ref_str}"
    return "Review the affected component and apply vendor-recommended patches or configuration changes."
