"""
VulneraX — Nikto Scanner
==========================
Wraps the Nikto CLI and parses its text output into Vulnerability objects.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, List, Optional

from scanners.base_scanner import BaseScanner
from utils.config_loader import load_config
from utils.schema import Vulnerability


# Keyword → severity heuristic for Nikto lines
_SEVERITY_KEYWORDS = {
    "critical": "critical",
    "sql injection": "critical",
    "xss": "high",
    "cross-site scripting": "high",
    "remote file inclusion": "high",
    "rfi": "high",
    "directory traversal": "high",
    "shell": "high",
    "outdated": "medium",
    "vulnerable": "medium",
    "misconfigured": "medium",
    "header": "low",
    "cookie": "low",
    "information": "info",
    "disclosure": "info",
}


def _infer_severity(line: str) -> str:
    lower = line.lower()
    for kw, sev in _SEVERITY_KEYWORDS.items():
        if kw in lower:
            return sev
    return "info"


class NiktoScanner(BaseScanner):
    """Runs Nikto web-server scanner and parses line-based findings."""

    name = "nikto"
    description = "Web server vulnerability and misconfiguration scanner"

    def __init__(
        self,
        target: str,
        timeout: int = 60,
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ) -> None:
        cfg = load_config()
        nikto_cfg = cfg.get("tools", {}).get("nikto", {})
        timeout = nikto_cfg.get("timeout", timeout)
        self._maxtime = nikto_cfg.get("maxtime", 30)
        super().__init__(target, timeout, progress_callback)

    # ------------------------------------------------------------------
    def run(self) -> List[Vulnerability]:
        binary = shutil.which("nikto") or shutil.which("nikto.pl")
        if not binary:
            raise FileNotFoundError("nikto binary not found in PATH")

        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False, mode="w"
        ) as tmp:
            out_path = tmp.name

        cmd = [
            binary,
            "-h", self.target,
            "-maxtime", str(self._maxtime),
            "-output", out_path,
            "-Format", "txt",
            "-nointeractive",
        ]
        self._emit(f"[NIKTO] Command: {' '.join(cmd)}", 5)

        subprocess.run(cmd, timeout=self.timeout, capture_output=True, check=False)
        return self._parse_output(out_path)

    # ------------------------------------------------------------------
    def _parse_output(self, file_path: str) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        path = Path(file_path)
        if not path.exists():
            return findings

        with open(file_path, encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()

        for line in lines:
            line = line.strip()
            # Nikto finding lines start with "+"
            if not line.startswith("+"):
                continue
            # Skip header/summary lines
            if any(kw in line for kw in ["Target IP:", "Target Port:", "Target Host:", "Nikto", "---", "Start Time", "End Time"]):
                continue

            content = line.lstrip("+ ").strip()
            if len(content) < 10:
                continue

            sev = _infer_severity(content)
            findings.append(
                Vulnerability(
                    name=content[:80],
                    source=self.name,
                    description=content,
                    severity=sev,
                    url=self.target,
                    remediation=_remediation_hint(content),
                    tags=["web-server", "nikto"],
                    raw={"raw_line": line},
                )
            )

        self.log.info("Nikto found %d findings.", len(findings))
        return findings


def _remediation_hint(description: str) -> str:
    lower = description.lower()
    if "header" in lower:
        return "Configure appropriate security headers (X-Frame-Options, CSP, HSTS, etc.)."
    if "cookie" in lower:
        return "Set Secure and HttpOnly flags on all session cookies."
    if "directory" in lower or "listing" in lower:
        return "Disable directory listing on the web server."
    if "outdated" in lower or "version" in lower:
        return "Update the affected software component to the latest stable version."
    if "xss" in lower or "cross-site" in lower:
        return "Implement proper input validation and output encoding; apply a Content Security Policy."
    return "Review and remediate the identified misconfiguration following OWASP guidelines."
