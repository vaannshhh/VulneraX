"""
VulneraX — Nikto Output Parser
================================
Standalone parser for Nikto plain-text output files.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from utils.schema import Vulnerability

_SEVERITY_KEYWORDS = {
    "sql injection": "critical",
    "xss": "high",
    "rfi": "high",
    "directory traversal": "high",
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


def parse_nikto_txt(file_path: str, target: str = "") -> List[Vulnerability]:
    """
    Parse a Nikto plain-text output file into Vulnerability objects.

    Args:
        file_path: Path to the Nikto .txt output file.
        target:    Original scan target URL.

    Returns:
        List of Vulnerability objects.
    """
    findings: List[Vulnerability] = []
    path = Path(file_path)
    if not path.exists():
        return findings

    with open(file_path, encoding="utf-8", errors="ignore") as fh:
        lines = fh.readlines()

    for line in lines:
        line = line.strip()
        if not line.startswith("+"):
            continue
        if any(kw in line for kw in ["Target IP:", "Target Host:", "Start Time:", "End Time:", "Nikto"]):
            continue
        content = line.lstrip("+ ").strip()
        if len(content) < 10:
            continue

        sev = _infer_severity(content)
        findings.append(
            Vulnerability(
                name=content[:80],
                source="nikto",
                description=content,
                severity=sev,
                url=target,
                remediation=_remediation_hint(content),
                tags=["web-server", "nikto"],
                raw={"raw_line": line},
            )
        )

    return findings


def _remediation_hint(desc: str) -> str:
    lower = desc.lower()
    if "header" in lower:
        return "Configure appropriate HTTP security headers."
    if "cookie" in lower:
        return "Set Secure, HttpOnly, and SameSite flags on session cookies."
    if "directory" in lower:
        return "Disable directory listing on the web server."
    if "outdated" in lower:
        return "Update the identified software to the latest stable version."
    return "Review and remediate per OWASP guidelines."
