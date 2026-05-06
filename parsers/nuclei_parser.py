"""
VulneraX — Nuclei Output Parser
=================================
Standalone parser for Nuclei JSONL output files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from utils.schema import Vulnerability, normalize_severity


def parse_nuclei_jsonl(file_path: str, target: str = "") -> List[Vulnerability]:
    """
    Parse a Nuclei JSONL output file into Vulnerability objects.

    Args:
        file_path: Path to the Nuclei .jsonl output file.
        target:    Original scan target.

    Returns:
        List of Vulnerability objects.
    """
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

            remediation = info.get("remediation", "")
            if not remediation and refs:
                ref = refs[0] if isinstance(refs, list) else refs
                remediation = f"Refer to: {ref}"

            findings.append(
                Vulnerability(
                    name=info.get("name", data.get("template-id", "Unknown")),
                    source="nuclei",
                    description=info.get("description", ""),
                    severity=severity,
                    url=data.get("matched-at", target),
                    cve=cve,
                    remediation=remediation,
                    references=refs if isinstance(refs, list) else [refs],
                    tags=tags if isinstance(tags, list) else [tags],
                    raw=data,
                )
            )

    return findings
