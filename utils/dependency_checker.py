"""
VulneraX — Dependency Checker
===============================
Verifies that required external tools are available in PATH before scanning.
"""

import shutil
from dataclasses import dataclass, field
from typing import List

from utils.logger import get_logger

log = get_logger("vulnerax.deps")


@dataclass
class ToolStatus:
    name: str
    found: bool
    path: str = ""
    optional: bool = False


# Required CLI tools — these must exist for full functionality
REQUIRED_TOOLS: List[str] = ["nmap"]

# Optional CLI tools — scans are skipped (not failed) when missing
OPTIONAL_TOOLS: List[str] = ["nikto", "nuclei"]


def check_all() -> List[ToolStatus]:
    """
    Check all required and optional tools.

    Returns:
        List of ToolStatus dataclass instances.
    """
    results: List[ToolStatus] = []

    for tool in REQUIRED_TOOLS:
        path = shutil.which(tool) or ""
        found = bool(path)
        results.append(ToolStatus(name=tool, found=found, path=path, optional=False))
        if found:
            log.debug("✔ %s found at %s", tool, path)
        else:
            log.warning("✘ Required tool '%s' not found in PATH", tool)

    for tool in OPTIONAL_TOOLS:
        path = shutil.which(tool) or ""
        found = bool(path)
        results.append(ToolStatus(name=tool, found=found, path=path, optional=True))
        if found:
            log.debug("✔ %s found at %s", tool, path)
        else:
            log.info("- Optional tool '%s' not found — related scan will be skipped", tool)

    return results


def tool_available(name: str) -> bool:
    """Quick single-tool availability check."""
    return shutil.which(name) is not None


def summarise(statuses: List[ToolStatus]) -> str:
    """Return a human-readable summary string."""
    lines = ["Dependency Check Results", "-" * 30]
    for s in statuses:
        tag = "OPTIONAL" if s.optional else "REQUIRED"
        status = "✔ FOUND" if s.found else "✘ MISSING"
        lines.append(f"  [{tag}] {s.name:<12} {status}")
    return "\n".join(lines)
