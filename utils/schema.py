"""
VulneraX — Unified Vulnerability Schema
========================================
Central data model consumed by every scanner, parser, engine, and reporter.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

SEVERITY_RANK: dict[str, int] = {
    SEVERITY_CRITICAL: 5,
    SEVERITY_HIGH: 4,
    SEVERITY_MEDIUM: 3,
    SEVERITY_LOW: 2,
    SEVERITY_INFO: 1,
}

SEVERITY_COLOR: dict[str, str] = {
    SEVERITY_CRITICAL: "#FF3366",
    SEVERITY_HIGH: "#FF6B35",
    SEVERITY_MEDIUM: "#FFD700",
    SEVERITY_LOW: "#00CED1",
    SEVERITY_INFO: "#8A8A8A",
}


def normalize_severity(raw: str) -> str:
    """Normalise a raw severity string from any tool to a canonical value."""
    mapping = {
        "critical": SEVERITY_CRITICAL,
        "high": SEVERITY_HIGH,
        "medium": SEVERITY_MEDIUM,
        "moderate": SEVERITY_MEDIUM,
        "low": SEVERITY_LOW,
        "info": SEVERITY_INFO,
        "informational": SEVERITY_INFO,
        "none": SEVERITY_INFO,
        "unknown": SEVERITY_INFO,
    }
    return mapping.get(raw.strip().lower(), SEVERITY_INFO)


def cvss_from_severity(severity: str) -> float:
    """Return a representative CVSS score for a given severity band."""
    defaults = {
        SEVERITY_CRITICAL: 9.5,
        SEVERITY_HIGH: 8.0,
        SEVERITY_MEDIUM: 5.5,
        SEVERITY_LOW: 2.0,
        SEVERITY_INFO: 0.0,
    }
    return defaults.get(severity, 0.0)


def severity_from_cvss(score: float) -> str:
    """Derive severity band from a CVSS numeric score."""
    if score >= 9.0:
        return SEVERITY_CRITICAL
    if score >= 7.0:
        return SEVERITY_HIGH
    if score >= 4.0:
        return SEVERITY_MEDIUM
    if score > 0.0:
        return SEVERITY_LOW
    return SEVERITY_INFO


# ---------------------------------------------------------------------------
# Core vulnerability dataclass
# ---------------------------------------------------------------------------
@dataclass
class Vulnerability:
    """Canonical representation of a single vulnerability finding."""

    name: str
    source: str  # "nmap" | "zap" | "nuclei" | "nikto" | plugin name
    description: str = ""
    severity: str = SEVERITY_INFO
    cvss_score: float = 0.0
    url: str = ""
    port: Optional[int] = None
    protocol: Optional[str] = None
    cve: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    confirmed_by: List[str] = field(default_factory=list)
    boosted: bool = False
    raw: dict = field(default_factory=dict)  # Original scanner output
    vuln_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        if self.cvss_score == 0.0:
            self.cvss_score = cvss_from_severity(self.severity)

    def to_dict(self) -> dict:
        """Serialise to a plain dictionary (JSON-safe)."""
        return {
            "id": self.vuln_id,
            "name": self.name,
            "source": self.source,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "url": self.url,
            "port": self.port,
            "protocol": self.protocol,
            "cve": self.cve,
            "remediation": self.remediation,
            "references": self.references,
            "tags": self.tags,
            "confirmed_by": self.confirmed_by,
            "boosted": self.boosted,
        }

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)


# ---------------------------------------------------------------------------
# Scan result container
# ---------------------------------------------------------------------------
@dataclass
class ScanResult:
    """Container for all vulnerabilities found during a scan session."""

    target: str
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_type: str = "full"
    tools_used: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    @property
    def total(self) -> int:
        return len(self.vulnerabilities)

    @property
    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {s: 0 for s in SEVERITY_RANK}
        for v in self.vulnerabilities:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts

    @property
    def critical_count(self) -> int:
        return self.by_severity[SEVERITY_CRITICAL]

    @property
    def high_count(self) -> int:
        return self.by_severity[SEVERITY_HIGH]

    @property
    def sorted_vulnerabilities(self) -> List[Vulnerability]:
        return sorted(self.vulnerabilities, key=lambda v: v.severity_rank, reverse=True)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "scan_type": self.scan_type,
            "tools_used": self.tools_used,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "summary": self.by_severity,
            "total": self.total,
            "errors": self.errors,
            "vulnerabilities": [v.to_dict() for v in self.sorted_vulnerabilities],
        }
