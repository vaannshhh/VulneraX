"""
VulneraX — ZAP Alert Parser
==============================
Standalone parser for ZAP alert dictionaries (from zapv2 API or JSON export).
"""

from __future__ import annotations

from typing import Any, Dict, List

from utils.schema import Vulnerability, normalize_severity

_RISK_MAP = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}


def parse_zap_alerts(alerts: List[Dict[str, Any]], target: str = "") -> List[Vulnerability]:
    """
    Convert a list of ZAP alert dicts into Vulnerability objects.

    Args:
        alerts: List of alert dicts as returned by ``zap.core.alerts()``.
        target: The scan target URL.

    Returns:
        List of Vulnerability objects.
    """
    findings: List[Vulnerability] = []
    for alert in alerts:
        raw_risk = alert.get("risk", "Informational")
        severity = normalize_severity(_RISK_MAP.get(raw_risk, "info"))
        refs_raw = alert.get("reference", "")
        refs = [r.strip() for r in refs_raw.split("\n") if r.strip()]

        findings.append(
            Vulnerability(
                name=alert.get("alert", "Unknown ZAP Alert"),
                source="zap",
                description=alert.get("description", ""),
                severity=severity,
                url=alert.get("url", target),
                remediation=alert.get("solution", ""),
                references=refs,
                tags=["zap", "active-scan"],
                raw=alert,
            )
        )
    return findings
