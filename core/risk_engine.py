"""
VulneraX — Risk Scoring Engine
================================
Normalises CVSS scores, applies multi-tool confirmation boosts,
and re-classifies severity bands consistently across all findings.
"""

from __future__ import annotations

from typing import List

from utils.config_loader import load_config
from utils.logger import get_logger
from utils.schema import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    Vulnerability,
    severity_from_cvss,
)

log = get_logger("vulnerax.risk")


class RiskEngine:
    """
    Applies CVSS-based scoring and severity normalisation to all findings.

    Boost logic
    -----------
    If ``vulnerability.boosted`` is True (confirmed by ≥2 tools) the raw CVSS
    score receives a configurable additive bonus, capped at 10.0.
    """

    def __init__(self) -> None:
        cfg = load_config()
        self._boost: float = cfg.get("correlation", {}).get("boost_score", 1.5)
        bands = cfg.get("risk", {}).get("cvss_bands", {})
        self._band_critical: float = bands.get("critical", 9.0)
        self._band_high: float = bands.get("high", 7.0)
        self._band_medium: float = bands.get("medium", 4.0)

    # ------------------------------------------------------------------
    def score_all(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """
        Apply scoring to every finding in the list (in-place mutation).

        Args:
            vulns: Correlated vulnerability list.

        Returns:
            Same list, with cvss_score and severity updated.
        """
        for v in vulns:
            v.cvss_score = self._apply_boost(v)
            v.severity = self._band(v.cvss_score)

        # Sort descending by CVSS for consistent output
        vulns.sort(key=lambda v: v.cvss_score, reverse=True)
        log.info("Risk engine processed %d findings.", len(vulns))
        return vulns

    # ------------------------------------------------------------------
    def _apply_boost(self, v: Vulnerability) -> float:
        """Return the final CVSS score, applying boost if warranted."""
        base = v.cvss_score
        if v.boosted:
            base = min(10.0, base + self._boost)
        return round(base, 1)

    def _band(self, score: float) -> str:
        """Map a CVSS score to a severity band string."""
        if score >= self._band_critical:
            return SEVERITY_CRITICAL
        if score >= self._band_high:
            return SEVERITY_HIGH
        if score >= self._band_medium:
            return SEVERITY_MEDIUM
        if score > 0.0:
            return SEVERITY_LOW
        return SEVERITY_INFO

    # ------------------------------------------------------------------
    @staticmethod
    def summary_stats(vulns: List[Vulnerability]) -> dict:
        """Return a quick statistics dict for dashboard / report headers."""
        counts = {s: 0 for s in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]}
        boosted = 0
        cvss_scores = []
        for v in vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
            if v.boosted:
                boosted += 1
            if v.cvss_score > 0:
                cvss_scores.append(v.cvss_score)

        return {
            "total": len(vulns),
            "by_severity": counts,
            "boosted_count": boosted,
            "avg_cvss": round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else 0.0,
            "max_cvss": max(cvss_scores, default=0.0),
        }
