"""
VulneraX — Vulnerability Correlation Engine
=============================================
Merges duplicate findings across tools, identifies multi-tool confirmations,
and groups related findings into enriched single records.

Algorithm
---------
1. Exact-name dedup within the same source (rare but can happen with Nikto).
2. Cross-tool correlation: two findings are "the same" when their normalised
   names are sufficiently similar (Jaccard on word tokens) AND they share
   the same port/URL context.
3. Merged findings carry a `confirmed_by` list; if len >= 2 → boosted = True.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple

from utils.config_loader import load_config
from utils.logger import get_logger
from utils.schema import Vulnerability

log = get_logger("vulnerax.correlation")


def _tokenise(text: str) -> Set[str]:
    """Lower-case word-token set for Jaccard similarity."""
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _jaccard(a: str, b: str) -> float:
    ta, tb = _tokenise(a), _tokenise(b)
    if not ta and not tb:
        return 1.0
    inter = ta & tb
    union = ta | tb
    return len(inter) / len(union)


def _context_key(v: Vulnerability) -> str:
    """Compact context string used for grouping (port + normalised url)."""
    port_part = str(v.port) if v.port else "noport"
    url_part = re.sub(r"https?://", "", v.url).rstrip("/").lower() if v.url else "nourl"
    return f"{port_part}@{url_part}"


class CorrelationEngine:
    """Deduplicates and correlates findings across scanners."""

    def __init__(self) -> None:
        cfg = load_config()
        self._threshold: float = (
            cfg.get("correlation", {}).get("similarity_threshold", 0.75)
        )

    # ------------------------------------------------------------------
    def correlate(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """
        Run the full correlation pipeline.

        Args:
            vulnerabilities: Raw flat list from all scanners.

        Returns:
            De-duplicated, correlated list with confirmed_by populated.
        """
        if not vulnerabilities:
            return []

        log.info("Correlation: processing %d raw findings…", len(vulnerabilities))

        # Step 1 — intra-source dedup
        deduped = self._intra_source_dedup(vulnerabilities)

        # Step 2 — cross-tool merge
        merged = self._cross_tool_merge(deduped)

        log.info(
            "Correlation: %d raw → %d after dedup → %d after merge.",
            len(vulnerabilities),
            len(deduped),
            len(merged),
        )
        return merged

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    def _intra_source_dedup(
        self, vulns: List[Vulnerability]
    ) -> List[Vulnerability]:
        """Remove exact-name duplicates within the same source tool."""
        seen: Set[Tuple[str, str]] = set()
        result: List[Vulnerability] = []
        for v in vulns:
            key = (v.source, v.name.lower().strip())
            if key not in seen:
                seen.add(key)
                result.append(v)
        return result

    def _cross_tool_merge(
        self, vulns: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Group findings from different sources that describe the same issue.
        The representative finding (highest severity) absorbs the rest.
        """
        # Union-Find approach
        n = len(vulns)
        parent = list(range(n))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: int, y: int) -> None:
            parent[find(x)] = find(y)

        for i in range(n):
            for j in range(i + 1, n):
                vi, vj = vulns[i], vulns[j]
                # Don't merge findings from the same tool — keep them separate
                if vi.source == vj.source:
                    continue
                if _jaccard(vi.name, vj.name) >= self._threshold and (
                    _context_key(vi) == _context_key(vj)
                    or vi.cve is not None and vi.cve == vj.cve
                ):
                    union(i, j)

        # Collect groups
        groups: Dict[int, List[int]] = {}
        for idx in range(n):
            root = find(idx)
            groups.setdefault(root, []).append(idx)

        merged: List[Vulnerability] = []
        for root, indices in groups.items():
            if len(indices) == 1:
                merged.append(vulns[indices[0]])
                continue

            # Pick representative: highest severity_rank
            representative = max(
                (vulns[i] for i in indices), key=lambda v: v.severity_rank
            )
            # Accumulate sources
            all_sources = [vulns[i].source for i in indices]
            representative.confirmed_by = list(
                set(all_sources) - {representative.source}
            )
            representative.boosted = len(all_sources) >= 2
            # Merge description if the representative's is short
            if len(representative.description) < 20:
                for i in indices:
                    if len(vulns[i].description) > len(representative.description):
                        representative.description = vulns[i].description
            # Merge remediation similarly
            if not representative.remediation:
                for i in indices:
                    if vulns[i].remediation:
                        representative.remediation = vulns[i].remediation
                        break
            merged.append(representative)

        return merged
