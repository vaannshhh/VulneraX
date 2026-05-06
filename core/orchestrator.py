"""
VulneraX — Orchestration Engine
=================================
Drives parallel + sequential scanner execution, collects all findings,
and fires progress callbacks throughout.
"""

from __future__ import annotations

import datetime
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional

from core.correlation_engine import CorrelationEngine
from core.risk_engine import RiskEngine
from scanners.base_scanner import BaseScanner
from scanners.nikto_scanner import NiktoScanner
from scanners.nmap_scanner import NmapScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.zap_scanner import ZAPScanner
from utils.config_loader import load_config
from utils.input_classifier import TargetType, classify, recommended_scanners
from utils.logger import get_logger
from utils.schema import ScanResult, Vulnerability

log = get_logger("vulnerax.orchestrator")

# Map scanner name → class
_SCANNER_REGISTRY: Dict[str, type] = {
    "nmap": NmapScanner,
    "nikto": NiktoScanner,
    "nuclei": NucleiScanner,
    "zap": ZAPScanner,
}


class Orchestrator:
    """
    Central coordinator that:
      1. Classifies the target input type
      2. Selects appropriate scanners
      3. Runs them in parallel with a thread pool
      4. Feeds raw findings through correlation + risk engines
      5. Returns a ScanResult
    """

    def __init__(
        self,
        progress_callback: Optional[Callable[[str, int], None]] = None,
        max_workers: int = 4,
    ) -> None:
        self._progress_cb = progress_callback
        self._max_workers = max_workers
        self._cfg = load_config()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------
    def run(
        self,
        target: str,
        scan_type: str = "full",
        custom_scanners: Optional[List[str]] = None,
    ) -> ScanResult:
        """
        Execute a full scan session.

        Args:
            target:          URL, IP, or domain.
            scan_type:       'quick' | 'full' | 'custom'.
            custom_scanners: Scanner names to use when scan_type='custom'.

        Returns:
            Populated ScanResult.
        """
        result = ScanResult(
            target=target,
            scan_type=scan_type,
            started_at=datetime.datetime.utcnow().isoformat(),
        )

        self._emit(f"[*] Target classified as: {classify(target).value.upper()}", 0)

        # Determine which scanners to run
        if scan_type == "custom" and custom_scanners:
            scanner_names = custom_scanners
        else:
            scanner_names = recommended_scanners(target, scan_type)

        # Load any active plugins
        from plugins import discover_plugins
        plugin_names = {cls.name for cls in discover_plugins()}
        plugin_scanners = self._load_plugins(target, allowed_names=scanner_names if (scan_type == "custom" and custom_scanners) else None)

        self._emit(
            f"[*] Scanners selected: {', '.join(scanner_names) or 'none'}", 2
        )

        all_vulns: List[Vulnerability] = []

        # ---- Run built-in scanners in parallel ----
        built_in = self._instantiate_scanners(scanner_names, target, plugin_names)
        futures: Dict[Future, str] = {}

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            for scanner in built_in:
                fut = pool.submit(scanner.execute)
                futures[fut] = scanner.name

            total = len(futures)
            done_count = 0
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    vulns = fut.result()
                    all_vulns.extend(vulns)
                    result.tools_used.append(name)
                    self._emit(
                        f"[+] {name.upper()} completed - {len(vulns)} finding(s)", 
                        int((done_count + 1) / max(total, 1) * 70),
                    )
                except Exception as exc:  # noqa: BLE001
                    msg = f"[!] {name.upper()} failed: {exc}"
                    log.error(msg)
                    result.errors.append(msg)
                finally:
                    done_count += 1

        # ---- Run plugin scanners sequentially ----
        for plugin in plugin_scanners:
            try:
                vulns = plugin.execute()
                all_vulns.extend(vulns)
                result.tools_used.append(plugin.name)
                self._emit(f"[+] Plugin '{plugin.name}' completed - {len(vulns)} finding(s)", 75)
            except Exception as exc:  # noqa: BLE001
                msg = f"[!] Plugin '{plugin.name}' failed: {exc}"
                log.error(msg)
                result.errors.append(msg)

        # ---- Correlation ----
        self._emit("[*] Running correlation engine…", 80)
        correlated = CorrelationEngine().correlate(all_vulns)

        # ---- Risk scoring ----
        self._emit("[*] Applying risk scoring…", 90)
        scored = RiskEngine().score_all(correlated)

        result.vulnerabilities = scored
        result.completed_at = datetime.datetime.utcnow().isoformat()
        self._emit(
            f"[+] Scan complete - {result.total} unique findings | "
            f"Critical: {result.critical_count}  High: {result.high_count}",
            100,
        )
        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    def _instantiate_scanners(
        self, names: List[str], target: str, plugin_names: set[str]
    ) -> List[BaseScanner]:
        scanners: List[BaseScanner] = []
        for name in names:
            cls = _SCANNER_REGISTRY.get(name)
            if cls is None:
                if name not in plugin_names:
                    log.warning("Unknown scanner '%s' — skipping.", name)
                continue
            
            # Wrap callback to just pass through for now, or scale it if desired
            def cb(msg: str, pct: int):
                if self._progress_cb:
                    self._progress_cb(msg, pct)
            
            scanners.append(cls(target=target, progress_callback=cb))
        return scanners

    def _load_plugins(self, target: str, allowed_names: Optional[List[str]] = None) -> List[BaseScanner]:
        """Dynamically load scanners from the plugins/ directory."""
        from plugins import discover_plugins
        plugin_classes = discover_plugins()
        instances: List[BaseScanner] = []
        for cls in plugin_classes:
            if allowed_names is not None and cls.name not in allowed_names:
                continue
            try:
                # Wrap callback
                def cb(msg: str, pct: int):
                    if self._progress_cb:
                        self._progress_cb(msg, pct)

                instances.append(cls(target=target, progress_callback=cb))
            except Exception as exc:  # noqa: BLE001
                log.warning("Could not load plugin %s: %s", cls, exc)
        return instances

    def _emit(self, message: str, percent: int) -> None:
        log.info(message)
        if self._progress_cb:
            try:
                self._progress_cb(message, percent)
            except Exception:  # noqa: BLE001
                pass
