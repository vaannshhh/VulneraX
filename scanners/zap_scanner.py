"""
VulneraX — OWASP ZAP Scanner
==============================
Connects to a running ZAP instance via its REST API, runs spider + active scan,
and converts alerts to Vulnerability objects.
"""

from __future__ import annotations

import time
from typing import Callable, List, Optional

from scanners.base_scanner import BaseScanner
from utils.config_loader import load_config
from utils.schema import Vulnerability, normalize_severity


# ZAP risk string → normalised severity
_RISK_MAP = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}


class ZAPScanner(BaseScanner):
    """OWASP ZAP active scanner (requires ZAP daemon running)."""

    name = "zap"
    description = "OWASP ZAP spider + active vulnerability scanner"

    def __init__(
        self,
        target: str,
        timeout: int = 300,
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ) -> None:
        cfg = load_config()
        zap_cfg = cfg.get("tools", {}).get("zap", {})
        timeout = zap_cfg.get("timeout", timeout)
        self._api_key = zap_cfg.get("api_key", "")
        host = zap_cfg.get("host", "http://localhost")
        port = zap_cfg.get("port", 8081)
        self._proxies = {
            "http": f"{host}:{port}",
            "https": f"{host}:{port}",
        }
        super().__init__(target, timeout, progress_callback)

    # ------------------------------------------------------------------
    def run(self) -> List[Vulnerability]:
        try:
            from zapv2 import ZAPv2  # type: ignore
        except ImportError:
            raise ImportError(
                "python-owasp-zap-v2.4 is not installed. "
                "Run: pip install python-owasp-zap-v2.4"
            )

        self._emit("[ZAP] Connecting to ZAP daemon…", 2)
        zap = ZAPv2(apikey=self._api_key, proxies=self._proxies)

        try:
            zap.core.new_session(name="VulneraX_Session", overwrite=True)
        except Exception as exc:  # noqa: BLE001
            raise ConnectionError(
                f"Cannot reach ZAP on {self._proxies['http']}. "
                "Is ZAP running with API enabled? Error: " + str(exc)
            ) from exc

        # --- Spider ---
        self._emit("[ZAP] Starting spider…", 10)
        scan_id = zap.spider.scan(self.target)
        deadline = time.monotonic() + self.timeout
        while int(zap.spider.status(scan_id)) < 100:
            if time.monotonic() > deadline:
                self.log.warning("ZAP spider timed out.")
                break
            pct = int(zap.spider.status(scan_id))
            self._emit(f"[ZAP] Spider progress: {pct}%", 10 + pct // 5)
            time.sleep(2)

        # --- Active Scan ---
        self._emit("[ZAP] Starting active scan…", 30)
        ascan_id = zap.ascan.scan(self.target)
        deadline = time.monotonic() + self.timeout
        while int(zap.ascan.status(ascan_id)) < 100:
            if time.monotonic() > deadline:
                self.log.warning("ZAP active scan timed out.")
                break
            pct = int(zap.ascan.status(ascan_id))
            self._emit(f"[ZAP] Active scan progress: {pct}%", 30 + pct * 7 // 10)
            time.sleep(3)

        # --- Collect Alerts ---
        self._emit("[ZAP] Collecting alerts…", 95)
        alerts = zap.core.alerts(baseurl=self.target)
        return self._convert_alerts(alerts)

    # ------------------------------------------------------------------
    def _convert_alerts(self, alerts: list) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        for alert in alerts:
            raw_risk = alert.get("risk", "Informational")
            severity = normalize_severity(_RISK_MAP.get(raw_risk, "info"))

            refs_raw = alert.get("reference", "")
            refs = [r.strip() for r in refs_raw.split("\n") if r.strip()]

            findings.append(
                Vulnerability(
                    name=alert.get("alert", "Unknown ZAP Alert"),
                    source=self.name,
                    description=alert.get("description", ""),
                    severity=severity,
                    url=alert.get("url", self.target),
                    remediation=alert.get("solution", ""),
                    references=refs,
                    tags=["zap", "active-scan"],
                    raw=alert,
                )
            )

        self.log.info("ZAP found %d alerts.", len(findings))
        return findings
