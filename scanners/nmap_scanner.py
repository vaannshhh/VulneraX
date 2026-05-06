"""
VulneraX — Nmap Scanner
========================
Wraps nmap CLI for port + service-version discovery.
Outputs are parsed from XML and mapped to Vulnerability objects.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, List, Optional

from scanners.base_scanner import BaseScanner
from utils.config_loader import load_config
from utils.schema import Vulnerability, normalize_severity


class NmapScanner(BaseScanner):
    """Runs `nmap -sV -sC` and converts port/service data to findings."""

    name = "nmap"
    description = "Port scanning and service version detection via Nmap"

    def __init__(
        self,
        target: str,
        timeout: int = 120,
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ) -> None:
        cfg = load_config()
        timeout = cfg.get("tools", {}).get("nmap", {}).get("timeout", timeout)
        super().__init__(target, timeout, progress_callback)
        self._flags = cfg.get("tools", {}).get("nmap", {}).get("flags", "-sV -sC")

    # ------------------------------------------------------------------
    def run(self) -> List[Vulnerability]:
        binary = shutil.which("nmap")
        if not binary:
            raise FileNotFoundError("nmap binary not found in PATH")

        # Write XML output to a temp file so we don't pollute the CWD
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        cmd = [binary, *self._flags.split(), "-oX", xml_path, self._host()]
        self._emit(f"[NMAP] Command: {' '.join(cmd)}", 5)

        try:
            subprocess.run(
                cmd,
                timeout=self.timeout,
                capture_output=True,
                check=False,
            )
        finally:
            pass  # XML may still be partially written — parse what we can

        return self._parse_xml(xml_path)

    # ------------------------------------------------------------------
    def _host(self) -> str:
        """Strip scheme from URL if present."""
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        return parsed.hostname or self.target

    def _parse_xml(self, xml_path: str) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        path = Path(xml_path)
        if not path.exists() or path.stat().st_size == 0:
            self.log.warning("Nmap produced no output XML.")
            return findings

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except ET.ParseError as exc:
            self.log.error("Failed to parse Nmap XML: %s", exc)
            return findings

        for host in root.findall("host"):
            addr_el = host.find("address")
            host_addr = addr_el.get("addr", self.target) if addr_el is not None else self.target

            for port_el in host.findall("ports/port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port_el.find("service")
                portid = port_el.get("portid", "?")
                protocol = port_el.get("protocol", "tcp")
                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                version = service_el.get("version", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""

                # Build a human-readable description
                desc_parts = [f"Open {protocol.upper()} port {portid}"]
                if product:
                    desc_parts.append(f"running {product}")
                if version:
                    desc_parts.append(f"version {version}")

                sev = "low"
                if portid in {"21", "23", "3389", "5900", "445"}:
                    sev = "high"
                elif portid in {"22", "80", "443", "8080", "8443"}:
                    sev = "medium"

                findings.append(
                    Vulnerability(
                        name=f"Open Port {portid}/{protocol} ({service_name})",
                        source=self.name,
                        description=" ".join(desc_parts) + ".",
                        severity=sev,
                        url=host_addr,
                        port=int(portid),
                        protocol=protocol,
                        remediation=(
                            f"Review whether port {portid} should be publicly accessible. "
                            "Apply firewall rules to restrict access where not required. "
                            f"Ensure {service_name} is fully patched and hardened."
                        ),
                        tags=["port-scan", "service-detection"],
                        raw={
                            "portid": portid,
                            "protocol": protocol,
                            "service": service_name,
                            "product": product,
                            "version": version,
                        },
                    )
                )

        self.log.info("Nmap found %d open ports.", len(findings))
        return findings
