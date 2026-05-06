"""
VulneraX — Nmap Output Parser
================================
Standalone parser for Nmap XML output files.
Can be used independently of the NmapScanner (e.g. for importing existing scans).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from utils.schema import Vulnerability


def parse_nmap_xml(file_path: str, target: str = "") -> List[Vulnerability]:
    """
    Parse an Nmap XML output file into Vulnerability objects.

    Args:
        file_path: Path to the nmap XML file.
        target:    Original scan target (used as fallback URL).

    Returns:
        List of Vulnerability objects, one per open port.
    """
    findings: List[Vulnerability] = []
    path = Path(file_path)
    if not path.exists() or path.stat().st_size == 0:
        return findings

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError:
        return findings

    for host in root.findall("host"):
        addr_el = host.find("address")
        host_addr = addr_el.get("addr", target) if addr_el is not None else target

        for port_el in host.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            service_el = port_el.find("service")
            portid    = port_el.get("portid", "?")
            protocol  = port_el.get("protocol", "tcp")
            svc_name  = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product   = service_el.get("product", "")     if service_el is not None else ""
            version   = service_el.get("version", "")     if service_el is not None else ""

            sev = "low"
            if portid in {"21", "23", "3389", "5900", "445"}:
                sev = "high"
            elif portid in {"22", "80", "443", "8080", "8443"}:
                sev = "medium"

            desc_parts = [f"Open {protocol.upper()} port {portid}"]
            if product:
                desc_parts.append(f"running {product}")
            if version:
                desc_parts.append(f"v{version}")

            findings.append(
                Vulnerability(
                    name=f"Open Port {portid}/{protocol} ({svc_name})",
                    source="nmap",
                    description=" ".join(desc_parts) + ".",
                    severity=sev,
                    url=host_addr,
                    port=int(portid),
                    protocol=protocol,
                    remediation=(
                        f"Review whether port {portid} must be publicly accessible. "
                        "Apply firewall rules to restrict access. "
                        f"Ensure {svc_name} is fully patched."
                    ),
                    tags=["port-scan", "service-detection"],
                    raw={"portid": portid, "protocol": protocol,
                         "service": svc_name, "product": product, "version": version},
                )
            )

    return findings
