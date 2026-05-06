"""
VulneraX — Native Port Scanner Plugin
=======================================
A 100% pure Python multi-threaded port scanner.
Requires NO external dependencies (unlike Nmap).
"""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional
from urllib.parse import urlparse

from plugins.plugin_base import PluginBase
from utils.schema import Vulnerability

# Top 50 most common ports for a fast scan
_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
    993, 995, 1723, 3306, 3389, 5900, 8000, 8080, 8443, 8888,
    27017, 6379, 5432, 1433, 1521, 9200, 11211, 5000, 3000,
]

_PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy",
    27017: "MongoDB", 6379: "Redis", 5432: "PostgreSQL",
}

_DANGEROUS_PORTS = {
    21: "FTP transmits data in cleartext.",
    23: "Telnet transmits data in cleartext. Highly vulnerable to interception.",
    3389: "RDP should not be exposed directly to the internet.",
    5900: "VNC should not be exposed directly to the internet.",
}


class NativePortScanner(PluginBase):
    name        = "native_port_scanner"
    description = "Fast, pure-Python threaded port scanner (Top 50 ports)"
    author      = "VulneraX Contributors"
    version     = "1.0.0"

    def run(self) -> List[Vulnerability]:
        findings = []
        host = self._get_hostname(self.target)
        if not host:
            self.log.error("Could not determine hostname from target.")
            return findings

        # Resolve IP
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            self.log.error(f"Could not resolve hostname: {host}")
            return findings

        self._emit(f"Resolved {host} to {ip}", 10)

        # Thread pool for fast scanning
        open_ports = []
        total_ports = len(_COMMON_PORTS)

        def scan_port(port: int) -> None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
            except Exception:
                pass
            finally:
                sock.close()

        with ThreadPoolExecutor(max_workers=20) as executor:
            # We map simply to run them concurrently
            futures = [executor.submit(scan_port, p) for p in _COMMON_PORTS]
            for i, _ in enumerate(futures):
                if i % 10 == 0:
                    self._emit(f"Scanning ports... ({i}/{total_ports})", 10 + int(80 * (i/total_ports)))

        self._emit("Port scan complete, analyzing results.", 95)

        for port in sorted(open_ports):
            service = _PORT_SERVICES.get(port, "Unknown Service")
            
            # Determine severity
            severity = "info"
            remediation = "Ensure this port is meant to be exposed. Use firewalls to restrict access if necessary."
            
            if port in _DANGEROUS_PORTS:
                severity = "high" if port in (23, 3389) else "medium"
                remediation = _DANGEROUS_PORTS[port] + " Block this port at the firewall or use a VPN/SSH tunnel."

            findings.append(
                Vulnerability(
                    name=f"Open Port {port}/TCP ({service})",
                    source=self.name,
                    description=f"Port {port} is open and running {service}.",
                    severity=severity,
                    url=self.target,
                    port=port,
                    protocol="tcp",
                    remediation=remediation,
                    tags=["port-scan", "native"],
                )
            )

        self._emit("Finished.", 100)
        return findings

    def _get_hostname(self, target: str) -> str:
        if target.startswith("http://") or target.startswith("https://"):
            return urlparse(target).hostname or ""
        return target
