"""
VulneraX — Example Plugin
===========================
Demonstrates how to write a custom scanner plugin for VulneraX.

This plugin performs a lightweight HTTP header security check:
  - Checks for missing security headers
  - Flags insecure server banners
  - Reports missing HTTPS redirect

Copy this file, rename it, and modify run() to add your own scanner logic.
VulneraX will auto-discover it on next launch.
"""

from __future__ import annotations

from typing import List
from urllib.parse import urlparse

import urllib3

from plugins.plugin_base import PluginBase
from utils.schema import Vulnerability

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Security headers that should be present on every response
REQUIRED_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "HSTS not set — site is vulnerable to protocol downgrade attacks.",
    "Content-Security-Policy": "CSP header missing — XSS mitigation is not in place.",
    "X-Frame-Options": "X-Frame-Options missing — site may be vulnerable to clickjacking.",
    "X-Content-Type-Options": "X-Content-Type-Options missing — MIME sniffing attacks possible.",
    "Referrer-Policy": "Referrer-Policy not set — sensitive URL data may leak via Referer header.",
    "Permissions-Policy": "Permissions-Policy missing — browser feature access is unrestricted.",
}

SERVER_BANNER_SIGNATURES = ["apache", "nginx", "iis", "php", "openssl", "lighttpd"]


class HeaderSecurityPlugin(PluginBase):
    """Checks HTTP response headers for common security misconfigurations."""

    name = "header_security"
    description = "HTTP security header checker — flags missing or insecure response headers"
    author = "VulneraX Contributors"
    version = "1.0.0"

    def run(self) -> List[Vulnerability]:
        """
        Perform the header security check.

        Returns:
            List of Vulnerability objects for each missing/insecure header.
        """
        try:
            import requests
        except ImportError:
            raise ImportError("requests library is required for HeaderSecurityPlugin")

        target = self.target
        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        self._emit(f"[HEADER_SECURITY] Checking headers for {target}", 10)

        try:
            resp = requests.get(target, timeout=10, verify=False, allow_redirects=True)
        except Exception as exc:
            self.log.warning("Could not reach %s: %s", target, exc)
            return []

        headers = {k.lower(): v for k, v in resp.headers.items()}
        findings: List[Vulnerability] = []

        # --- Missing security headers ---
        for header, description in REQUIRED_HEADERS.items():
            if header.lower() not in headers:
                findings.append(
                    Vulnerability(
                        name=f"Missing Security Header: {header}",
                        source=self.name,
                        description=description,
                        severity="medium",
                        url=target,
                        remediation=(
                            f"Add the '{header}' response header to your web server "
                            "or application configuration. Refer to OWASP Secure Headers "
                            "Project for recommended values."
                        ),
                        tags=["headers", "misconfiguration", "owasp"],
                    )
                )

        # --- Server banner disclosure ---
        server_header = headers.get("server", "")
        for sig in SERVER_BANNER_SIGNATURES:
            if sig in server_header.lower():
                findings.append(
                    Vulnerability(
                        name="Server Version Disclosure via Server Header",
                        source=self.name,
                        description=(
                            f"The Server response header discloses version information: "
                            f"'{server_header}'. This gives attackers a starting point "
                            "for targeted exploit searches."
                        ),
                        severity="low",
                        url=target,
                        remediation=(
                            "Configure your web server to suppress or obfuscate the "
                            "Server header value (e.g., `ServerTokens Prod` in Apache, "
                            "`server_tokens off;` in Nginx)."
                        ),
                        tags=["headers", "disclosure", "fingerprinting"],
                    )
                )
                break  # One finding per banner

        # --- HTTP → HTTPS redirect check ---
        if target.startswith("http://"):
            https_target = "https://" + target[7:]
            try:
                https_resp = requests.get(
                    https_target, timeout=5, verify=False, allow_redirects=False
                )
                # If HTTP doesn't redirect to HTTPS, flag it
                if not resp.url.startswith("https://"):
                    findings.append(
                        Vulnerability(
                            name="HTTP to HTTPS Redirect Not Enforced",
                            source=self.name,
                            description=(
                                "The site does not automatically redirect HTTP traffic "
                                "to HTTPS, allowing unencrypted connections."
                            ),
                            severity="medium",
                            url=target,
                            remediation=(
                                "Configure a permanent 301 redirect from HTTP to HTTPS. "
                                "Also enable HSTS to prevent future HTTP connections."
                            ),
                            tags=["tls", "redirect", "misconfiguration"],
                        )
                    )
            except Exception:  # noqa: BLE001
                pass  # HTTPS may simply not be available

        self.log.info("HeaderSecurityPlugin found %d findings.", len(findings))
        return findings
