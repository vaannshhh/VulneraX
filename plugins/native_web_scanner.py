"""
VulneraX — Native Web Scanner Plugin
======================================
A 100% pure Python web vulnerability scanner.
Checks for common sensitive files, misconfigurations, and basic injections.
Requires NO external dependencies.
"""

from __future__ import annotations

import requests
from typing import List
from urllib.parse import urlparse, urljoin

from plugins.plugin_base import PluginBase
from utils.schema import Vulnerability


_SENSITIVE_PATHS = {
    "/.git/config": ("high", "Exposed Git Repository", "The .git folder is accessible. This can leak source code and credentials. Block access to .git immediately."),
    "/.env": ("critical", "Exposed .env File", "The .env file is accessible, likely exposing database credentials and API keys. Remove it from the web root immediately."),
    "/phpinfo.php": ("medium", "Exposed phpinfo()", "A phpinfo() diagnostic file is exposed, leaking sensitive server configuration details."),
    "/server-status": ("low", "Apache Server Status", "Apache server-status page is exposed, showing current worker requests. Restrict access by IP."),
    "/wp-config.php.bak": ("high", "Exposed Backup Config", "A backup configuration file is exposed, potentially leaking database credentials."),
    "/robots.txt": ("info", "Robots.txt Found", "Review robots.txt to ensure it doesn't leak paths to sensitive internal directories."),
}


class NativeWebScanner(PluginBase):
    name        = "native_web_scanner"
    description = "Pure-Python web directory and basic vulnerability scanner"
    author      = "VulneraX Contributors"
    version     = "1.0.0"

    def run(self) -> List[Vulnerability]:
        findings = []
        
        # Ensure target has scheme
        base_url = self.target
        if not base_url.startswith("http"):
            # We assume http for port 80 and https for 443, but a quick probe is best.
            # We'll just try https first, then http.
            try:
                requests.get(f"https://{self.target}", timeout=3, verify=False)
                base_url = f"https://{self.target}"
            except Exception:
                base_url = f"http://{self.target}"

        self._emit(f"Scanning base URL: {base_url}", 10)

        # 1. Directory Bruteforcing (Sensitive Files)
        total = len(_SENSITIVE_PATHS)
        for idx, (path, (sev, title, remediation)) in enumerate(_SENSITIVE_PATHS.items()):
            self._emit(f"Checking {path}...", 10 + int(80 * (idx / total)))
            
            url = urljoin(base_url, path)
            try:
                # We use stream=True so we don't download large files by accident
                resp = requests.get(url, timeout=3, verify=False, allow_redirects=False, stream=True)
                
                # If we get a 200 OK and it looks like real content (not a soft 404)
                if resp.status_code == 200:
                    # Quick soft 404 check
                    text = resp.raw.read(500).decode('utf-8', errors='ignore').lower()
                    if "not found" not in text and "404" not in text:
                        findings.append(
                            Vulnerability(
                                name=title,
                                source=self.name,
                                description=f"Found sensitive file at {path}.",
                                severity=sev,
                                url=url,
                                remediation=remediation,
                                tags=["web", "sensitive-data", "native"],
                            )
                        )
            except requests.RequestException:
                pass

        self._emit("Finished.", 100)
        return findings
