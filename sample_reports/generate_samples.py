"""
VulneraX — Sample Report Generator
=====================================
Generates realistic sample reports (HTML, JSON, CSV) in sample_reports/
so users can see what output looks like before running a real scan.

Run:  python sample_reports/generate_samples.py
"""

import sys
import os
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.schema import ScanResult, Vulnerability
from core.ai_layer import enrich_all, generate_executive_summary
from core.risk_engine import RiskEngine
from reports.html_report import HTMLReporter
from reports.json_report import JSONReporter
from reports.csv_report import CSVReporter

# ─── Build a realistic mock ScanResult ─────────────────────────────────────

SAMPLE_VULNS = [
    Vulnerability(
        name="Open Port 21/TCP (FTP)",
        source="nmap",
        description="FTP service detected on port 21. FTP transmits credentials and data in cleartext.",
        severity="high",
        cvss_score=8.1,
        url="192.168.1.100",
        port=21,
        protocol="tcp",
        remediation="Disable FTP and replace with SFTP or SCP. If FTP is required, enforce FTPS and restrict access by IP.",
        tags=["port-scan", "service-detection"],
        confirmed_by=["nuclei"],
        boosted=True,
    ),
    Vulnerability(
        name="Open Port 23/TCP (Telnet)",
        source="nmap",
        description="Telnet service is running on port 23. All communication including credentials is transmitted in plaintext.",
        severity="critical",
        cvss_score=9.8,
        url="192.168.1.100",
        port=23,
        protocol="tcp",
        remediation="Disable Telnet immediately and replace with SSH (port 22) with key-based authentication.",
        tags=["port-scan", "plaintext-protocol"],
    ),
    Vulnerability(
        name="Missing Security Header: Strict-Transport-Security",
        source="header_security",
        description="HSTS header is not configured. The site is vulnerable to protocol downgrade attacks and SSL stripping.",
        severity="medium",
        cvss_score=5.3,
        url="https://example.com",
        remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        tags=["headers", "misconfiguration", "owasp"],
    ),
    Vulnerability(
        name="Missing Security Header: Content-Security-Policy",
        source="header_security",
        description="No CSP header found. Without a Content Security Policy, the application has no XSS mitigation at the browser level.",
        severity="medium",
        cvss_score=5.5,
        url="https://example.com",
        remediation="Define and deploy a Content-Security-Policy header. Start with 'default-src https:' and tighten iteratively.",
        tags=["headers", "xss", "owasp"],
    ),
    Vulnerability(
        name="Cross-Site Scripting (Reflected)",
        source="zap",
        description="Reflected XSS was detected in the 'search' parameter. User-supplied input is reflected in the response without proper encoding.",
        severity="high",
        cvss_score=7.4,
        url="https://example.com/search?q=<script>",
        cve="CVE-2023-12345",
        remediation="Implement context-sensitive output encoding for all user-controlled data. Apply a Content Security Policy.",
        references=["https://owasp.org/www-community/attacks/xss/"],
        tags=["xss", "injection", "owasp-a03"],
        confirmed_by=["nikto"],
        boosted=True,
    ),
    Vulnerability(
        name="SQL Injection",
        source="zap",
        description="SQL injection vulnerability detected in the 'id' parameter. An attacker could extract, modify, or delete database content.",
        severity="critical",
        cvss_score=9.3,
        url="https://example.com/product?id=1",
        cve="CVE-2023-67890",
        remediation="Replace all string-concatenated SQL with parameterised queries or prepared statements. Apply least-privilege DB accounts.",
        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
        tags=["sqli", "injection", "owasp-a03"],
    ),
    Vulnerability(
        name="Outdated Apache Version (2.4.49)",
        source="nikto",
        description="Apache HTTP Server 2.4.49 is outdated and vulnerable to CVE-2021-41773 (path traversal / RCE).",
        severity="critical",
        cvss_score=9.8,
        url="https://example.com",
        cve="CVE-2021-41773",
        remediation="Upgrade Apache to version 2.4.51 or later immediately. This vulnerability has public exploits available.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        tags=["outdated-software", "rce", "apache"],
        confirmed_by=["nuclei"],
        boosted=True,
    ),
    Vulnerability(
        name="Directory Listing Enabled",
        source="nikto",
        description="Directory listing is enabled on the web server, exposing internal file structure to unauthenticated users.",
        severity="medium",
        cvss_score=5.0,
        url="https://example.com/uploads/",
        remediation="Disable directory listing: add 'Options -Indexes' in Apache or 'autoindex off;' in Nginx.",
        tags=["misconfiguration", "information-disclosure"],
    ),
    Vulnerability(
        name="Exposed .git Directory",
        source="nuclei",
        description="The .git directory is publicly accessible, potentially exposing source code, credentials and deployment secrets.",
        severity="high",
        cvss_score=7.5,
        url="https://example.com/.git/config",
        remediation="Block access to .git at the web server level. Rotate any exposed credentials immediately.",
        references=["https://github.com/internetwache/GitTools"],
        tags=["misconfiguration", "secret-exposure", "git"],
    ),
    Vulnerability(
        name="Server Version Disclosure via Server Header",
        source="header_security",
        description="The Server response header reveals: 'Apache/2.4.49 (Ubuntu)'. Version disclosure aids targeted attacks.",
        severity="low",
        cvss_score=2.6,
        url="https://example.com",
        remediation="Configure 'ServerTokens Prod' in Apache or 'server_tokens off;' in Nginx to suppress version info.",
        tags=["headers", "disclosure", "fingerprinting"],
    ),
    Vulnerability(
        name="Open Port 443/TCP (HTTPS)",
        source="nmap",
        description="HTTPS service running on port 443. Standard expected port — verify TLS configuration.",
        severity="info",
        cvss_score=0.0,
        url="192.168.1.100",
        port=443,
        protocol="tcp",
        remediation="Ensure TLS 1.2 or 1.3 only, disable weak cipher suites, and enable HSTS.",
        tags=["port-scan"],
    ),
    Vulnerability(
        name="Cookie Without HttpOnly Flag",
        source="zap",
        description="Session cookie 'PHPSESSID' is set without the HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS-based session hijacking.",
        severity="medium",
        cvss_score=4.3,
        url="https://example.com/login",
        remediation="Add HttpOnly; Secure; SameSite=Strict to all session cookie Set-Cookie headers.",
        tags=["cookie", "session-management"],
    ),
]


def generate() -> None:
    """Generate all sample report files."""
    out_dir = os.path.dirname(os.path.abspath(__file__))

    result = ScanResult(
        target="https://example.com",
        scan_type="full",
        tools_used=["nmap", "zap", "nikto", "nuclei", "header_security"],
        started_at=datetime.datetime(2026, 5, 1, 10, 0, 0).isoformat(),
        completed_at=datetime.datetime(2026, 5, 1, 10, 18, 42).isoformat(),
        errors=[
            "ZAP active scan timed out — partial results collected.",
        ],
    )
    result.vulnerabilities = SAMPLE_VULNS

    # Apply risk scoring
    RiskEngine().score_all(result.vulnerabilities)

    # Enrich with AI layer
    enrich_all(result.vulnerabilities)
    result.executive_summary = generate_executive_summary(result)  # type: ignore[attr-defined]

    # Generate reports
    base = os.path.join(out_dir, "sample_report")
    JSONReporter().generate(result, base + ".json")
    CSVReporter().generate(result, base + ".csv")
    HTMLReporter().generate(result, base + ".html")

    print(f"Sample reports generated in: {out_dir}")
    print(f"  HTML: {base}.html")
    print(f"  JSON: {base}.json")
    print(f"  CSV:  {base}.csv")


if __name__ == "__main__":
    generate()
