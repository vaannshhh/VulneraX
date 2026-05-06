"""
VulneraX — AI / NLP Layer
===========================
Produces human-readable summaries and actionable remediation steps from
structured vulnerability data without requiring any external API calls.

Design
------
- Rule-based NLP with keyword matching and template filling.
- Remediation lookup table covers OWASP Top 10 + common network findings.
- Plain-English severity descriptions for executive summaries.
- All output is deterministic and works fully offline.
"""

from __future__ import annotations

import textwrap
from typing import List

from utils.logger import get_logger
from utils.schema import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    ScanResult,
    Vulnerability,
)

log = get_logger("vulnerax.ai")


# ---------------------------------------------------------------------------
# Remediation knowledge base
# ---------------------------------------------------------------------------
_REMEDIATION_KB: dict[str, str] = {
    # Network / ports
    "ftp": (
        "Disable FTP and replace with SFTP or SCP. If FTP is required, enforce "
        "TLS via FTPS and restrict access to known IP addresses using firewall rules."
    ),
    "telnet": (
        "Disable Telnet immediately and replace with SSH. Telnet transmits all "
        "data, including credentials, in plaintext."
    ),
    "rdp": (
        "Restrict RDP access to VPN-only connections. Enable Network Level "
        "Authentication (NLA), apply all Windows security patches, and enforce "
        "strong password policies."
    ),
    "smb": (
        "Disable SMBv1 immediately. Restrict SMB access using firewall rules. "
        "Apply all Microsoft security patches relating to EternalBlue / MS17-010."
    ),
    "vnc": (
        "Disable VNC unless strictly required. If needed, tunnel over SSH and "
        "enforce strong authentication with session encryption."
    ),
    # Web
    "xss": (
        "Implement context-sensitive output encoding for all user-controlled data. "
        "Deploy a Content Security Policy (CSP) header. Use a modern framework "
        "with XSS protection built-in."
    ),
    "sql injection": (
        "Replace all string-concatenated SQL with parameterised queries or "
        "prepared statements. Apply principle of least privilege to DB accounts. "
        "Use an ORM where possible."
    ),
    "csrf": (
        "Implement CSRF tokens on all state-changing forms. Verify the Origin and "
        "Referer headers server-side. Use SameSite=Strict cookies."
    ),
    "header": (
        "Configure the following security headers: Strict-Transport-Security, "
        "Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: "
        "nosniff, Referrer-Policy."
    ),
    "cookie": (
        "Set the Secure, HttpOnly, and SameSite=Strict attributes on all session "
        "cookies. Rotate session IDs after authentication."
    ),
    "directory listing": (
        "Disable directory listing in your web server configuration "
        "(e.g., `Options -Indexes` in Apache, `autoindex off;` in Nginx)."
    ),
    "outdated": (
        "Update the identified software component to the latest stable release. "
        "Subscribe to the vendor's security advisory mailing list and implement "
        "a patch management process."
    ),
    "ssl": (
        "Upgrade to TLS 1.2 or TLS 1.3. Disable SSL 2.0, SSL 3.0, and TLS 1.0/1.1. "
        "Obtain a certificate from a trusted CA and configure HSTS."
    ),
    "open port": (
        "Audit all open ports and close any that are not required for business "
        "operations. Apply firewall rules to restrict access to necessary source IPs."
    ),
}

_SEVERITY_PLAIN: dict[str, str] = {
    SEVERITY_CRITICAL: "critically severe and requires immediate attention",
    SEVERITY_HIGH: "high severity and should be addressed within 24–48 hours",
    SEVERITY_MEDIUM: "medium severity and should be scheduled for remediation this sprint",
    SEVERITY_LOW: "low severity and can be addressed in a routine patching cycle",
    SEVERITY_INFO: "informational and may not require remediation",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def enrich_vulnerability(vuln: Vulnerability) -> Vulnerability:
    """
    Enrich a single vulnerability with improved description and remediation.

    Modifies the object in-place and returns it for chaining.
    """
    if not vuln.remediation:
        vuln.remediation = _lookup_remediation(vuln)
    if not vuln.description or len(vuln.description) < 15:
        vuln.description = _generate_description(vuln)
    return vuln


def enrich_all(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """Enrich every finding in the list."""
    for v in vulns:
        enrich_vulnerability(v)
    return vulns


def generate_executive_summary(result: ScanResult) -> str:
    """
    Produce a plain-English executive summary paragraph for reports.

    Args:
        result: Completed ScanResult.

    Returns:
        Multi-line summary string.
    """
    stats = result.by_severity
    total = result.total
    tools = ", ".join(result.tools_used) if result.tools_used else "no tools"

    crit = stats.get(SEVERITY_CRITICAL, 0)
    high = stats.get(SEVERITY_HIGH, 0)
    med = stats.get(SEVERITY_MEDIUM, 0)
    low = stats.get(SEVERITY_LOW, 0)

    risk_level = "Low"
    if crit > 0:
        risk_level = "Critical"
    elif high > 0:
        risk_level = "High"
    elif med > 0:
        risk_level = "Medium"

    summary = textwrap.dedent(f"""
        An automated vulnerability assessment was conducted against **{result.target}**
        using the VulneraX framework. The scan employed {tools} and identified a total
        of **{total} unique security finding(s)**.

        Overall Risk Level: **{risk_level}**

        Findings breakdown:
          • Critical : {crit}
          • High     : {high}
          • Medium   : {med}
          • Low      : {low}

        {"Immediate remediation is strongly recommended for all Critical and High severity findings." if crit + high > 0 else "No critical or high severity issues were identified during this assessment."}
        {"Multi-tool confirmation increased confidence in " + str(sum(1 for v in result.vulnerabilities if v.boosted)) + " finding(s)." if any(v.boosted for v in result.vulnerabilities) else ""}
    """).strip()

    return summary


def plain_english(vuln: Vulnerability) -> str:
    """
    Produce a one-sentence plain-English description of a vulnerability.
    """
    sev_desc = _SEVERITY_PLAIN.get(vuln.severity, "of unknown severity")
    source_note = (
        f"confirmed by {', '.join(vuln.confirmed_by)}"
        if vuln.confirmed_by
        else f"detected by {vuln.source}"
    )
    cve_note = f" (CVE: {vuln.cve})" if vuln.cve else ""

    return (
        f"'{vuln.name}'{cve_note} is {sev_desc}, "
        f"{source_note}. {vuln.remediation[:120] if vuln.remediation else ''}"
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------
def _lookup_remediation(vuln: Vulnerability) -> str:
    name_lower = vuln.name.lower()
    desc_lower = vuln.description.lower()
    combined = name_lower + " " + desc_lower

    for keyword, advice in _REMEDIATION_KB.items():
        if keyword in combined:
            return advice

    # Port-specific fallback
    if vuln.port:
        return (
            f"Verify that port {vuln.port} is intentionally exposed. "
            "Apply firewall restrictions and ensure the running service is fully patched."
        )

    return (
        "Review the affected component against the relevant OWASP or CIS benchmark. "
        "Apply vendor patches and follow secure configuration guidelines."
    )


def _generate_description(vuln: Vulnerability) -> str:
    sev = vuln.severity.capitalize()
    src = vuln.source.upper()
    port_ctx = f" on port {vuln.port}" if vuln.port else ""
    url_ctx = f" at {vuln.url}" if vuln.url else ""
    return (
        f"{sev} severity finding detected by {src}{port_ctx}{url_ctx}. "
        f"{vuln.name}."
    )
