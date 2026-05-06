"""
VulneraX — Input Classifier
=============================
Detects whether a user-supplied target is an IP address, a domain/hostname,
or a full URL, then recommends the optimal scanner set.
"""

import ipaddress
import re
from enum import Enum
from typing import List
from urllib.parse import urlparse


class TargetType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    UNKNOWN = "unknown"


# Recommended scanners per target type
SCANNER_MAP: dict[TargetType, List[str]] = {
    TargetType.IP: ["nmap", "nuclei"],
    TargetType.DOMAIN: ["zap", "nikto", "nuclei", "nmap"],
    TargetType.URL: ["zap", "nikto", "nuclei"],
    TargetType.UNKNOWN: ["nmap", "nuclei"],
}


def classify(target: str) -> TargetType:
    """
    Classify a raw target string.

    Args:
        target: Raw user input (e.g. '192.168.1.1', 'example.com', 'https://…').

    Returns:
        TargetType enum value.
    """
    target = target.strip()

    # Full URL?
    if target.startswith(("http://", "https://")):
        return TargetType.URL

    # Plain IP address?
    try:
        ipaddress.ip_address(target)
        return TargetType.IP
    except ValueError:
        pass

    # CIDR notation?
    try:
        ipaddress.ip_network(target, strict=False)
        return TargetType.IP
    except ValueError:
        pass

    # Hostname / domain? (letters, digits, hyphens, dots)
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if domain_pattern.match(target):
        return TargetType.DOMAIN

    return TargetType.UNKNOWN


def get_host(target: str) -> str:
    """Extract just the hostname from a URL or return target as-is."""
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.hostname or target
    return target


def recommended_scanners(target: str, scan_type: str = "full") -> List[str]:
    """
    Return the list of scanner names appropriate for *target*.

    Args:
        target:    Raw user input.
        scan_type: 'quick' | 'full' | 'custom'.

    Returns:
        List of scanner name strings.
    """
    t_type = classify(target)
    scanners = SCANNER_MAP.get(t_type, SCANNER_MAP[TargetType.UNKNOWN])

    if scan_type == "quick":
        # Quick scan: only the fastest tools
        quick_set = {"nmap", "nuclei"}
        scanners = [s for s in scanners if s in quick_set]

    return scanners
