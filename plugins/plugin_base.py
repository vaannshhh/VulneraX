"""
VulneraX — Plugin Base Interface
==================================
All third-party scanner plugins must subclass PluginBase and implement run().
This is the public contract that the plugin system enforces.

Example
-------
    from plugins.plugin_base import PluginBase
    from utils.schema import Vulnerability

    class MyScanner(PluginBase):
        name = "my_scanner"
        description = "My custom scanner plugin"
        author = "Your Name"
        version = "1.0.0"

        def run(self) -> list[Vulnerability]:
            # ... scan logic ...
            return []
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Callable, List, Optional

from scanners.base_scanner import BaseScanner
from utils.schema import Vulnerability


class PluginBase(BaseScanner):
    """
    Abstract base class for VulneraX scanner plugins.

    Inherits from BaseScanner so plugins get free timeout handling,
    progress callbacks, and uniform error catching via execute().

    Required class attributes
    -------------------------
    name        : str  — unique snake_case identifier (e.g. "my_scanner")
    description : str  — one-line human description
    author      : str  — plugin author
    version     : str  — semver string
    """

    name: str = "plugin_base"
    description: str = "Abstract plugin base"
    author: str = "Unknown"
    version: str = "0.0.0"

    def __init__(
        self,
        target: str,
        timeout: int = 120,
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ) -> None:
        super().__init__(target, timeout, progress_callback)

    @abstractmethod
    def run(self) -> List[Vulnerability]:
        """
        Perform the plugin's scan against self.target.

        Returns:
            List of Vulnerability objects.

        Raises:
            FileNotFoundError: If a required binary is missing.
            Any other exception on scan failure (will be caught by execute()).
        """
