"""
VulneraX — Abstract Base Scanner
==================================
All scanners inherit from BaseScanner and implement `run()`.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Callable, List, Optional

from utils.logger import get_logger
from utils.schema import ScanResult, Vulnerability

log = get_logger("vulnerax.scanner")


class BaseScanner(ABC):
    """
    Abstract scanner interface.

    Subclasses must implement :meth:`run` and set :attr:`name`.
    """

    name: str = "base"
    description: str = "Abstract base scanner"

    def __init__(
        self,
        target: str,
        timeout: int = 120,
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ) -> None:
        """
        Args:
            target:            The scan target (URL, IP, domain).
            timeout:           Maximum seconds to wait for the scan.
            progress_callback: Optional callback(message, percent) for GUI updates.
        """
        self.target = target
        self.timeout = timeout
        self.progress_callback = progress_callback
        self.log = get_logger(f"vulnerax.scanner.{self.name}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def execute(self) -> List[Vulnerability]:
        """
        Execute the scan, catch all exceptions, and return findings.

        Returns:
            List of Vulnerability objects (may be empty on failure).
        """
        self._emit(f"[{self.name.upper()}] Starting scan against {self.target}", 0)
        t0 = time.monotonic()
        try:
            results = self.run()
            elapsed = time.monotonic() - t0
            self._emit(
                f"[{self.name.upper()}] Completed in {elapsed:.1f}s — "
                f"{len(results)} finding(s)",
                100,
            )
            return results
        except FileNotFoundError:
            self.log.warning(
                "%s binary not found in PATH — skipping scan.", self.name
            )
            self._emit(f"[{self.name.upper()}] Skipped (binary not found)", 100)
            return []
        except Exception as exc:  # noqa: BLE001
            self.log.error("%s scan failed: %s", self.name, exc, exc_info=True)
            self._emit(f"[{self.name.upper()}] ERROR: {exc}", 100)
            return []

    # ------------------------------------------------------------------
    # Subclass interface
    # ------------------------------------------------------------------
    @abstractmethod
    def run(self) -> List[Vulnerability]:
        """
        Perform the actual scan.

        Returns:
            List of Vulnerability objects.

        Raises:
            FileNotFoundError: If the required binary is absent.
            Any other exception on scan failure.
        """

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _emit(self, message: str, percent: int) -> None:
        """Fire the progress callback if one was supplied."""
        self.log.info(message)
        if self.progress_callback:
            try:
                self.progress_callback(message, percent)
            except Exception:  # noqa: BLE001
                pass
