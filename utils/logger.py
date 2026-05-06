"""
VulneraX — Logging Subsystem
==============================
Provides a pre-configured logger with:
  - Colour-coded console output (ANSI)
  - Rotating file handler (vulnerax.log)
  - Optional GUI callback for live log streaming
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# ANSI colour codes (terminal)
# ---------------------------------------------------------------------------
RESET = "\033[0m"
_COLOURS = {
    "DEBUG": "\033[36m",      # Cyan
    "INFO": "\033[32m",       # Green
    "WARNING": "\033[33m",    # Yellow
    "ERROR": "\033[31m",      # Red
    "CRITICAL": "\033[35m",   # Magenta
}

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vulnerax.log")


class ColourFormatter(logging.Formatter):
    """Console formatter with ANSI colour support."""

    def format(self, record: logging.LogRecord) -> str:
        colour = _COLOURS.get(record.levelname, RESET)
        record.levelname = f"{colour}{record.levelname:<8}{RESET}"
        return super().format(record)


class GUIHandler(logging.Handler):
    """Custom handler that forwards log records to a GUI callback."""

    def __init__(self, callback: Callable[[str, str], None]) -> None:
        super().__init__()
        self._callback = callback

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            level = record.levelname.strip().lower()
            self._callback(msg, level)
        except Exception:  # noqa: BLE001
            self.handleError(record)


def get_logger(name: str = "vulnerax") -> logging.Logger:
    """Return a module-level logger. Call once per module."""
    return logging.getLogger(name)


def setup_logging(
    level: int = logging.DEBUG,
    console_level: Optional[int] = None,
    gui_callback: Optional[Callable[[str, str], None]] = None,
    log_file: str = LOG_FILE,
) -> logging.Logger:
    """
    Configure the root VulneraX logger.

    Args:
        level:        Root logging level.
        gui_callback: Optional callback(message, level) for live GUI streaming.
        log_file:     Path for the rotating log file.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger("vulnerax")
    logger.setLevel(level)
    logger.handlers.clear()

    fmt = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    date_fmt = "%H:%M:%S"

    # --- Console handler ---
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level if console_level is not None else level)
    console_handler.setFormatter(ColourFormatter(fmt, datefmt=date_fmt))
    logger.addHandler(console_handler)

    # --- File handler ---
    try:
        file_handler = RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(fmt, datefmt=date_fmt))
        logger.addHandler(file_handler)
    except OSError as exc:
        logger.warning("Could not create log file at %s: %s", log_file, exc)

    # --- GUI handler ---
    if gui_callback is not None:
        gui_h = GUIHandler(gui_callback)
        gui_h.setLevel(level)
        gui_h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(gui_h)

    logger.propagate = False
    return logger
