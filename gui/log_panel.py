"""
VulneraX — Live Log Panel
===========================
Color-coded real-time log viewer with auto-scroll and level filtering.
"""

from __future__ import annotations

import re
import tkinter as tk
from typing import Optional

import customtkinter as ctk

from gui.styles import (
    BG_TERTIARY, BORDER, FONT_MONO, FONT_SMALL, FONT_SUBTITLE,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_GREEN, ACCENT_RED, ACCENT_YELLOW, ACCENT_CYAN,
    PAD_MD, PAD_LG, CORNER_LG, CTK_FRAME,
)


# Pattern → colour tag
_LOG_PATTERNS = [
    (re.compile(r"(\[✔\]|\[DONE\]|\[\+\]|\[INFO\].*found|completed)", re.I), "success"),
    (re.compile(r"(\[!\]|\[ERROR\]|\[CRIT\]|failed|exception)", re.I),        "error"),
    (re.compile(r"(\[-\]|\[WARN\]|skipped|timeout|missing)", re.I),           "warning"),
    (re.compile(r"(\[\*\]|\[INFO\]|starting|running|connecting)", re.I),       "info"),
]

_TAG_COLORS = {
    "success": ACCENT_GREEN,
    "error":   ACCENT_RED,
    "warning": ACCENT_YELLOW,
    "info":    ACCENT_CYAN,
    "default": TEXT_MUTED,
}


def _classify(line: str) -> str:
    for pattern, tag in _LOG_PATTERNS:
        if pattern.search(line):
            return tag
    return "default"


class LogPanel(ctk.CTkFrame):
    """
    Scrollable, color-coded real-time log display.

    Thread-safe: call :meth:`append` from any thread.
    """

    def __init__(self, parent: ctk.CTkFrame, **kwargs) -> None:
        super().__init__(parent, **CTK_FRAME, **kwargs)
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        # Header row
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=PAD_LG, pady=(PAD_MD, 0))

        ctk.CTkLabel(
            header, text="⬛  Live Scan Log",
            font=FONT_SUBTITLE, text_color=TEXT_PRIMARY,
        ).pack(side="left")

        self._clear_btn = ctk.CTkButton(
            header, text="Clear", width=60, height=28,
            fg_color="transparent", border_width=1, border_color=BORDER,
            text_color=TEXT_SECONDARY, font=FONT_SMALL,
            hover_color=BG_TERTIARY, command=self.clear,
        )
        self._clear_btn.pack(side="right")

        # Text widget inside a frame for border effect
        textbox_frame = ctk.CTkFrame(self, fg_color=BG_TERTIARY,
                                     corner_radius=10, border_width=1,
                                     border_color=BORDER)
        textbox_frame.pack(fill="both", expand=True,
                           padx=PAD_LG, pady=PAD_MD)

        self._text = tk.Text(
            textbox_frame,
            state="disabled",
            background=BG_TERTIARY,
            foreground=TEXT_MUTED,
            font=FONT_MONO,
            relief="flat",
            wrap="word",
            padx=12,
            pady=10,
            cursor="arrow",
            selectbackground="#2a2f40",
            insertbackground=ACCENT_GREEN,
            borderwidth=0,
            highlightthickness=0,
        )
        scrollbar = ctk.CTkScrollbar(textbox_frame, command=self._text.yview)
        self._text.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        self._text.pack(fill="both", expand=True)

        # Register colour tags
        for tag, color in _TAG_COLORS.items():
            self._text.tag_configure(tag, foreground=color)

        self._line_count = 0

    # ------------------------------------------------------------------
    def append(self, message: str, level: str = "default") -> None:
        """
        Append a line to the log widget — thread-safe via after().

        Args:
            message: The log line to display.
            level:   Colour tag hint ('success'|'error'|'warning'|'info'|'default').
        """
        self.after(0, self._insert, message, level)

    def _insert(self, message: str, level: str) -> None:
        tag = level if level in _TAG_COLORS else _classify(message)
        line = message.rstrip("\n") + "\n"
        self._text.configure(state="normal")
        self._text.insert("end", line, tag)
        self._text.see("end")
        self._text.configure(state="disabled")
        self._line_count += 1

    def clear(self) -> None:
        """Clear all log content."""
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.configure(state="disabled")
        self._line_count = 0

    def log_callback(self, message: str, level: str = "default") -> None:
        """
        Direct callable suitable for use as a logging handler callback.
        Strips ANSI codes before display.
        """
        clean = re.sub(r"\x1b\[[0-9;]*m", "", message)
        self.append(clean, level)
