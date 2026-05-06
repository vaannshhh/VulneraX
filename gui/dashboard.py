"""
VulneraX — Dashboard Tab
==========================
Shows real-time scan statistics:
  - Total / Critical / High counters
  - Severity distribution bar
  - Tools-used badges
  - Last scan metadata
"""

from __future__ import annotations

import tkinter as tk
from typing import Dict

import customtkinter as ctk

from gui.styles import (
    ACCENT_CYAN, ACCENT_GREEN, ACCENT_ORANGE, ACCENT_PURPLE,
    ACCENT_RED, ACCENT_YELLOW, BG_PRIMARY, BG_SECONDARY,
    BG_TERTIARY, BORDER, FONT_BODY, FONT_MONO_SM, FONT_SMALL,
    FONT_SUBTITLE, FONT_TITLE, PAD_LG, PAD_MD, PAD_SM,
    SEVERITY_COLORS, TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
    CTK_FRAME,
)
from utils.schema import ScanResult


class DashboardPanel(ctk.CTkFrame):
    """Dashboard tab — live summary stats updated after each scan."""

    def __init__(self, parent: ctk.CTkScrollableFrame, **kwargs) -> None:
        super().__init__(parent, fg_color="transparent", **kwargs)
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        # ── Title ───────────────────────────────────────────────────
        title_row = ctk.CTkFrame(self, fg_color="transparent")
        title_row.pack(fill="x", pady=(PAD_MD, PAD_LG))

        ctk.CTkLabel(
            title_row, text="⚡  Scan Dashboard",
            font=FONT_TITLE, text_color=TEXT_PRIMARY,
        ).pack(side="left")

        self._status_badge = ctk.CTkLabel(
            title_row, text="● IDLE",
            font=FONT_SMALL, text_color=TEXT_MUTED,
        )
        self._status_badge.pack(side="right", padx=PAD_MD)

        # ── Stat Cards Row ──────────────────────────────────────────
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, PAD_LG))
        cards_frame.columnconfigure((0, 1, 2, 3, 4), weight=1, uniform="col")

        self._stat_labels: Dict[str, ctk.CTkLabel] = {}
        card_defs = [
            ("total",    "Total",    ACCENT_PURPLE, "0"),
            ("critical", "Critical", ACCENT_RED,    "0"),
            ("high",     "High",     ACCENT_ORANGE, "0"),
            ("medium",   "Medium",   ACCENT_YELLOW, "0"),
            ("low",      "Low",      ACCENT_CYAN,   "0"),
        ]
        for col, (key, label, color, default) in enumerate(card_defs):
            card = ctk.CTkFrame(
                cards_frame, fg_color=BG_SECONDARY,
                corner_radius=12, border_width=1, border_color=BORDER,
            )
            card.grid(row=0, column=col, padx=PAD_SM, sticky="nsew")

            # Coloured top bar
            accent_bar = tk.Frame(card, height=4, background=color, bd=0)
            accent_bar.pack(fill="x")

            num_lbl = ctk.CTkLabel(
                card, text=default, font=("Segoe UI", 32, "bold"),
                text_color=color,
            )
            num_lbl.pack(pady=(PAD_MD, 0))

            ctk.CTkLabel(
                card, text=label.upper(),
                font=("Segoe UI", 10, "bold"), text_color=TEXT_MUTED,
            ).pack(pady=(0, PAD_MD))

            self._stat_labels[key] = num_lbl

        # ── Severity Bar ─────────────────────────────────────────────
        bar_card = ctk.CTkFrame(self, **CTK_FRAME)
        bar_card.pack(fill="x", pady=(0, PAD_LG), ipady=PAD_MD)

        ctk.CTkLabel(
            bar_card, text="Severity Distribution",
            font=FONT_SUBTITLE, text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=PAD_LG, pady=(PAD_MD, PAD_SM))

        bar_container = ctk.CTkFrame(bar_card, fg_color=BG_TERTIARY,
                                      corner_radius=6, height=14)
        bar_container.pack(fill="x", padx=PAD_LG, pady=(0, PAD_MD))
        bar_container.pack_propagate(False)
        self._bar_container = bar_container
        self._bar_segments: list[tk.Frame] = []

        # ── Scan Metadata ────────────────────────────────────────────
        meta_card = ctk.CTkFrame(self, **CTK_FRAME)
        meta_card.pack(fill="x", pady=(0, PAD_LG))

        ctk.CTkLabel(
            meta_card, text="Last Scan Details",
            font=FONT_SUBTITLE, text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=PAD_LG, pady=(PAD_MD, PAD_SM))

        self._meta_text = ctk.CTkLabel(
            meta_card,
            text="No scan completed yet.",
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
            justify="left",
            wraplength=900,
        )
        self._meta_text.pack(anchor="w", padx=PAD_LG, pady=(0, PAD_MD))

        # ── Tools Used ───────────────────────────────────────────────
        tools_card = ctk.CTkFrame(self, **CTK_FRAME)
        tools_card.pack(fill="x")

        ctk.CTkLabel(
            tools_card, text="Tools Engaged",
            font=FONT_SUBTITLE, text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=PAD_LG, pady=(PAD_MD, PAD_SM))

        self._tools_frame = ctk.CTkFrame(tools_card, fg_color="transparent")
        self._tools_frame.pack(fill="x", padx=PAD_LG, pady=(0, PAD_MD))
        ctk.CTkLabel(
            self._tools_frame, text="—", font=FONT_SMALL, text_color=TEXT_MUTED,
        ).pack(side="left")

    # ------------------------------------------------------------------
    def update_from_result(self, result: ScanResult) -> None:
        """Refresh all dashboard widgets from a completed ScanResult."""
        by_sev = result.by_severity

        # Update counters
        self._stat_labels["total"].configure(text=str(result.total))
        for sev in ("critical", "high", "medium", "low"):
            self._stat_labels[sev].configure(text=str(by_sev.get(sev, 0)))

        # Update status badge
        if result.critical_count > 0:
            self._status_badge.configure(text="● CRITICAL FINDINGS", text_color=ACCENT_RED)
        elif result.high_count > 0:
            self._status_badge.configure(text="● HIGH FINDINGS", text_color=ACCENT_ORANGE)
        else:
            self._status_badge.configure(text="● SCAN COMPLETE", text_color=ACCENT_GREEN)

        # Severity bar — rebuild segments
        for seg in self._bar_segments:
            seg.destroy()
        self._bar_segments.clear()

        total = result.total or 1
        for sev, color in SEVERITY_COLORS.items():
            count = by_sev.get(sev, 0)
            if count == 0:
                continue
            pct = count / total
            seg = tk.Frame(self._bar_container, background=color, bd=0)
            seg.place(relx=sum(
                by_sev.get(s, 0) / total for s in list(SEVERITY_COLORS.keys())
                if list(SEVERITY_COLORS.keys()).index(s) < list(SEVERITY_COLORS.keys()).index(sev)
            ), rely=0, relwidth=pct, relheight=1.0)
            self._bar_segments.append(seg)

        # Metadata text
        self._meta_text.configure(
            text=(
                f"Target: {result.target}   |   "
                f"Scan ID: {result.scan_id[:8]}   |   "
                f"Type: {result.scan_type.upper()}   |   "
                f"Started: {result.started_at or '—'}   |   "
                f"Completed: {result.completed_at or '—'}"
            ),
            text_color=TEXT_SECONDARY,
        )

        # Tools used badges
        for widget in self._tools_frame.winfo_children():
            widget.destroy()

        if result.tools_used:
            for tool in result.tools_used:
                badge = ctk.CTkLabel(
                    self._tools_frame, text=f"  {tool.upper()}  ",
                    font=("Segoe UI", 10, "bold"),
                    text_color=ACCENT_GREEN,
                    fg_color="#00ff9d1a",
                    corner_radius=4,
                )
                badge.pack(side="left", padx=(0, PAD_SM))
        else:
            ctk.CTkLabel(
                self._tools_frame, text="—", font=FONT_SMALL, text_color=TEXT_MUTED,
            ).pack(side="left")

    def set_scanning(self) -> None:
        """Switch status badge to scanning state."""
        self._status_badge.configure(text="● SCANNING…", text_color=ACCENT_YELLOW)
