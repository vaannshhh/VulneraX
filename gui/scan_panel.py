"""
VulneraX — Scan Panel
=======================
Input form for launching scans:
  - Target URL / IP / domain entry
  - Scan type selector (Quick / Full / Custom)
  - Custom scanner checkboxes
  - Animated progress bar + status label
  - Start / Cancel button
"""

from __future__ import annotations

import threading
from typing import Callable, Optional

import customtkinter as ctk

from gui.styles import (
    ACCENT_GREEN, ACCENT_ORANGE, ACCENT_PURPLE, ACCENT_RED,
    ACCENT_YELLOW, BG_SECONDARY, BG_TERTIARY, BORDER,
    CTK_BUTTON, CTK_BUTTON_OUTLINE, CTK_ENTRY, CTK_FRAME,
    FONT_BODY, FONT_SMALL, FONT_SUBTITLE, FONT_TITLE,
    PAD_LG, PAD_MD, PAD_SM, TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
)


class ScanPanel(ctk.CTkFrame):
    """
    Scan configuration and launch panel.

    Args:
        parent:          Parent widget.
        on_scan_start:   Callback(target, scan_type, custom_scanners) → None.
        on_scan_cancel:  Callback() → None.
    """

    def __init__(
        self,
        parent,
        on_scan_start: Callable[[str, str, list], None],
        on_scan_cancel: Callable[[], None],
        **kwargs,
    ) -> None:
        super().__init__(parent, fg_color="transparent", **kwargs)
        self._on_scan_start = on_scan_start
        self._on_scan_cancel = on_scan_cancel
        self._scanning = False
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        # ── Title ────────────────────────────────────────────────────
        ctk.CTkLabel(
            self, text="🔍  New Scan",
            font=FONT_TITLE, text_color=TEXT_PRIMARY,
        ).pack(anchor="w", pady=(PAD_MD, PAD_LG))

        # ── Target Input Card ────────────────────────────────────────
        input_card = ctk.CTkFrame(self, **CTK_FRAME)
        input_card.pack(fill="x", pady=(0, PAD_MD))

        ctk.CTkLabel(
            input_card, text="Target",
            font=FONT_SUBTITLE, text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=PAD_LG, pady=(PAD_LG, PAD_SM))

        ctk.CTkLabel(
            input_card,
            text="Enter a URL, IP address, or domain name.",
            font=FONT_SMALL, text_color=TEXT_MUTED,
        ).pack(anchor="w", padx=PAD_LG, pady=(0, PAD_SM))

        entry_row = ctk.CTkFrame(input_card, fg_color="transparent")
        entry_row.pack(fill="x", padx=PAD_LG, pady=(0, PAD_LG))

        self._target_entry = ctk.CTkEntry(
            entry_row,
            placeholder_text="e.g.  https://example.com   192.168.1.1   scanme.nmap.org",
            **CTK_ENTRY,
        )
        self._target_entry.pack(fill="x", expand=True)

        # ── Scan Type Selector ────────────────────────────────────────
        type_card = ctk.CTkFrame(self, **CTK_FRAME)
        type_card.pack(fill="x", pady=(0, PAD_MD))

        ctk.CTkLabel(
            type_card, text="Scan Type",
            font=FONT_SUBTITLE, text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=PAD_LG, pady=(PAD_LG, PAD_SM))

        type_row = ctk.CTkFrame(type_card, fg_color="transparent")
        type_row.pack(fill="x", padx=PAD_LG, pady=(0, PAD_SM))

        self._scan_type = ctk.StringVar(value="full")
        type_descs = {
            "quick":  ("⚡ Quick", "Nmap + Nuclei only — fast overview."),
            "full":   ("🔥 Full",  "All tools — comprehensive assessment."),
            "custom": ("⚙  Custom", "Hand-pick which scanners to run."),
        }
        self._type_buttons: dict[str, ctk.CTkButton] = {}
        for key, (label, _) in type_descs.items():
            btn = ctk.CTkButton(
                type_row, text=label,
                fg_color=ACCENT_PURPLE if key == "full" else "transparent",
                border_width=1, border_color=BORDER if key != "full" else ACCENT_PURPLE,
                hover_color="#6d28d9" if key == "full" else BG_TERTIARY,
                text_color=TEXT_PRIMARY, font=FONT_BODY,
                height=38, corner_radius=8,
                command=lambda k=key: self._set_type(k),
            )
            btn.pack(side="left", padx=(0, PAD_SM))
            self._type_buttons[key] = btn

        # Type description label
        self._type_desc = ctk.CTkLabel(
            type_card, text=type_descs["full"][1],
            font=FONT_SMALL, text_color=TEXT_MUTED,
        )
        self._type_desc.pack(anchor="w", padx=PAD_LG, pady=(0, PAD_MD))

        # ── Custom Scanner Checkboxes ─────────────────────────────────
        self._custom_card = ctk.CTkFrame(self, **CTK_FRAME)
        self._custom_card.pack(fill="x", pady=(0, PAD_MD))
        self._custom_card.pack_forget()  # Hidden unless "Custom" selected

        ctk.CTkLabel(
            self._custom_card, text="Select Scanners",
            font=FONT_SUBTITLE, text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=PAD_LG, pady=(PAD_LG, PAD_SM))

        cb_row = ctk.CTkFrame(self._custom_card, fg_color="transparent")
        cb_row.pack(fill="x", padx=PAD_LG, pady=(0, PAD_LG))

        self._scanner_vars: dict[str, ctk.BooleanVar] = {}
        for scanner in ["nmap", "nuclei", "nikto", "zap"]:
            var = ctk.BooleanVar(value=True)
            self._scanner_vars[scanner] = var
            cb = ctk.CTkCheckBox(
                cb_row, text=scanner.upper(),
                variable=var,
                font=FONT_BODY, text_color=TEXT_SECONDARY,
                fg_color=ACCENT_PURPLE, hover_color="#6d28d9",
                border_color=BORDER,
            )
            cb.pack(side="left", padx=(0, PAD_LG))

        # ── Progress Section ─────────────────────────────────────────
        prog_card = ctk.CTkFrame(self, **CTK_FRAME)
        prog_card.pack(fill="x", pady=(0, PAD_MD))

        prog_header = ctk.CTkFrame(prog_card, fg_color="transparent")
        prog_header.pack(fill="x", padx=PAD_LG, pady=(PAD_LG, PAD_SM))

        ctk.CTkLabel(
            prog_header, text="Progress",
            font=FONT_SUBTITLE, text_color=TEXT_PRIMARY,
        ).pack(side="left")

        self._pct_label = ctk.CTkLabel(
            prog_header, text="0%",
            font=FONT_SMALL, text_color=TEXT_MUTED,
        )
        self._pct_label.pack(side="right")

        self._progress_bar = ctk.CTkProgressBar(
            prog_card,
            fg_color=BG_TERTIARY,
            progress_color=ACCENT_PURPLE,
            corner_radius=4,
            height=8,
        )
        self._progress_bar.set(0)
        self._progress_bar.pack(fill="x", padx=PAD_LG, pady=(0, PAD_SM))

        self._status_label = ctk.CTkLabel(
            prog_card, text="Ready to scan.",
            font=FONT_SMALL, text_color=TEXT_MUTED,
        )
        self._status_label.pack(anchor="w", padx=PAD_LG, pady=(0, PAD_LG))

        # ── Action Buttons ───────────────────────────────────────────
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", pady=PAD_MD)

        self._start_btn = ctk.CTkButton(
            btn_row, text="▶  Start Scan",
            command=self._handle_start,
            **CTK_BUTTON,
        )
        self._start_btn.pack(side="left")

        self._cancel_btn = ctk.CTkButton(
            btn_row, text="■  Cancel",
            command=self._handle_cancel,
            **CTK_BUTTON_OUTLINE,
            state="disabled",
        )
        self._cancel_btn.pack(side="left", padx=PAD_SM)

    # ------------------------------------------------------------------
    # Type selection
    # ------------------------------------------------------------------
    _TYPE_DESCS = {
        "quick":  "Nmap + Nuclei only — fastest, suitable for initial recon.",
        "full":   "All enabled tools — comprehensive vulnerability assessment.",
        "custom": "Manually select which scanners to include.",
    }

    def _set_type(self, key: str) -> None:
        self._scan_type.set(key)
        for k, btn in self._type_buttons.items():
            active = k == key
            btn.configure(
                fg_color=ACCENT_PURPLE if active else "transparent",
                border_color=ACCENT_PURPLE if active else BORDER,
                hover_color="#6d28d9" if active else BG_TERTIARY,
            )
        self._type_desc.configure(text=self._TYPE_DESCS.get(key, ""))
        if key == "custom":
            self._custom_card.pack(fill="x", pady=(0, PAD_MD), before=self._start_btn.master)
        else:
            self._custom_card.pack_forget()

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------
    def _handle_start(self) -> None:
        target = self._target_entry.get().strip()
        if not target:
            self._status_label.configure(
                text="⚠  Please enter a target before scanning.", text_color=ACCENT_YELLOW
            )
            return

        scan_type = self._scan_type.get()
        custom = (
            [k for k, v in self._scanner_vars.items() if v.get()]
            if scan_type == "custom" else []
        )

        self._start_btn.configure(state="disabled", text="Scanning…")
        self._cancel_btn.configure(state="normal")
        self._progress_bar.set(0)
        self._progress_bar.configure(progress_color=ACCENT_PURPLE)
        self._status_label.configure(text="Initialising scan…", text_color=TEXT_SECONDARY)
        self._scanning = True

        self._on_scan_start(target, scan_type, custom)

    def _handle_cancel(self) -> None:
        self._on_scan_cancel()
        self.scan_finished(success=False)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def update_progress(self, message: str, percent: int) -> None:
        """Called from the orchestrator thread via after()."""
        def _update():
            self._progress_bar.set(min(percent, 100) / 100)
            self._pct_label.configure(text=f"{min(percent, 100)}%")
            self._status_label.configure(text=message[:120], text_color=TEXT_SECONDARY)
        self.after(0, _update)

    def scan_finished(self, success: bool = True) -> None:
        """Reset UI after a scan completes or is cancelled."""
        def _reset():
            self._scanning = False
            self._start_btn.configure(state="normal", text="▶  Start Scan")
            self._cancel_btn.configure(state="disabled")
            if success:
                self._progress_bar.set(1.0)
                self._progress_bar.configure(progress_color=ACCENT_GREEN)
                self._status_label.configure(
                    text="✔  Scan complete. Reports saved.",
                    text_color=ACCENT_GREEN,
                )
            else:
                self._progress_bar.set(0)
                self._status_label.configure(
                    text="Scan cancelled or failed.", text_color=ACCENT_RED
                )
        self.after(0, _reset)
