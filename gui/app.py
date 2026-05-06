"""
VulneraX — Main GUI Application
=================================
Root CustomTkinter window with tab-based layout:
  Tab 1 — Dashboard
  Tab 2 — Scan
  Tab 3 — Results
  Tab 4 — Logs

Scans run in daemon threads; all UI updates go through after().
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import List, Optional

import customtkinter as ctk

from gui.dashboard import DashboardPanel
from gui.log_panel import LogPanel
from gui.results_panel import ResultsPanel
from gui.scan_panel import ScanPanel
from gui.styles import (
    ACCENT_GREEN, ACCENT_PURPLE, ACCENT_RED, BG_PRIMARY, BG_SECONDARY,
    BORDER, FONT_BODY, FONT_SMALL, FONT_SUBTITLE, FONT_TITLE,
    PAD_LG, PAD_MD, PAD_SM, TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
)
from utils.dependency_checker import check_all, summarise
from utils.logger import setup_logging


class VulneraXApp(ctk.CTk):
    """Main application window."""

    APP_TITLE   = "VulneraX — Intelligent Vulnerability Assessment Framework"
    MIN_WIDTH   = 1100
    MIN_HEIGHT  = 720

    def __init__(self) -> None:
        super().__init__()
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.title(self.APP_TITLE)
        self.geometry("1280x800")
        self.minsize(self.MIN_WIDTH, self.MIN_HEIGHT)
        self.configure(fg_color=BG_PRIMARY)

        self._scan_result = None
        self._report_paths: dict[str, str] = {}
        self._cancel_event = threading.Event()

        self._build_ui()
        self._setup_logging()
        self._run_dep_check()

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        # ── Side Rail ─────────────────────────────────────────────────
        self._rail = ctk.CTkFrame(self, fg_color=BG_SECONDARY,
                                   corner_radius=0, border_width=0, width=220)
        self._rail.pack(side="left", fill="y")
        self._rail.pack_propagate(False)

        self._build_rail()

        # ── Main Content Area ─────────────────────────────────────────
        content = ctk.CTkFrame(self, fg_color=BG_PRIMARY, corner_radius=0)
        content.pack(side="left", fill="both", expand=True)

        self._tab_view = ctk.CTkTabview(
            content,
            fg_color=BG_PRIMARY,
            segmented_button_fg_color=BG_SECONDARY,
            segmented_button_selected_color=ACCENT_PURPLE,
            segmented_button_selected_hover_color="#6d28d9",
            segmented_button_unselected_color=BG_SECONDARY,
            segmented_button_unselected_hover_color="#1c2030",
            text_color=TEXT_PRIMARY,
            text_color_disabled=TEXT_MUTED,
        )
        self._tab_view.pack(fill="both", expand=True, padx=0, pady=0)

        for tab in ("Dashboard", "Scan", "Results", "Logs"):
            self._tab_view.add(tab)

        # Dashboard
        dash_scroll = ctk.CTkScrollableFrame(
            self._tab_view.tab("Dashboard"),
            fg_color="transparent",
        )
        dash_scroll.pack(fill="both", expand=True, padx=PAD_LG, pady=PAD_MD)
        self._dashboard = DashboardPanel(dash_scroll)
        self._dashboard.pack(fill="both", expand=True)

        # Scan
        scan_scroll = ctk.CTkScrollableFrame(
            self._tab_view.tab("Scan"),
            fg_color="transparent",
        )
        scan_scroll.pack(fill="both", expand=True, padx=PAD_LG, pady=PAD_MD)
        self._scan_panel = ScanPanel(
            scan_scroll,
            on_scan_start=self._start_scan,
            on_scan_cancel=self._cancel_scan,
        )
        self._scan_panel.pack(fill="both", expand=True)

        # Results
        self._results_panel = ResultsPanel(self._tab_view.tab("Results"))
        self._results_panel.pack(fill="both", expand=True, padx=PAD_LG, pady=PAD_MD)

        # Logs
        self._log_panel = LogPanel(self._tab_view.tab("Logs"))
        self._log_panel.pack(fill="both", expand=True, padx=PAD_LG, pady=PAD_MD)

    def _build_rail(self) -> None:
        """Build the left-side navigation rail."""
        # Logo / branding
        brand = ctk.CTkFrame(self._rail, fg_color="transparent")
        brand.pack(fill="x", pady=(PAD_LG * 2, PAD_LG), padx=PAD_LG)

        ctk.CTkLabel(
            brand, text="⚡ VulneraX",
            font=("Segoe UI", 18, "bold"), text_color=TEXT_PRIMARY,
        ).pack(anchor="w")
        ctk.CTkLabel(
            brand, text="v1.0.0  •  Open Source",
            font=FONT_SMALL, text_color=TEXT_MUTED,
        ).pack(anchor="w", pady=(2, 0))

        # Divider
        ctk.CTkFrame(self._rail, height=1, fg_color=BORDER).pack(fill="x", padx=PAD_MD)

        # Quick-nav buttons
        nav_items = [
            ("🏠  Dashboard", "Dashboard"),
            ("🔍  New Scan",  "Scan"),
            ("📋  Results",   "Results"),
            ("📄  Live Logs", "Logs"),
        ]
        for label, tab in nav_items:
            btn = ctk.CTkButton(
                self._rail, text=label, anchor="w",
                fg_color="transparent", hover_color="#1c2030",
                text_color=TEXT_SECONDARY, font=FONT_BODY,
                height=40, corner_radius=8,
                command=lambda t=tab: self._tab_view.set(t),
            )
            btn.pack(fill="x", padx=PAD_MD, pady=2)

        # Divider
        ctk.CTkFrame(self._rail, height=1, fg_color=BORDER).pack(fill="x", padx=PAD_MD, pady=PAD_MD)

        # Report actions
        ctk.CTkLabel(
            self._rail, text="REPORTS",
            font=("Segoe UI", 9, "bold"), text_color=TEXT_MUTED,
        ).pack(anchor="w", padx=PAD_LG, pady=(0, PAD_SM))

        self._open_html_btn = ctk.CTkButton(
            self._rail, text="🌐  Open HTML Report", anchor="w",
            fg_color="transparent", hover_color="#1c2030",
            text_color=TEXT_SECONDARY, font=FONT_SMALL,
            height=36, corner_radius=8, state="disabled",
            command=self._open_html_report,
        )
        self._open_html_btn.pack(fill="x", padx=PAD_MD, pady=2)

        self._open_dir_btn = ctk.CTkButton(
            self._rail, text="📁  Open Report Folder", anchor="w",
            fg_color="transparent", hover_color="#1c2030",
            text_color=TEXT_SECONDARY, font=FONT_SMALL,
            height=36, corner_radius=8, state="disabled",
            command=self._open_report_dir,
        )
        self._open_dir_btn.pack(fill="x", padx=PAD_MD, pady=2)

        # Spacer
        ctk.CTkFrame(self._rail, fg_color="transparent").pack(fill="both", expand=True)

        # Status indicator
        self._rail_status = ctk.CTkLabel(
            self._rail, text="● Idle",
            font=FONT_SMALL, text_color=TEXT_MUTED,
        )
        self._rail_status.pack(pady=PAD_MD)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    def _setup_logging(self) -> None:
        setup_logging(gui_callback=self._log_panel.log_callback)

    # ------------------------------------------------------------------
    # Dependency check
    # ------------------------------------------------------------------
    def _run_dep_check(self) -> None:
        def _check():
            statuses = check_all()
            summary = summarise(statuses)
            for line in summary.split("\n"):
                self._log_panel.append(line, "info")
        threading.Thread(target=_check, daemon=True).start()

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------
    def _start_scan(self, target: str, scan_type: str, custom: List[str]) -> None:
        self._cancel_event.clear()
        self._dashboard.set_scanning()
        self._rail_status.configure(text="● Scanning…", text_color=ACCENT_GREEN)
        self._tab_view.set("Logs")

        def _progress(message: str, percent: int) -> None:
            self._scan_panel.update_progress(message, percent)

        def _worker() -> None:
            from core.orchestrator import Orchestrator
            from reports.report_generator import ReportGenerator

            try:
                orch = Orchestrator(progress_callback=_progress)
                result = orch.run(
                    target=target,
                    scan_type=scan_type,
                    custom_scanners=custom if custom else None,
                )

                if self._cancel_event.is_set():
                    return

                # Generate reports
                paths = ReportGenerator().generate(result)

                self._scan_result = result
                self._report_paths = paths

                self.after(0, self._on_scan_done, result, paths)

            except Exception as exc:  # noqa: BLE001
                self._log_panel.append(f"[!] Fatal error: {exc}", "error")
                self.after(0, self._scan_panel.scan_finished, False)
                self.after(0, lambda: self._rail_status.configure(
                    text="● Error", text_color=ACCENT_RED))

        threading.Thread(target=_worker, daemon=True).start()

    def _cancel_scan(self) -> None:
        self._cancel_event.set()
        self._log_panel.append("[!] Scan cancelled by user.", "warning")
        self._rail_status.configure(text="● Cancelled", text_color=TEXT_MUTED)

    def _on_scan_done(self, result, paths: dict) -> None:
        self._scan_panel.scan_finished(success=True)
        self._dashboard.update_from_result(result)
        self._results_panel.load_results(result)
        self._rail_status.configure(
            text=f"● Done — {result.total} findings", text_color=ACCENT_GREEN
        )
        if paths.get("html"):
            self._open_html_btn.configure(state="normal")
        self._open_dir_btn.configure(state="normal")
        self._tab_view.set("Dashboard")

    # ------------------------------------------------------------------
    # Report actions
    # ------------------------------------------------------------------
    def _open_html_report(self) -> None:
        path = self._report_paths.get("html", "")
        if path and Path(path).exists():
            os.startfile(path)

    def _open_report_dir(self) -> None:
        if self._scan_result:
            from utils.config_loader import load_config
            cfg = load_config()
            out_dir = Path(cfg.get("reports", {}).get("output_dir", "scan_results"))
            target = out_dir / self._scan_result.scan_id
            if target.exists():
                os.startfile(str(target))


def launch() -> None:
    """Entry-point called from main.py."""
    app = VulneraXApp()
    app.mainloop()
