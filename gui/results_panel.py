"""
VulneraX — Results Panel
==========================
Sortable, filterable vulnerability table with click-to-expand detail view.
"""

from __future__ import annotations

import tkinter as tk
import tkinter.ttk as ttk
from typing import List, Optional

import customtkinter as ctk

from gui.styles import (
    ACCENT_CYAN, ACCENT_GREEN, ACCENT_ORANGE, ACCENT_PURPLE,
    ACCENT_RED, ACCENT_YELLOW, BG_PRIMARY, BG_SECONDARY,
    BG_TERTIARY, BORDER, CTK_FRAME, FONT_BODY, FONT_MONO_SM,
    FONT_SMALL, FONT_SUBTITLE, FONT_TITLE, PAD_LG, PAD_MD, PAD_SM,
    SEVERITY_COLORS, TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
)
from utils.schema import ScanResult, Vulnerability

_COLUMNS = ("severity", "cvss", "name", "source", "url", "port", "cve", "confirmed")
_COL_LABELS = {
    "severity":  "Severity",
    "cvss":      "CVSS",
    "name":      "Finding",
    "source":    "Source",
    "url":       "URL / Host",
    "port":      "Port",
    "cve":       "CVE",
    "confirmed": "Confirmed By",
}
_COL_WIDTH = {
    "severity": 90, "cvss": 65, "name": 280, "source": 90,
    "url": 220, "port": 65, "cve": 130, "confirmed": 130,
}


class ResultsPanel(ctk.CTkFrame):
    """Filterable vulnerability table with expandable detail drawer."""

    def __init__(self, parent, **kwargs) -> None:
        super().__init__(parent, fg_color="transparent", **kwargs)
        self._all_vulns: List[Vulnerability] = []
        self._selected: Optional[Vulnerability] = None
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        # Title
        header_row = ctk.CTkFrame(self, fg_color="transparent")
        header_row.pack(fill="x", pady=(PAD_MD, PAD_LG))

        ctk.CTkLabel(
            header_row, text="📋  Findings",
            font=FONT_TITLE, text_color=TEXT_PRIMARY,
        ).pack(side="left")

        self._count_label = ctk.CTkLabel(
            header_row, text="0 findings",
            font=FONT_SMALL, text_color=TEXT_MUTED,
        )
        self._count_label.pack(side="right", padx=PAD_MD)

        # Filter row
        filter_card = ctk.CTkFrame(self, **CTK_FRAME)
        filter_card.pack(fill="x", pady=(0, PAD_MD))

        filter_inner = ctk.CTkFrame(filter_card, fg_color="transparent")
        filter_inner.pack(fill="x", padx=PAD_LG, pady=PAD_MD)

        # Severity filter
        ctk.CTkLabel(filter_inner, text="Filter:", font=FONT_SMALL,
                     text_color=TEXT_MUTED).pack(side="left", padx=(0, PAD_SM))

        self._sev_filter = ctk.StringVar(value="all")
        for sev, color in [("all", ACCENT_PURPLE), ("critical", ACCENT_RED),
                            ("high", ACCENT_ORANGE), ("medium", ACCENT_YELLOW),
                            ("low", ACCENT_CYAN)]:
            btn = ctk.CTkButton(
                filter_inner,
                text=sev.upper(), width=80, height=30,
                fg_color="transparent", border_width=1, border_color=BORDER,
                text_color=color, font=("Segoe UI", 10, "bold"),
                hover_color=BG_TERTIARY, corner_radius=6,
                command=lambda s=sev: self._apply_filter(s),
            )
            btn.pack(side="left", padx=(0, PAD_SM))

        # Search
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._apply_filter(self._sev_filter.get()))
        search_entry = ctk.CTkEntry(
            filter_inner,
            placeholder_text="Search findings…",
            textvariable=self._search_var,
            fg_color=BG_TERTIARY, border_color=BORDER,
            text_color=TEXT_PRIMARY, placeholder_text_color=TEXT_MUTED,
            height=30, width=200, corner_radius=6, font=FONT_SMALL,
        )
        search_entry.pack(side="right")

        # Treeview frame
        tree_frame = ctk.CTkFrame(self, **CTK_FRAME)
        tree_frame.pack(fill="both", expand=True, pady=(0, PAD_MD))

        # Style Treeview
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("VX.Treeview",
                         background=BG_SECONDARY,
                         foreground=TEXT_SECONDARY,
                         rowheight=32,
                         fieldbackground=BG_SECONDARY,
                         borderwidth=0,
                         font=("Segoe UI", 11))
        style.configure("VX.Treeview.Heading",
                         background=BG_TERTIARY,
                         foreground=TEXT_MUTED,
                         font=("Segoe UI", 10, "bold"),
                         borderwidth=0)
        style.map("VX.Treeview",
                   background=[("selected", "#2a2f40")],
                   foreground=[("selected", TEXT_PRIMARY)])

        self._tree = ttk.Treeview(
            tree_frame, columns=_COLUMNS, show="headings",
            style="VX.Treeview", selectmode="browse",
        )
        for col in _COLUMNS:
            self._tree.heading(col, text=_COL_LABELS[col],
                               command=lambda c=col: self._sort_by(c))
            self._tree.column(col, width=_COL_WIDTH[col], minwidth=50, stretch=False)
        self._tree.column("name", stretch=True)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew", padx=(PAD_MD, 0), pady=PAD_MD)
        vsb.grid(row=0, column=1, sticky="ns", padx=(0, PAD_MD), pady=PAD_MD)
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # Severity colour tags
        for sev, color in SEVERITY_COLORS.items():
            self._tree.tag_configure(sev, foreground=color)

        # ── Detail Drawer ─────────────────────────────────────────────
        self._detail_frame = ctk.CTkFrame(self, **CTK_FRAME)
        self._detail_frame.pack(fill="x")

        ctk.CTkLabel(
            self._detail_frame, text="Finding Detail",
            font=FONT_SUBTITLE, text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=PAD_LG, pady=(PAD_MD, PAD_SM))

        self._detail_text = ctk.CTkTextbox(
            self._detail_frame,
            font=FONT_MONO_SM,
            fg_color=BG_TERTIARY,
            text_color=TEXT_SECONDARY,
            border_width=0,
            height=180,
            wrap="word",
        )
        self._detail_text.pack(fill="x", padx=PAD_LG, pady=(0, PAD_LG))
        self._detail_text.configure(state="disabled")
        self._show_empty_detail()

    # ------------------------------------------------------------------
    def load_results(self, result: ScanResult) -> None:
        """Populate the table from a completed ScanResult."""
        self._all_vulns = result.sorted_vulnerabilities
        self._populate(self._all_vulns)

    def _populate(self, vulns: List[Vulnerability]) -> None:
        for item in self._tree.get_children():
            self._tree.delete(item)

        for v in vulns:
            confirmed = ", ".join(v.confirmed_by) if v.confirmed_by else "—"
            boost = "⚡ " if v.boosted else ""
            self._tree.insert(
                "", "end",
                iid=v.vuln_id,
                values=(
                    v.severity.upper(),
                    f"{v.cvss_score:.1f}",
                    boost + v.name[:70],
                    v.source.upper(),
                    v.url[:50] if v.url else "—",
                    str(v.port) if v.port else "—",
                    v.cve or "—",
                    confirmed,
                ),
                tags=(v.severity,),
            )

        self._count_label.configure(text=f"{len(vulns)} finding(s)")

    def _apply_filter(self, severity: str) -> None:
        self._sev_filter.set(severity)
        query = self._search_var.get().lower().strip()
        filtered = [
            v for v in self._all_vulns
            if (severity == "all" or v.severity == severity)
            and (not query or query in v.name.lower() or query in v.description.lower())
        ]
        self._populate(filtered)

    def _sort_by(self, col: str) -> None:
        data = [(self._tree.set(item, col), item) for item in self._tree.get_children("")]
        try:
            data.sort(key=lambda t: float(t[0]), reverse=True)
        except ValueError:
            data.sort(key=lambda t: t[0])
        for idx, (_, item) in enumerate(data):
            self._tree.move(item, "", idx)

    def _on_select(self, _event) -> None:
        selected = self._tree.selection()
        if not selected:
            return
        vuln_id = selected[0]
        vuln = next((v for v in self._all_vulns if v.vuln_id == vuln_id), None)
        if vuln:
            self._show_detail(vuln)

    # ------------------------------------------------------------------
    def _show_detail(self, v: Vulnerability) -> None:
        text = (
            f"NAME        {v.name}\n"
            f"SEVERITY    {v.severity.upper()}  |  CVSS: {v.cvss_score:.1f}\n"
            f"SOURCE      {v.source.upper()}"
            + (f"  (confirmed by: {', '.join(v.confirmed_by)})" if v.confirmed_by else "") + "\n"
            f"URL         {v.url or '—'}\n"
            f"PORT        {v.port or '—'}   PROTOCOL: {v.protocol or '—'}\n"
            f"CVE         {v.cve or '—'}\n"
            f"TAGS        {', '.join(v.tags) or '—'}\n"
            f"\nDESCRIPTION\n{v.description or '—'}\n"
            f"\nREMEDIATION\n{v.remediation or '—'}\n"
        )
        if v.references:
            text += f"\nREFERENCES\n" + "\n".join(f"  • {r}" for r in v.references[:5])

        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.insert("1.0", text)
        self._detail_text.configure(state="disabled")

    def _show_empty_detail(self) -> None:
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.insert("1.0", "Select a finding to view details.")
        self._detail_text.configure(state="disabled")
