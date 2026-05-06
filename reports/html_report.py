"""
VulneraX — HTML Report Generator
===================================
Produces a professional, self-contained HTML report with:
  - Executive summary
  - Severity distribution chart (pure CSS/SVG — no external deps)
  - Full vulnerability table with expandable details
  - Remediation steps per finding
  - Dark cyberpunk theme
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import List

from utils.logger import get_logger
from utils.schema import (
    SEVERITY_COLOR,
    ScanResult,
    Vulnerability,
)

log = get_logger("vulnerax.report.html")


class HTMLReporter:
    """Generates a self-contained HTML report (no external CDN required)."""

    def generate(self, result: ScanResult, output_path: str) -> str:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        summary = getattr(result, "executive_summary", "")
        html_content = _build_html(result, summary)

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)

        log.info("HTML report written to %s", path)
        return str(path.resolve())


# ──────────────────────────────────────────────────────────────────────────────
# HTML builder
# ──────────────────────────────────────────────────────────────────────────────

def _sev_badge(sev: str) -> str:
    color = SEVERITY_COLOR.get(sev, "#8A8A8A")
    return (
        f'<span style="background:{color};color:#0d0d0d;padding:2px 10px;'
        f'border-radius:4px;font-size:0.75rem;font-weight:700;'
        f'text-transform:uppercase;letter-spacing:.5px">{html.escape(sev)}</span>'
    )


def _vuln_row(v: Vulnerability, idx: int) -> str:
    detail_id = f"detail-{idx}"
    cve = html.escape(v.cve or "—")
    confirmed = ", ".join(v.confirmed_by) if v.confirmed_by else "—"
    boost_badge = (
        ' <span style="background:#00ff9d22;color:#00ff9d;border:1px solid #00ff9d;'
        'padding:1px 6px;border-radius:3px;font-size:0.68rem">⚡ CONFIRMED</span>'
        if v.boosted else ""
    )

    row = f"""
    <tr class="vuln-row" onclick="toggleDetail('{detail_id}')">
      <td>{idx}</td>
      <td>{html.escape(v.name[:70])}{boost_badge}</td>
      <td>{_sev_badge(v.severity)}</td>
      <td>{v.cvss_score:.1f}</td>
      <td>{html.escape(v.source.upper())}</td>
      <td>{cve}</td>
      <td>{html.escape(v.url[:60])}</td>
      <td>{v.port or '—'}</td>
    </tr>
    <tr id="{detail_id}" class="detail-row" style="display:none">
      <td colspan="8">
        <div class="detail-box">
          <h4>Description</h4>
          <p>{html.escape(v.description)}</p>
          <h4>Remediation</h4>
          <p class="remediation">{html.escape(v.remediation)}</p>
          <table class="meta-table">
            <tr><th>Confirmed by</th><td>{html.escape(confirmed)}</td></tr>
            <tr><th>References</th><td>{"<br>".join(html.escape(r) for r in v.references[:5]) or "—"}</td></tr>
            <tr><th>Tags</th><td>{html.escape(", ".join(v.tags) or "—")}</td></tr>
            <tr><th>Finding ID</th><td><code>{html.escape(v.vuln_id)}</code></td></tr>
          </table>
        </div>
      </td>
    </tr>"""
    return row


def _severity_bar(by_sev: dict) -> str:
    total = sum(by_sev.values()) or 1
    bars = ""
    for sev, color in SEVERITY_COLOR.items():
        count = by_sev.get(sev, 0)
        pct = count / total * 100
        if pct > 0:
            bars += (
                f'<div style="width:{pct:.1f}%;background:{color};height:100%;'
                f'display:inline-block;transition:width .4s" title="{sev}: {count}"></div>'
            )
    return bars


def _build_html(result: ScanResult, summary: str) -> str:
    rows = "\n".join(_vuln_row(v, i + 1) for i, v in enumerate(result.sorted_vulnerabilities))
    by_sev = result.by_severity
    bar_html = _severity_bar(by_sev)

    stat_cards = ""
    for sev, color in SEVERITY_COLOR.items():
        count = by_sev.get(sev, 0)
        stat_cards += f"""
        <div class="stat-card" style="border-top:3px solid {color}">
          <div class="stat-num" style="color:{color}">{count}</div>
          <div class="stat-label">{sev.upper()}</div>
        </div>"""

    summary_html = summary.replace("\n", "<br>").replace("**", "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulneraX Report — {html.escape(result.target)}</title>
<style>
  :root {{
    --bg: #0d0f14; --surface: #151820; --surface2: #1c2030;
    --border: #2a2f40; --accent: #7c3aed; --accent2: #00ff9d;
    --text: #e2e8f0; --muted: #64748b; --font: "Segoe UI", system-ui, sans-serif;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); line-height: 1.6; }}
  .header {{
    background: linear-gradient(135deg, #0d0f14 0%, #1a0a2e 50%, #0d1117 100%);
    border-bottom: 1px solid var(--border); padding: 2.5rem 3rem; position: relative; overflow: hidden;
  }}
  .header::before {{
    content: ""; position: absolute; top: -60px; right: -60px;
    width: 300px; height: 300px; background: radial-gradient(circle, #7c3aed22 0%, transparent 70%);
    border-radius: 50%; pointer-events: none;
  }}
  .header h1 {{ font-size: 2.2rem; font-weight: 800; letter-spacing: -0.5px;
    background: linear-gradient(135deg, #c4b5fd, #7c3aed, #00ff9d);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
  .header .meta {{ color: var(--muted); margin-top: .4rem; font-size: .9rem; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem 2.5rem; }}
  .section {{ margin-bottom: 2.5rem; }}
  .section-title {{
    font-size: 1.1rem; font-weight: 700; letter-spacing: .5px; text-transform: uppercase;
    color: var(--accent2); margin-bottom: 1rem; padding-bottom: .5rem;
    border-bottom: 1px solid var(--border);
  }}
  /* Stat cards */
  .stats-grid {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
  .stat-card {{
    background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
    padding: 1.2rem 1.5rem; flex: 1; min-width: 120px; text-align: center;
  }}
  .stat-num {{ font-size: 2rem; font-weight: 800; }}
  .stat-label {{ font-size: .7rem; text-transform: uppercase; letter-spacing: .8px; color: var(--muted); margin-top: .2rem; }}
  /* Progress bar */
  .sev-bar-wrap {{ height: 10px; background: var(--surface2); border-radius: 6px; overflow: hidden; }}
  /* Executive summary */
  .summary-box {{
    background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
    padding: 1.5rem; font-size: .95rem; color: #cbd5e1; line-height: 1.8;
  }}
  /* Table */
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    background: var(--surface2); text-align: left; padding: .8rem 1rem;
    font-size: .75rem; text-transform: uppercase; letter-spacing: .6px;
    color: var(--muted); font-weight: 600; border-bottom: 2px solid var(--border);
  }}
  td {{ padding: .75rem 1rem; border-bottom: 1px solid var(--border); font-size: .88rem; }}
  .vuln-row {{ cursor: pointer; transition: background .15s; }}
  .vuln-row:hover {{ background: var(--surface2); }}
  .detail-box {{
    background: var(--surface2); border-radius: 8px; padding: 1.5rem;
    margin: .5rem 0; border-left: 3px solid var(--accent);
  }}
  .detail-box h4 {{ color: var(--accent2); font-size: .8rem; text-transform: uppercase;
    letter-spacing: .6px; margin-bottom: .5rem; margin-top: 1rem; }}
  .detail-box h4:first-child {{ margin-top: 0; }}
  .detail-box p {{ color: #94a3b8; font-size: .9rem; }}
  .remediation {{ color: #86efac !important; }}
  .meta-table td, .meta-table th {{ padding: .3rem .6rem; font-size: .82rem; border: none; }}
  .meta-table th {{ color: var(--muted); background: transparent; text-transform: none; }}
  code {{ background: #1e293b; color: #7c3aed; padding: 1px 5px; border-radius: 3px; font-size: .8rem; }}
  .table-wrap {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }}
  .footer {{ text-align: center; color: var(--muted); font-size: .8rem; padding: 2rem; border-top: 1px solid var(--border); margin-top: 3rem; }}
  @media (max-width: 768px) {{ .container {{ padding: 1rem; }} .stats-grid {{ gap: .5rem; }} }}
</style>
</head>
<body>

<div class="header">
  <h1>⚡ VulneraX Security Report</h1>
  <div class="meta">
    Target: <strong>{html.escape(result.target)}</strong> &nbsp;|&nbsp;
    Scan ID: <code style="-webkit-text-fill-color:#7c3aed">{result.scan_id[:8]}</code> &nbsp;|&nbsp;
    Scan Type: {result.scan_type.upper()} &nbsp;|&nbsp;
    Started: {result.started_at or "—"} &nbsp;|&nbsp;
    Completed: {result.completed_at or "—"}
  </div>
</div>

<div class="container">

  <div class="section">
    <div class="section-title">Severity Distribution</div>
    <div class="stats-grid">
      {stat_cards}
      <div class="stat-card" style="border-top:3px solid #7c3aed">
        <div class="stat-num" style="color:#7c3aed">{result.total}</div>
        <div class="stat-label">Total</div>
      </div>
    </div>
    <div class="sev-bar-wrap">{bar_html}</div>
  </div>

  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="summary-box">{summary_html or "No summary available."}</div>
  </div>

  <div class="section">
    <div class="section-title">Vulnerability Findings ({result.total})</div>
    <div style="margin-bottom:.8rem;font-size:.85rem;color:var(--muted)">
      Click any row to expand details. ⚡ CONFIRMED = detected by multiple tools.
    </div>
    <div class="table-wrap">
      <table id="vuln-table">
        <thead>
          <tr>
            <th>#</th><th>Name</th><th>Severity</th><th>CVSS</th>
            <th>Source</th><th>CVE</th><th>URL</th><th>Port</th>
          </tr>
        </thead>
        <tbody>
          {rows if rows else '<tr><td colspan="8" style="text-align:center;color:#64748b;padding:2rem">No vulnerabilities found.</td></tr>'}
        </tbody>
      </table>
    </div>
  </div>

  {"" if not result.errors else f'<div class="section"><div class="section-title">Scan Errors</div><div class="summary-box" style="border-color:#ff336633"><ul>' + "".join(f"<li>{html.escape(e)}</li>" for e in result.errors) + "</ul></div></div>"}

</div>

<div class="footer">
  Generated by <strong>VulneraX</strong> — Intelligent Automated Vulnerability Assessment Framework<br>
  <span style="color:#4a5568">For authorised penetration testing use only.</span>
</div>

<script>
  function toggleDetail(id) {{
    const el = document.getElementById(id);
    el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
  }}
</script>
</body>
</html>"""
