"""Rendering of ScanReport objects into human- and machine-readable formats."""

from __future__ import annotations

import html
import sys
from mtls_scanner.models import CheckStatus, ScanReport, Severity

_SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[1;41;97m",  # white on red, bold
    Severity.HIGH: "\033[1;31m",         # red
    Severity.MEDIUM: "\033[1;33m",       # yellow
    Severity.LOW: "\033[1;36m",          # cyan
    Severity.INFO: "\033[1;34m",         # blue
}
_STATUS_COLOR = {
    CheckStatus.VULNERABLE: "\033[1;31m",
    CheckStatus.SECURE: "\033[1;32m",
    CheckStatus.INCONCLUSIVE: "\033[1;33m",
    CheckStatus.SKIPPED: "\033[2m",
}
_RESET = "\033[0m"


def _supports_color() -> bool:
    return sys.stdout.isatty()


def render_text(report: ScanReport, use_color: bool = None) -> str:
    if use_color is None:
        use_color = _supports_color()

    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if use_color else text

    lines = []
    lines.append("=" * 72)
    lines.append("mTLS Misconfiguration Scan Report")
    lines.append(f"Target : {report.target}:{report.port}")
    lines.append(f"Scanner: v{report.scanner_version}")
    lines.append(f"Duration: {report.duration_seconds}s")
    lines.append("=" * 72)

    if report.errors:
        lines.append("")
        for err in report.errors:
            lines.append(c(_SEVERITY_COLOR[Severity.CRITICAL], f"[ERROR] {err}"))
        lines.append("")
        return "\n".join(lines)

    for r in report.results:
        status_color = _STATUS_COLOR.get(r.status, "")
        sev_color = _SEVERITY_COLOR.get(r.severity, "")
        lines.append("")
        lines.append(f"[{c(status_color, r.status.value):<24}] {r.name}  " + c(sev_color, f"({r.severity.value})"))
        lines.append(f"  check id : {r.check_id}")
        if r.description:
            lines.append(f"  what     : {r.description}")
        if r.detail:
            lines.append(f"  detail   : {r.detail}")
        if r.remediation:
            lines.append(f"  fix      : {r.remediation}")
        if r.duration_ms:
            lines.append(f"  timing   : {r.duration_ms} ms")

    lines.append("")
    lines.append("-" * 72)
    summary = (
        f"Checks: {len(report.results)}  |  "
        f"Vulnerable: {c(_SEVERITY_COLOR[Severity.CRITICAL], str(report.vulnerable_count)) if report.vulnerable_count else '0'}  |  "
        f"Secure: {report.secure_count}  |  "
        f"Inconclusive: {report.inconclusive_count}"
    )
    lines.append(summary)
    if report.is_vulnerable:
        sev = report.highest_severity
        lines.append(c(_SEVERITY_COLOR[sev], f"RESULT: VULNERABLE (highest severity: {sev.value})"))
    else:
        lines.append(c("\033[1;32m", "RESULT: NO MISCONFIGURATIONS DETECTED"))
    lines.append("-" * 72)
    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    return report.to_json()


def render_html(report: ScanReport) -> str:
    def esc(s: str) -> str:
        return html.escape(str(s))

    sev_class = {
        Severity.CRITICAL: "sev-critical",
        Severity.HIGH: "sev-high",
        Severity.MEDIUM: "sev-medium",
        Severity.LOW: "sev-low",
        Severity.INFO: "sev-info",
    }
    status_class = {
        CheckStatus.VULNERABLE: "status-vuln",
        CheckStatus.SECURE: "status-secure",
        CheckStatus.INCONCLUSIVE: "status-inconclusive",
        CheckStatus.SKIPPED: "status-skipped",
    }

    rows = []
    for r in report.results:
        rows.append(f"""
        <tr class="{status_class.get(r.status, '')}">
          <td>{esc(r.name)}</td>
          <td><span class="badge {status_class.get(r.status, '')}">{esc(r.status.value)}</span></td>
          <td><span class="badge {sev_class.get(r.severity, '')}">{esc(r.severity.value)}</span></td>
          <td>{esc(r.description)}</td>
          <td>{esc(r.detail)}</td>
          <td>{esc(r.remediation)}</td>
        </tr>""")

    result_banner = (
        f'<div class="banner banner-bad">VULNERABLE &mdash; highest severity: {esc(report.highest_severity.value)}</div>'
        if report.is_vulnerable
        else '<div class="banner banner-good">NO MISCONFIGURATIONS DETECTED</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>mTLS Scan Report - {esc(report.target)}:{esc(report.port)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; background: #0f1117; color: #e6e6e6; }}
  h1 {{ font-size: 1.4rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ border: 1px solid #2a2d38; padding: 0.6rem 0.8rem; text-align: left; vertical-align: top; font-size: 0.9rem; }}
  th {{ background: #171a24; }}
  tr.status-vuln {{ background: rgba(220, 38, 38, 0.08); }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.78rem; }}
  .status-vuln {{ background:#7f1d1d; color:#fecaca; }}
  .status-secure {{ background:#14532d; color:#bbf7d0; }}
  .status-inconclusive {{ background:#78350f; color:#fde68a; }}
  .status-skipped {{ background:#374151; color:#d1d5db; }}
  .sev-critical {{ background:#7f1d1d; color:#fff; }}
  .sev-high {{ background:#9a3412; color:#fff; }}
  .sev-medium {{ background:#854d0e; color:#fff; }}
  .sev-low {{ background:#155e75; color:#fff; }}
  .sev-info {{ background:#1e3a8a; color:#fff; }}
  .banner {{ padding: 0.8rem 1rem; border-radius: 6px; font-weight: 700; margin: 1rem 0; }}
  .banner-bad {{ background:#7f1d1d; color:#fecaca; }}
  .banner-good {{ background:#14532d; color:#bbf7d0; }}
  .meta {{ color:#9ca3af; font-size:0.85rem; }}
</style>
</head>
<body>
  <h1>mTLS Misconfiguration Scan Report</h1>
  <div class="meta">Target: {esc(report.target)}:{esc(report.port)} &nbsp;|&nbsp; Scanner v{esc(report.scanner_version)} &nbsp;|&nbsp; Duration: {esc(report.duration_seconds)}s</div>
  {result_banner}
  <table>
    <thead><tr><th>Check</th><th>Status</th><th>Severity</th><th>Description</th><th>Detail</th><th>Remediation</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</body>
</html>"""


RENDERERS = {
    "text": render_text,
    "json": render_json,
    "html": render_html,
}
