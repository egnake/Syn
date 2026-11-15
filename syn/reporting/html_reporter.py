"""
SYN - HTML Reporting Module
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from syn.core.config import RISK_CRITICAL, RISK_HIGH, RISK_LOW, RISK_MEDIUM, RISK_NONE
from syn.core.sanitizer import escape_html
from .base_reporter import BaseReporter


class HTMLReporter(BaseReporter):
    """Exports scan results to a self-contained, XSS-safe dark-theme HTML report."""

    def generate(
        self,
        results: List[Dict[str, Any]],
        cve_engine: Any,
        filename: Optional[str] = None,
    ) -> str:
        out_path = self.resolve_output_path(filename, "syn_report.html")
        rows, skipped_open_filtered, error_count = self.partition_display_rows(results, cve_engine)

        rows_html = ""
        targets = set()
        open_ports = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        for res, risk_analysis in rows:
            ip = str(res.get("target_ip", "127.0.0.1"))
            targets.add(ip)
            open_ports += 1

            port = res.get("port", "N/A")
            state = str(res.get("status", "Unknown"))
            banner = str(res.get("banner", "-") or "-")
            os_guess = self.normalize_os(res)
            decision = risk_analysis["decision"]

            if decision == RISK_CRITICAL:
                critical_count += 1
                risk_class = "critical"
            elif decision == RISK_HIGH:
                high_count += 1
                risk_class = "high"
            elif decision == RISK_MEDIUM:
                medium_count += 1
                risk_class = "medium"
            elif decision == RISK_LOW:
                low_count += 1
                risk_class = "low"
            else:
                risk_class = "safe"

            warning_text = risk_analysis.get("Warning", "")
            action_text = risk_analysis.get("Action", "")
            if decision != RISK_NONE:
                details = (
                    f"<strong>Warning:</strong> {escape_html(warning_text)}<br>"
                    f"<strong>Action:</strong> {escape_html(action_text)}"
                )
            else:
                details = "No immediate action required."

            web = self.summarize_web_info(res.get("web_info"))
            if web:
                missing_str = (
                    ", ".join(web["missing_headers"]) if web["missing_headers"] else "None"
                )
                details += (
                    f"<br><strong>Web ({escape_html(web['scheme'].upper())}):</strong> "
                    f"Title={escape_html(web['title'], max_len=40)} | "
                    f"WAF={escape_html(web['waf'])} | "
                    f"robots.txt={'Yes' if web['has_robots'] else 'No'} | "
                    f"Missing Headers={escape_html(missing_str)}"
                )

            rows_html += f"""
            <tr>
                <td>{escape_html(ip)}</td>
                <td>{escape_html(port)}</td>
                <td>{escape_html(state)}</td>
                <td class="banner-cell">{escape_html(banner, max_len=60)}</td>
                <td>{escape_html(os_guess)}</td>
                <td class="risk-{risk_class}">{escape_html(decision)}</td>
                <td class="details-cell">{details}</td>
            </tr>"""

        notes_html = ""
        if skipped_open_filtered > 0 or error_count > 0:
            notes_html = (
                f'<div class="notice">Suppressed {skipped_open_filtered} OPEN | FILTERED ports '
                f'and encountered {error_count} probe errors.</div>'
            )

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SYN - Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a1a; color: #cdd6f4; padding: 30px; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .header h1 {{ color: #89b4fa; font-size: 2em; letter-spacing: 2px; }}
        .header p {{ color: #6c7086; margin-top: 5px; }}
        .stats {{ display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap; }}
        .stat-card {{ background: #181825; border: 1px solid #313244; border-radius: 10px; padding: 18px 24px; flex: 1; min-width: 140px; }}
        .stat-card .label {{ color: #6c7086; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }}
        .stat-card .value {{ font-size: 1.8em; font-weight: bold; margin-top: 4px; }}
        .stat-card .value.critical {{ color: #f38ba8; }}
        .stat-card .value.high {{ color: #fab387; }}
        .stat-card .value.medium {{ color: #f9e2af; }}
        .stat-card .value.low {{ color: #94e2d5; }}
        .stat-card .value.open {{ color: #89b4fa; }}
        .notice {{ background: #1e1e2e; border-left: 4px solid #f9e2af; padding: 10px 14px; margin-bottom: 20px; color: #f9e2af; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; background: #11111b; border-radius: 10px; overflow: hidden; }}
        th {{ background: #1e1e2e; color: #cba6f7; padding: 14px 12px; text-align: left; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }}
        td {{ padding: 12px; border-bottom: 1px solid #1e1e2e; font-size: 0.9em; vertical-align: top; }}
        tr:hover {{ background: #1e1e2e; }}
        .risk-critical {{ color: #f38ba8; font-weight: bold; }}
        .risk-high {{ color: #fab387; font-weight: bold; }}
        .risk-medium {{ color: #f9e2af; }}
        .risk-low {{ color: #94e2d5; }}
        .risk-safe {{ color: #a6e3a1; }}
        .banner-cell {{ font-family: monospace; font-size: 0.8em; max-width: 250px; word-break: break-all; }}
        .details-cell {{ font-size: 0.8em; max-width: 360px; color: #a6adc8; }}
        .footer {{ text-align: center; margin-top: 40px; color: #45475a; font-size: 0.8em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SYN SCAN REPORT</h1>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>

    <div class="stats">
        <div class="stat-card"><div class="label">Targets</div><div class="value">{len(targets)}</div></div>
        <div class="stat-card"><div class="label">Exposed Ports</div><div class="value open">{open_ports}</div></div>
        <div class="stat-card"><div class="label">Critical</div><div class="value critical">{critical_count}</div></div>
        <div class="stat-card"><div class="label">High</div><div class="value high">{high_count}</div></div>
        <div class="stat-card"><div class="label">Medium</div><div class="value medium">{medium_count}</div></div>
        <div class="stat-card"><div class="label">Low</div><div class="value low">{low_count}</div></div>
    </div>

    {notes_html}

    <table>
        <thead>
            <tr>
                <th>Target IP</th>
                <th>Port</th>
                <th>State</th>
                <th>Service / Banner</th>
                <th>OS Guess</th>
                <th>Risk Level</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>

    <div class="footer">
        Generated by SYN AI-Powered Pentest Framework &mdash; github.com/egnake/syn
    </div>
</body>
</html>"""

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_doc)
        return out_path

    @staticmethod
    def _escape(text: str) -> str:
        """Backward-compatible wrapper delegating to strict html.escape."""
        return escape_html(text)
