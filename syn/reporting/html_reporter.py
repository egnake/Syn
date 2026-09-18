"""
SYN - HTML Raporlama Modülü
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any
import numpy as np


class HTMLReporter:
    """Tarama sonuçlarını şık, dark-theme HTML raporuna dönüştürür."""

    def generate(self, results: List[Dict[str, Any]], cve_engine, filename: str = "syn_report.html"):
        rows_html = ""
        targets = set()
        open_ports = 0
        critical_count = 0
        high_count = 0
        medium_count = 0

        for res in results:
            if res.get('status') not in ['OPEN', 'OPEN | FILTERED']:
                continue

            ip = res.get('target_ip', '127.0.0.1')
            targets.add(ip)
            open_ports += 1

            port = res.get('port', 'N/A')
            state = res.get('status', 'Unknown')
            banner = str(res.get('banner', '-') or '-')
            if len(banner) > 60:
                banner = banner[:57] + '...'

            os_guess = res.get('ai_os_tahmini', 'Unknown')
            if isinstance(os_guess, (list, np.ndarray)):
                os_guess = str(os_guess[0])

            risk_analysis = cve_engine.evaluate_result(res)
            decision = risk_analysis['decision']

            if 'CRITICAL' in decision:
                critical_count += 1
                risk_class = 'critical'
            elif 'HIGH' in decision:
                high_count += 1
                risk_class = 'high'
            elif 'MEDIUM' in decision:
                medium_count += 1
                risk_class = 'medium'
            else:
                risk_class = 'safe'

            warning_text = risk_analysis.get('Warning', '')
            action_text = risk_analysis.get('Action', '')
            details = ""
            if decision != 'NO_ACTION':
                details = f"<strong>Warning:</strong> {self._escape(warning_text)}<br><strong>Action:</strong> {self._escape(action_text)}"
            else:
                details = "No immediate action required."

            rows_html += f"""
            <tr>
                <td>{self._escape(str(ip))}</td>
                <td>{port}</td>
                <td>{state}</td>
                <td class="banner-cell">{self._escape(banner)}</td>
                <td>{self._escape(str(os_guess))}</td>
                <td class="risk-{risk_class}">{decision}</td>
                <td class="details-cell">{details}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
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
        .stat-card {{ background: #181825; border: 1px solid #313244; border-radius: 10px; padding: 18px 24px; flex: 1; min-width: 160px; }}
        .stat-card .label {{ color: #6c7086; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }}
        .stat-card .value {{ font-size: 1.8em; font-weight: bold; margin-top: 4px; }}
        .stat-card .value.critical {{ color: #f38ba8; }}
        .stat-card .value.high {{ color: #fab387; }}
        .stat-card .value.medium {{ color: #f9e2af; }}
        .stat-card .value.open {{ color: #89b4fa; }}
        table {{ width: 100%; border-collapse: collapse; background: #11111b; border-radius: 10px; overflow: hidden; }}
        th {{ background: #1e1e2e; color: #cba6f7; padding: 14px 12px; text-align: left; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }}
        td {{ padding: 12px; border-bottom: 1px solid #1e1e2e; font-size: 0.9em; }}
        tr:hover {{ background: #1e1e2e; }}
        .risk-critical {{ color: #f38ba8; font-weight: bold; }}
        .risk-high {{ color: #fab387; font-weight: bold; }}
        .risk-medium {{ color: #f9e2af; }}
        .risk-safe {{ color: #a6e3a1; }}
        .banner-cell {{ font-family: monospace; font-size: 0.8em; max-width: 250px; word-break: break-all; }}
        .details-cell {{ font-size: 0.8em; max-width: 300px; color: #a6adc8; }}
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
        <div class="stat-card"><div class="label">Open Ports</div><div class="value open">{open_ports}</div></div>
        <div class="stat-card"><div class="label">Critical</div><div class="value critical">{critical_count}</div></div>
        <div class="stat-card"><div class="label">High</div><div class="value high">{high_count}</div></div>
        <div class="stat-card"><div class="label">Medium</div><div class="value medium">{medium_count}</div></div>
    </div>

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
        Generated by SYN AI-Powered Pentest Framework &mdash; github.com/egnakesec/syn
    </div>
</body>
</html>"""

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        return filename

    @staticmethod
    def _escape(text: str) -> str:
        """Basic HTML escaping."""
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
