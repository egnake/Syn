"""
SYN - Console & JSON Reporting Engine
"""

import json
from typing import Any, Dict, List, Optional
from rich.markup import escape as rich_escape
from rich.table import Table
from syn.core.config import (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_NONE,
)
from syn.core.logger import console, logger
from syn.core.sanitizer import sanitize_terminal_text
from syn.vulnerability.cve_engine import CVEEngine
from .base_reporter import BaseReporter


class Reporter(BaseReporter):
    """Formats scan results for Rich console display and strict RFC 8259 JSON export."""

    def __init__(self, cve_engine: Optional[CVEEngine] = None):
        self._cve_engine = cve_engine

    @property
    def cve_engine(self) -> CVEEngine:
        if self._cve_engine is None:
            self._cve_engine = CVEEngine()
        return self._cve_engine

    def generate(
        self,
        results: List[Dict[str, Any]],
        cve_engine: Any = None,
        filename: Optional[str] = None,
    ) -> str:
        engine = cve_engine or self.cve_engine
        if filename:
            return self.export_json(results, filename=filename, cve_engine=engine)
        self.print_console_report(results, cve_engine=engine)
        return "console"

    def print_console_report(
        self, analyzed_results: List[Dict[str, Any]], cve_engine: Any = None
    ) -> None:
        engine = cve_engine or self.cve_engine
        table = Table(
            title="SYN - Advanced Scan & AI Analysis Results",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Target IP", style="dim", no_wrap=True)
        table.add_column("Port", justify="right", style="cyan", no_wrap=True)
        table.add_column("State", style="green")
        table.add_column("Service / Banner", style="yellow")
        table.add_column("AI OS", style="blue")
        table.add_column("Risk / Web Surface", style="red")

        rows, skipped_open_filtered, error_count = self.partition_display_rows(
            analyzed_results, engine
        )

        notable_findings = []
        for res, risk_analysis in rows:
            ip_str = sanitize_terminal_text(res.get("target_ip", "127.0.0.1"))
            port_str = sanitize_terminal_text(res.get("port", "N/A"))
            status = sanitize_terminal_text(res.get("status", "Unknown"))
            banner_display = sanitize_terminal_text(self.format_banner_display(res), max_len=68)
            os_tahmini = sanitize_terminal_text(self.normalize_os(res))
            decision = risk_analysis["decision"]

            if decision == RISK_CRITICAL:
                risk_str = f"[bold red]! {rich_escape(decision)} ![/bold red]"
            elif decision == RISK_HIGH:
                risk_str = f"[red]{rich_escape(decision)}[/red]"
            elif decision == RISK_MEDIUM:
                risk_str = f"[dark_orange]{rich_escape(decision)}[/dark_orange]"
            elif decision == RISK_LOW:
                risk_str = f"[yellow]{rich_escape(decision)}[/yellow]"
            else:
                risk_str = "[green]SAFE[/green]"

            if decision not in (RISK_NONE, RISK_LOW):
                notable_findings.append((res, risk_analysis))

            web = self.summarize_web_info(res.get("web_info"))
            if web:
                title_str = sanitize_terminal_text(web["title"], max_len=24)
                waf_str = sanitize_terminal_text(web["waf"], max_len=20)
                robots_str = f" | {rich_escape('[robots.txt]')}" if web["has_robots"] else ""
                missing = web["missing_headers"]
                hdr_str = (
                    f" | Missing Headers: {len(missing)}" if missing else ""
                )
                tls_str = (
                    f" | TLS: {sanitize_terminal_text(web['tls_summary'])}"
                    if web.get("tls_summary")
                    else ""
                )
                risk_str += (
                    f"\n[dim cyan]{web['scheme'].upper()} | Title: {title_str}"
                    f" | WAF: {waf_str}{tls_str}{robots_str}{hdr_str}[/dim cyan]"
                )

            table.add_row(ip_str, port_str, status, banner_display, os_tahmini, risk_str)

        console.print(table)

        if skipped_open_filtered > 0:
            logger.info(
                f"Suppressed {skipped_open_filtered} 'OPEN | FILTERED' ports "
                "(likely firewall drops or unprivileged stealth probes)."
            )
        if error_count > 0:
            logger.warning(
                f"{error_count} port probes failed with socket/permission errors (marked as ERROR)."
            )

        if notable_findings:
            console.print("\n[bold red]>>> WARNING: CRITICAL RISKS OR VULNERABILITIES DETECTED! <<<[/bold red]")
            for res, risk_analysis in notable_findings:
                port_lbl = sanitize_terminal_text(res.get("port", "N/A"))
                ip_lbl = sanitize_terminal_text(res.get("target_ip", "127.0.0.1"))
                warn_lbl = sanitize_terminal_text(risk_analysis.get("Warning", ""))
                act_lbl = sanitize_terminal_text(risk_analysis.get("Action", ""))
                console.print(f"\n[bold yellow]{ip_lbl}:{port_lbl} Detailed Analysis:[/bold yellow]")
                console.print(f"Warning: {warn_lbl}")
                console.print(f"Action: {act_lbl}")

    def export_json(
        self,
        results: List[Dict[str, Any]],
        filename: Optional[str] = "syn_report.json",
        cve_engine: Any = None,
    ) -> str:
        """Export full results including risk evaluation as strict RFC 8259 JSON."""
        engine = cve_engine or self.cve_engine
        out_path = self.resolve_output_path(filename, "syn_report.json")

        clean_results = []
        for record in results:
            clean_r = self.to_json_safe(record)
            risk_info = engine.evaluate_result(record)
            clean_r["risk_analysis"] = {
                "decision": self.normalize_risk(risk_info.get("decision")),
                "warning": risk_info.get("Warning", ""),
                "action": risk_info.get("Action", ""),
            }
            clean_results.append(clean_r)

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(clean_results, f, ensure_ascii=False, indent=4, allow_nan=False)

        logger.info(f"[REPORT] JSON report saved to: {out_path}")
        return out_path
