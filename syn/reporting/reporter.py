"""
SYN - Raporlama Motoru
"""

import json
import numpy as np
from typing import List, Dict, Any
from syn.core.logger import logger, console
from rich.table import Table
from syn.vulnerability.cve_engine import CVEEngine

class Reporter:
    """Processes scan results, prints to console, or exports in JSON/HTML format."""
    
    def __init__(self):
        self.cve_engine = CVEEngine()

    def print_console_report(self, analyzed_results: List[Dict[str, Any]]):
        """Sonuçları Rich tablosu olarak profesyonelce konsola yazdırır."""
        
        table = Table(title="SYN - Advanced Scan & AI Analysis Results", show_header=True, header_style="bold magenta")
        table.add_column("Target IP", style="dim", no_wrap=True)
        table.add_column("Port", justify="right", style="cyan", no_wrap=True)
        table.add_column("State", style="green")
        table.add_column("Service / Banner", style="yellow")
        table.add_column("AI OS", style="blue")
        table.add_column("Risk / Web Surface", style="red")
        
        kritik_bulundu = False
        open_filtered_count = sum(1 for r in analyzed_results if r.get('status') == 'OPEN | FILTERED')
        
        for res in analyzed_results:
            ip_str = res.get('target_ip', '127.0.0.1')
            port_str = str(res.get('port', 'N/A'))
            status = res.get('status', 'Unknown')

            if status not in ['OPEN', 'OPEN | FILTERED']:
                continue
            
            if status == 'OPEN | FILTERED' and open_filtered_count > 20:
                continue
                
            banner = res.get('banner', '')
            banner_display = banner[:40] + '...' if len(banner) > 40 else banner
            if not banner_display:
                banner_display = "-"
                
            os_tahmini = res.get('ai_os_tahmini', 'Unknown')
            if isinstance(os_tahmini, list) or isinstance(os_tahmini, np.ndarray):
                 os_tahmini = str(os_tahmini[0])
            
            risk_analysis = self.cve_engine.evaluate_result(res)
            decision = risk_analysis['decision']
            
            risk_str = ""
            if decision != 'NO_ACTION':
                kritik_bulundu = True
                if decision == 'CRITICAL RISK' or decision == 'CRITICAL RISK':
                    risk_str = f"[bold red]! {decision} ![/bold red]"
                elif decision == 'HIGH RISK' or decision == 'HIGH RISK':
                    risk_str = f"[red]{decision}[/red]"
                elif decision == 'MEDIUM RISK' or decision == 'MEDIUM RISK':
                    risk_str = f"[dark_orange]{decision}[/dark_orange]"
                else:
                    risk_str = f"[yellow]{decision}[/yellow]"
            else:
                risk_str = "[green]SAFE[/green]"

            # Inject Web Surface info if it exists
            if 'web_info' in res and isinstance(res['web_info'], dict):
                w = res['web_info']
                if w.get('is_web'):
                    waf_str = f" | WAF: {w.get('waf')}"
                    title_str = f" | Title: {str(w.get('title', ''))[:20]}"
                    dirb_str = " | [robots.txt]" if w.get('has_robots') else ""
                    risk_str += f"\n[dim cyan]{title_str}{waf_str}{dirb_str}[/dim cyan]"

            table.add_row(ip_str, port_str, status, banner_display, os_tahmini, risk_str)

        console.print(table)
        
        if open_filtered_count > 20:
            logger.info(f"Not showing {open_filtered_count} 'OPEN | FILTERED' ports (likely firewall drops or stealth scan artifacts).")
        
        if kritik_bulundu:
            console.print("\n[bold red]>>> WARNING: CRITICAL RISKS OR VULNERABILITIES DETECTED! <<<[/bold red]")
            for res in analyzed_results:
                risk_analysis = self.cve_engine.evaluate_result(res)
                if risk_analysis['decision'] not in ['NO_ACTION', 'LOW RISK']:
                    console.print(f"\n[bold yellow]Port {res['port']} Detailed Analysis:[/bold yellow]")
                    console.print(f"Warning: {risk_analysis['Warning']}")
                    console.print(f"Action: {risk_analysis['Action']}")

    def export_json(self, results: List[Dict[str, Any]], filename: str = "umay_report.json"):
        """Exports results as a JSON file."""

        clean_results = []
        for r in results:
            clean_r = r.copy()
            for k, v in clean_r.items():
                if isinstance(v, (np.integer, np.int64)):
                    clean_r[k] = int(v)
                elif isinstance(v, (np.floating, np.float64)):
                    clean_r[k] = float(v)
                elif isinstance(v, np.ndarray):
                    clean_r[k] = v.tolist()
            clean_results.append(clean_r)
            
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(clean_results, f, ensure_ascii=False, indent=4)
        logger.info(f"Report saved to file.")














