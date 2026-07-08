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
    """Tarama sonuÃ§larÄ±nÄ± iÅŸleyerek konsola basar veya JSON/HTML formatÄ±nda dÄ±ÅŸa aktarÄ±r."""
    
    def __init__(self):
        self.cve_engine = CVEEngine()

    def print_console_report(self, analyzed_results: List[Dict[str, Any]]):
        """Sonuçları Rich tablosu olarak profesyonelce konsola yazdırır."""
        
        table = Table(title="SYN - GeliÃ…Å¸miÃ…Å¸ Tarama ve YZ Analiz Sonuçları", show_header=True, header_style="bold magenta")
        table.add_column("Port", justify="right", style="cyan", no_wrap=True)
        table.add_column("Durum", style="green")
        table.add_column("Servis / Banner", style="yellow")
        table.add_column("YZ OS Tahmini", style="blue")
        table.add_column("Risk / Aksiyon", style="red")
        
        kritik_bulundu = False
        
        for res in analyzed_results:
            port_str = str(res.get('port', 'N/A'))
            status = res.get('status', 'Bilinmiyor')

            if status not in ['AÇIK', 'AÇIK | FİLTRELİ']:
                continue
                
            banner = res.get('banner', '')
            banner_display = banner[:40] + '...' if len(banner) > 40 else banner
            if not banner_display:
                banner_display = "-"
                
            os_tahmini = res.get('ai_os_tahmini', 'Bilinmiyor')
            if isinstance(os_tahmini, list) or isinstance(os_tahmini, np.ndarray):
                 os_tahmini = str(os_tahmini[0])
            
            risk_analizi = self.cve_engine.evaluate_result(res)
            karar = risk_analizi['karar']
            
            risk_str = ""
            if karar != 'GEREK YOK':
                kritik_bulundu = True
                if karar == 'KRİTİK RİSK' or karar == 'KRİTİK':
                    risk_str = f"[bold red]! {karar} ![/bold red]"
                elif karar == 'YÜKSEK RİSK' or karar == 'YÜKSEK':
                    risk_str = f"[red]{karar}[/red]"
                elif karar == 'ORTA RİSK' or karar == 'ORTA':
                    risk_str = f"[dark_orange]{karar}[/dark_orange]"
                else:
                    risk_str = f"[yellow]{karar}[/yellow]"
            else:
                risk_str = "[green]TEMİZ[/green]"

            table.add_row(port_str, status, banner_display, os_tahmini, risk_str)

        console.print(table)
        
        if kritik_bulundu:
            console.print("\n[bold red]>>> DİKKAT: KRİTİK RİSKLER VEYA ZAFİYETLER TESPİT EDİLDİ! <<<[/bold red]")
            for res in analyzed_results:
                risk_analizi = self.cve_engine.evaluate_result(res)
                if risk_analizi['karar'] not in ['GEREK YOK', 'DÜÃ…ÂÜK RİSK', 'DÜÃ…ÂÜK']:
                    console.print(f"\n[bold yellow]Port {res['port']} Detaylı Analiz:[/bold yellow]")
                    console.print(f"Uyarı: {risk_analizi['uyari']}")
                    console.print(f"Öneri: {risk_analizi['onerisi']}")

    def export_json(self, results: List[Dict[str, Any]], filename: str = "umay_report.json"):
        """Sonuçları JSON dosyası olarak dıÃ…Å¸a aktarır."""

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
        logger.info(f"Rapor {filename} dosyasına kaydedildi.")




