"""
SYN - CLI (Komut Satırı Arayüzü)
"""

import sys
import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)

import argparse
from rich.prompt import Prompt, IntPrompt, Confirm
from syn.core.logger import logger, console
from syn.core.config import QUICK_SCAN_PORTS
from syn.scanner.async_scanner import AsyncScanner
from syn.scanner.stealth_scanner import StealthScanner
from syn.scanner.banner_grabber import BannerGrabber
from syn.ai.model_manager import ModelManager
from syn.ai.analyzer import AIAnalyzer
from syn.reporting.reporter import Reporter
from syn.reporting.html_reporter import HTMLReporter
from syn.reporting.markdown_reporter import MarkdownReporter

from syn.recon.target_parser import TargetParser
from syn.recon.host_discovery import HostDiscovery
from syn.recon.subdomain_enum import SubdomainEnum
from syn.web.http_analyzer import HttpAnalyzer
from syn.scanner.service_identifier import ServiceIdentifier
import asyncio
from syn.banners import get_random_banner

def interactive_wizard():
    art = get_random_banner()
    console.print(f"[bold magenta]{art}[/bold magenta]")
    console.print("[bold cyan]       [ INTERACTIVE SETUP ]       [/bold cyan]\n")

    while True:
        target = Prompt.ask("[bold cyan][?][/bold cyan] Target IP/Hostname", default="127.0.0.1")
        
        console.print("\n[bold yellow]Port Scanning Profiles:[/bold yellow]")
        console.print("  [1] FAST   - Top 10,000 Ports (Includes 9999, 10000, 8443 etc.)")
        console.print("  [2] ALL    - 1-65535 All Ports (Thorough but slow)")
        console.print("  [3] CUSTOM - Specify a custom range (e.g., 50-500)")
        p_choice = Prompt.ask("[bold cyan][?][/bold cyan] Select Port Profile", choices=["1", "2", "3", "FAST", "ALL", "CUSTOM"], default="1")
        
        p_map = {"1": "FAST", "2": "ALL", "3": "CUSTOM", "FAST": "FAST", "ALL": "ALL", "CUSTOM": "CUSTOM"}
        profile = p_map[p_choice.upper()]
        
        if profile == "FAST":
            start_port, end_port = 1, 10000
        elif profile == "ALL":
            start_port, end_port = 1, 65535
        else:
            port_choice = Prompt.ask("[bold cyan][?][/bold cyan] Custom Port Range (e.g., '1-1000')", default="1-1000")
            try:
                parts = port_choice.split('-')
                start_port = int(parts[0].strip())
                end_port = int(parts[1].strip()) if len(parts) > 1 else start_port
            except:
                console.print("[red][!] Invalid format. Defaulting to 1-1000.[/red]")
                start_port, end_port = 1, 1000

        console.print("\n[bold yellow]Available Scan Modes:[/bold yellow]")
        console.print("  [1] SMART   - Autonomous AI Decision Engine (Recommended)")
        console.print("  [2] ASYNC   - Ultra-Fast TCP Connect Scan")
        console.print("  [3] STEALTH - Scapy Stealth Scan (Requires root/admin)")
        mode_choice = Prompt.ask("[bold cyan][?][/bold cyan] Select Mode", choices=["1", "2", "3", "SMART", "ASYNC", "STEALTH"], default="1")
        
        mode_map = {"1": "SMART", "2": "ASYNC", "3": "S", "SMART": "SMART", "ASYNC": "ASYNC", "STEALTH": "S"}
        mode = mode_map[mode_choice.upper()]

        report = Prompt.ask("[bold cyan][?][/bold cyan] Output Format", choices=["console", "json", "html", "md"], default="console")

        console.print(f"\n[bold green]Summary:[/bold green] Target: {target}, Ports: {start_port}-{end_port}, Mode: {mode}, Report: {report}")
        confirm = Confirm.ask("[bold cyan][?][/bold cyan] Are these settings correct?", default=True)
        if confirm:
            return argparse.Namespace(target=target, start_port=start_port, end_port=end_port, mode=mode, report=report)
        else:
            console.print("[yellow][!] Let's try again...[/yellow]\n")


def main():
    parser = argparse.ArgumentParser(
        description="SYN: AI-Powered Autonomous Security Scanner & Pentest Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  syn 192.168.1.1 1 1000 --mode SMART
  syn scanme.nmap.org 80 443 --mode ASYNC --report json
  syn 10.0.0.5 1 65535 --mode S
"""
    )
    
    parser.add_argument("target", nargs='?', help="Target IP address or hostname to scan")
    parser.add_argument("start_port", nargs='?', type=int, help="Starting port number (e.g., 1)")
    parser.add_argument("end_port", nargs='?', type=int, help="Ending port number (e.g., 1000)")
    
    parser.add_argument(
        "--mode", 
        choices=["SMART", "ASYNC", "S", "A", "F", "X", "N"], 
        default="SMART",
        help="""Scan execution mode:
  SMART : Autonomous mode. Uses AI to analyze initial state and pivot dynamically.
  ASYNC : Ultra-fast concurrent TCP connect scan (No root required).
  S     : TCP SYN Stealth Scan.
  A     : TCP ACK Scan (Firewall mapping).
  F     : TCP FIN Scan (Bypassing stateless firewalls).
  X     : TCP XMAS Scan.
  N     : TCP NULL Scan."""
    )
    
    parser.add_argument(
        "--report", 
        choices=["console", "json", "html", "md"], 
        default="console",
        help="Report output format: console, json, html, md (default: console)"
    )

    try:
        if len(sys.argv) == 1:
            args = interactive_wizard()
        else:
            args = parser.parse_args()
            if not args.target or not args.start_port or not args.end_port:
                parser.print_help(sys.stderr)
                sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Interrupted by user. Exiting...[/bold red]")
        sys.exit(0)

    console.print("\n[bold cyan]    [ SYN ENGINE INITIALIZATION ]    [/bold cyan]\n")

    model_manager = ModelManager()
    classifier, anomaly_detector, scaler = model_manager.load_or_train_models()
    analyzer = AIAnalyzer(classifier, anomaly_detector, scaler)
    reporter = Reporter()
    http_analyzer = HttpAnalyzer()

    # Store original mode for multi-target reset
    original_mode = args.mode

    # Parse and Expand Targets
    raw_target = args.target
    ips, target_type = TargetParser.parse_target(raw_target)
    
    if target_type == 'DOMAIN':
        logger.info(f"[RECON] Target is a Domain: {raw_target}")
        console.print("[bold yellow][?] Do you want to map subdomains via OSINT? (y/n)[/bold yellow]")
        do_sub = input().strip().lower()
        if do_sub == 'y':
            subs = SubdomainEnum.query_crt_sh(raw_target)
            sub_ips = SubdomainEnum.resolve_subdomains(subs)
            ips.extend(sub_ips)
            # Remove duplicates
            ips = list(set(ips))
            logger.info(f"[RECON] Expanded target list to {len(ips)} IPs.")
            
    if len(ips) > 1:
        # Perform Host Discovery for CIDR or Multiple Subdomains
        live_ips = asyncio.run(HostDiscovery().discover_live_hosts(ips))
        if not live_ips:
            logger.error("[RECON] No live hosts found in target scope. Exiting.")
            sys.exit(0)
        ips = live_ips

    all_results = []
    
    for ip in ips:
        logger.info(f"\n[bold cyan]>>> Scanning Target: {ip} <<<[/bold cyan]")
        banner_grabber = BannerGrabber(ip)
        target_results = []

        if args.mode == "SMART":
            logger.info("[MODULE] Initializing OODA Loop (SMART Mode)...")
            
            # Root yetki kontrolü - Scapy raw socket için root gerekli
            import os as _os
            if _os.geteuid() != 0:
                logger.warning("[SMART] Root privileges not available. Stealth probe skipped. Falling back to ASYNC scan.")
                args.mode = "ASYNC"
            else:
                ports_to_check = [p for p in QUICK_SCAN_PORTS if args.start_port <= p <= args.end_port]
                if not ports_to_check:
                    ports_to_check = list(range(args.start_port, min(args.end_port + 1, args.start_port + 10)))
                
                stealth_scanner = StealthScanner(ip, ports_to_check[0], ports_to_check[-1], "S")
                stealth_scanner.port_range = ports_to_check 
                initial_results = stealth_scanner.scan()

                initial_analyzed = analyzer.analyze(initial_results)
                open_ports_count = sum(1 for res in initial_analyzed if res['status'] == 'OPEN')
                ttl_values = [res['ttl'] for res in initial_analyzed if res['ttl'] > 0]
                
                chosen_scan_type = "ASYNC"
                os_tahmini = "Unknown"
                
                if len(ttl_values) > 0:
                    avg_ttl = sum(ttl_values) / len(ttl_values)
                    if 100 < avg_ttl <= 128:
                        os_tahmini = "Windows"
                    elif 50 < avg_ttl <= 64:
                        os_tahmini = "Linux"

                if open_ports_count == 0 and len(initial_analyzed) > 0 and all(res['status'] in ['NO_RESPONSE', 'CLOSED'] for res in initial_analyzed):
                    logger.info("[AI_DECISION] Zero footprint detected. Suspected stateful firewall. Pivoting to FIN scan.")
                    chosen_scan_type = "F"
                elif os_tahmini == "Windows":
                    logger.info(f"[OS_FINGERPRINT] AI detected OS footprint: {os_tahmini}")
                elif os_tahmini == "Linux":
                    logger.info(f"[OS_FINGERPRINT] AI detected OS footprint: {os_tahmini}")
                
                logger.info(f"[EXEC] Triggering payload phase using engine: {chosen_scan_type}")
                args.mode = chosen_scan_type

        if args.mode == "ASYNC":
            scanner = AsyncScanner(ip, args.start_port, args.end_port)
            target_results = scanner.scan()
            
            logger.info("[EXEC] Commencing deep service fingerprinting...")
            for res in target_results:
                if res['status'] == 'OPEN':
                    if not res.get('banner'):
                        res['banner'] = banner_grabber.get_banner(res['port'])
        else:
            scanner = StealthScanner(ip, args.start_port, args.end_port, args.mode)
            target_results = scanner.scan()
            
            logger.info("[EXEC] Commencing deep service fingerprinting...")
            for res in target_results:
                if res['status'] == 'OPEN':
                    res['banner'] = banner_grabber.get_banner(res['port'])

        # Generic Service & Web Attack Surface Phase
        for res in target_results:
            if res['status'] == 'OPEN':
                # Jenerik Heuristic Analizi (Port 53'ü de tanır, HTTP'yi de)
                srv_info = ServiceIdentifier.identify(res['port'], res.get('banner', ''))
                
                # Eğer orjinal banner yoksa ve fallback bir isim verildiyse (Örn: DNS Service) onu kullan
                if (not res.get('banner') or res.get('banner') == 'Unknown (No Banner)') and srv_info['service_name'] != 'Unknown (No Banner)':
                    res['banner'] = srv_info['service_name']

                if srv_info['is_web']:
                    logger.info(f"[WEB] Analyzing HTTP surface dynamically on port {res['port']}...")
                    web_data = http_analyzer.analyze_web_service(ip, res['port'])
                    if web_data['is_web']:
                        res['web_info'] = web_data

        analyzed_target_results = analyzer.analyze(target_results)
        
        # Add IP back for reporting
        for res in analyzed_target_results:
            res['target_ip'] = ip
            
        all_results.extend(analyzed_target_results)
        
        # Reset mode for next IP if it was pivoted by SMART
        args.mode = original_mode

    if args.report == "json":
        reporter.export_json(all_results)
    elif args.report == "html":
        html_reporter = HTMLReporter()
        out = html_reporter.generate(all_results, reporter.cve_engine)
        logger.info(f"[REPORT] HTML report saved to: {out}")
    elif args.report == "md":
        md_reporter = MarkdownReporter()
        out = md_reporter.generate(all_results, reporter.cve_engine)
        logger.info(f"[REPORT] Markdown report saved to: {out}")
    else:
        reporter.print_console_report(all_results)
        
    logger.info("[SYSTEM] Execution halted. Scan complete.")

if __name__ == "__main__":
    main()













