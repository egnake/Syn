"""
SYN - CLI (Komut SatÄ±rÄ± ArayÃ¼zÃ¼)
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

def interactive_wizard():
    console.print("\n[bold magenta]=========================================[/bold magenta]")
    console.print("[bold magenta]          SYN INTERACTIVE SETUP          [/bold magenta]")
    console.print("[bold magenta]=========================================[/bold magenta]\n")

    target = Prompt.ask("[bold cyan][?][/bold cyan] Target IP/Hostname", default="127.0.0.1")
    
    port_choice = Prompt.ask(
        "[bold cyan][?][/bold cyan] Port Range (e.g., '1-1000' or 'fast')", 
        default="fast"
    )

    if port_choice.lower() == 'fast':
        start_port, end_port = 1, 1000
    else:
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

    report = Prompt.ask("[bold cyan][?][/bold cyan] Output Format", choices=["console", "json"], default="console")

    return argparse.Namespace(target=target, start_port=start_port, end_port=end_port, mode=mode, report=report)


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
        choices=["console", "json"], 
        default="console",
        help="Report output format (default: console)"
    )

    if len(sys.argv) == 1:
        args = interactive_wizard()
    else:
        args = parser.parse_args()
        if not args.target or not args.start_port or not args.end_port:
            parser.print_help(sys.stderr)
            sys.exit(1)

    console.print("\n[bold cyan]=========================================[/bold cyan]")
    console.print("[bold cyan]       SYN ENGINE INITIALIZATION         [/bold cyan]")
    console.print("[bold cyan]=========================================[/bold cyan]\n")

    model_manager = ModelManager()
    classifier, anomaly_detector, scaler = model_manager.load_or_train_models()
    analyzer = AIAnalyzer(classifier, anomaly_detector, scaler)
    reporter = Reporter()
    banner_grabber = BannerGrabber(args.target)

    all_results = []

    if args.mode == "SMART":
        logger.info("[MODULE] Initializing OODA Loop (SMART Mode)...")
        
        ports_to_check = [p for p in QUICK_SCAN_PORTS if args.start_port <= p <= args.end_port]
        if not ports_to_check:
            ports_to_check = list(range(args.start_port, min(args.end_port + 1, args.start_port + 10)))
        
        stealth_scanner = StealthScanner(args.target, ports_to_check[0], ports_to_check[-1], "S")
        stealth_scanner.port_range = ports_to_check 
        initial_results = stealth_scanner.scan()
        
        initial_analyzed = analyzer.analyze(initial_results)
        open_ports_count = sum(1 for res in initial_analyzed if res['status'] == 'AÃ‡IK')
        ttl_values = [res['ttl'] for res in initial_analyzed if res['ttl'] > 0]
        
        chosen_scan_type = "ASYNC"
        os_tahmini = "Unknown"
        
        if len(ttl_values) > 0:
            avg_ttl = sum(ttl_values) / len(ttl_values)
            if 100 < avg_ttl <= 128:
                os_tahmini = "Windows"
            elif 50 < avg_ttl <= 64:
                os_tahmini = "Linux"

        if open_ports_count == 0 and len(initial_analyzed) > 0 and all(res['status'] in ['YANIT_YOK', 'KAPALI'] for res in initial_analyzed):
            logger.info("[AI_DECISION] Zero footprint detected. Suspected stateful firewall. Pivoting to FIN scan.")
            chosen_scan_type = "F"
        elif os_tahmini == "Windows":
            logger.info(f"[OS_FINGERPRINT] AI detected OS footprint: {os_tahmini}")
        elif os_tahmini == "Linux":
            logger.info(f"[OS_FINGERPRINT] AI detected OS footprint: {os_tahmini}")
        
        logger.info(f"[EXEC] Triggering payload phase using engine: {chosen_scan_type}")
        args.mode = chosen_scan_type

    if args.mode == "ASYNC":
        scanner = AsyncScanner(args.target, args.start_port, args.end_port)
        all_results = scanner.scan()
        
        logger.info("[EXEC] Commencing deep service fingerprinting...")
        for res in all_results:
            if res['status'] == 'AÃ‡IK':
                if not res.get('banner'):
                    res['banner'] = banner_grabber.get_banner(res['port'])
    else:
        scanner = StealthScanner(args.target, args.start_port, args.end_port, args.mode)
        all_results = scanner.scan()
        
        logger.info("[EXEC] Commencing deep service fingerprinting...")
        for res in all_results:
            if res['status'] == 'AÃ‡IK':
                res['banner'] = banner_grabber.get_banner(res['port'])

    analyzed_results = analyzer.analyze(all_results)
    
    if args.report == "json":
        reporter.export_json(analyzed_results)
    else:
        reporter.print_console_report(analyzed_results)
        
    logger.info("[SYSTEM] Execution halted. Scan complete.")

if __name__ == "__main__":
    main()



