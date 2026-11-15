"""
SYN - CLI (Command Line Interface & Scan Orchestrator)
"""

import argparse
import asyncio
from collections import OrderedDict
import logging
import sys
from typing import Any, Dict, List, Optional, Tuple
from rich.prompt import Confirm, Prompt

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from syn.ai.analyzer import AIAnalyzer
from syn.ai.model_manager import ModelManager
from syn.banners import get_random_banner
from syn.core.config import (
    ASYNC_TIMEOUT,
    QUICK_SCAN_PORTS,
    STATUS_ERROR,
    STATUS_NO_RESPONSE,
    STATUS_OPEN,
    TOP_100_PORTS,
    TOP_PORTS_BY_PRIORITY,
)
from syn.core.logger import console, enable_file_logging, logger
from syn.core.sanitizer import parse_port_spec, validate_port_range
from syn.recon.host_discovery import HostDiscovery
from syn.recon.subdomain_enum import SubdomainEnum
from syn.recon.target_parser import TargetParser
from syn.reporting.html_reporter import HTMLReporter
from syn.reporting.markdown_reporter import MarkdownReporter
from syn.reporting.reporter import Reporter
from syn.scanner.async_scanner import AsyncScanner
from syn.scanner.banner_grabber import BannerGrabber
from syn.scanner.service_identifier import ServiceIdentifier
from syn.scanner.stealth_scanner import StealthScanner
from syn.vulnerability.cve_engine import CVEEngine
from syn.web.http_analyzer import HttpAnalyzer


def _prompt_custom_ports() -> List[int]:
    while True:
        port_choice = Prompt.ask(
            "[bold cyan][?][/bold cyan] Custom Ports/Ranges (e.g., '22,80,443,8000-8100')",
            default="1-1000",
        )
        try:
            return parse_port_spec(port_choice)
        except ValueError as exc:
            console.print(f"[red][!] {exc} Please try again.[/red]")


def interactive_wizard() -> argparse.Namespace:
    art = get_random_banner()
    console.print(f"[bold magenta]{art}[/bold magenta]")
    console.print("[bold cyan]       [ INTERACTIVE SETUP ]       [/bold cyan]\n")

    while True:
        target = Prompt.ask("[bold cyan][?][/bold cyan] Target IP/Hostname", default="127.0.0.1")

        console.print("\n[bold yellow]Port Scanning Profiles:[/bold yellow]")
        console.print("  [1] QUICK    - Top 100 Common Ports (Fastest)")
        console.print("  [2] STANDARD - Ports 1-1000")
        console.print("  [3] ALL      - Ports 1-65,535 (Thorough but slower)")
        console.print("  [4] CUSTOM   - Specific ports or ranges (e.g., 22,80,443,8000-8100)")
        p_choice = Prompt.ask(
            "[bold cyan][?][/bold cyan] Select Port Profile",
            choices=["1", "2", "3", "4", "QUICK", "STANDARD", "ALL", "CUSTOM"],
            default="1",
        )

        p_map = {
            "1": "QUICK",
            "2": "STANDARD",
            "3": "ALL",
            "4": "CUSTOM",
            "QUICK": "QUICK",
            "STANDARD": "STANDARD",
            "ALL": "ALL",
            "CUSTOM": "CUSTOM",
        }
        profile = p_map[p_choice.upper()]

        explicit_ports: Optional[List[int]] = None
        if profile == "QUICK":
            explicit_ports = list(TOP_100_PORTS)
            start_port, end_port = explicit_ports[0], explicit_ports[-1]
            port_label = f"Top {len(explicit_ports)} Common Ports"
        elif profile == "STANDARD":
            start_port, end_port = 1, 1000
            port_label = "1-1000"
        elif profile == "ALL":
            start_port, end_port = 1, 65535
            port_label = "1-65535"
        else:
            explicit_ports = _prompt_custom_ports()
            start_port, end_port = explicit_ports[0], explicit_ports[-1]
            port_label = (
                f"{explicit_ports[0]}"
                if len(explicit_ports) == 1
                else f"{len(explicit_ports)} selected ports ({start_port}-{end_port})"
            )

        console.print("\n[bold yellow]Available Scan Modes:[/bold yellow]")
        console.print("  [1] SMART   - Autonomous AI Decision Engine (Recommended)")
        console.print("  [2] ASYNC   - Ultra-Fast TCP Connect Scan")
        console.print("  [3] STEALTH - Scapy SYN Stealth Scan (Requires Admin/Root)")
        console.print("  [4] UDP     - Scapy UDP Scan (Requires Admin/Root)")
        mode_choice = Prompt.ask(
            "[bold cyan][?][/bold cyan] Select Mode",
            choices=["1", "2", "3", "4", "SMART", "ASYNC", "STEALTH", "UDP"],
            default="1",
        )

        mode_map = {
            "1": "SMART",
            "2": "ASYNC",
            "3": "S",
            "4": "U",
            "SMART": "SMART",
            "ASYNC": "ASYNC",
            "STEALTH": "S",
            "UDP": "U",
        }
        mode = mode_map[mode_choice.upper()]

        jitter = Confirm.ask(
            "[bold cyan][?][/bold cyan] Enable AI Dynamic Jitter (IDS/IPS Evasion)?",
            default=False,
        )
        subdomains = False
        if not TargetParser.is_ip(target) and not TargetParser.is_cidr(target) and "." in target:
            subdomains = Confirm.ask(
                "[bold cyan][?][/bold cyan] Map subdomains via OSINT (crt.sh)?",
                default=False,
            )

        report = Prompt.ask(
            "[bold cyan][?][/bold cyan] Output Format",
            choices=["console", "json", "html", "md"],
            default="console",
        )

        console.print(
            f"\n[bold green]Summary:[/bold green] Target: {target}, Ports: {port_label}, "
            f"Mode: {mode}, Jitter: {jitter}, Subdomains: {subdomains}, Report: {report}"
        )
        if Confirm.ask("[bold cyan][?][/bold cyan] Are these settings correct?", default=True):
            return argparse.Namespace(
                target=target,
                start_port=start_port,
                end_port=end_port,
                ports=None,
                top_ports=None,
                explicit_ports=explicit_ports,
                mode=mode,
                report=report,
                jitter=jitter,
                subdomains=subdomains,
                output=None,
                timeout=ASYNC_TIMEOUT,
                quiet=False,
            )
        console.print("[yellow][!] Let's try again...[/yellow]\n")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SYN: AI-Powered Autonomous Security Scanner & Pentest Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  syn 192.168.1.1
  syn 192.168.1.1 -p 22,80,443,8000-8100 --mode ASYNC
  syn 192.168.1.1 1 1000 --mode SMART
  syn scanme.nmap.org --top-ports 25 --report json -o scan.json
  sudo syn 10.0.0.5 1 65535 --mode S
""",
    )

    parser.add_argument("target", nargs="?", help="Target IP, CIDR, URL, or hostname to scan")
    parser.add_argument("start_port", nargs="?", type=int, help="Starting port number (1-65535)")
    parser.add_argument("end_port", nargs="?", type=int, help="Ending port number (1-65535)")

    parser.add_argument(
        "-p",
        "--ports",
        default=None,
        help="Comma-separated ports and/or ranges (e.g., 22,80,443,8000-8100).",
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        default=None,
        help=f"Scan top N most common TCP ports (1-{len(TOP_PORTS_BY_PRIORITY)}).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=ASYNC_TIMEOUT,
        help=f"Socket connect timeout in seconds for ASYNC scan (default: {ASYNC_TIMEOUT}).",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Reduce terminal banner/progress output (quiet mode).",
    )

    parser.add_argument(
        "--mode",
        choices=["SMART", "ASYNC", "S", "A", "F", "X", "N", "U"],
        default="SMART",
        help="""Scan execution mode:
  SMART : Autonomous mode. Uses AI to analyze initial state and pivot dynamically.
  ASYNC : Ultra-fast concurrent TCP connect scan (No root required).
  S     : TCP SYN Stealth Scan.
  A     : TCP ACK Scan (Firewall mapping).
  F     : TCP FIN Scan (Bypassing stateless firewalls).
  X     : TCP XMAS Scan.
  N     : TCP NULL Scan.
  U     : UDP Scan.""",
    )
    parser.add_argument(
        "--jitter",
        action="store_true",
        help="Enable AI Dynamic Jitter to evade IDS/IPS during stealth/UDP scans.",
    )
    parser.add_argument(
        "--subdomains",
        action="store_true",
        help="Expand domain targets via OSINT (crt.sh) subdomain enumeration.",
    )
    parser.add_argument(
        "--report",
        choices=["console", "json", "html", "md"],
        default="console",
        help="Report output format: console, json, html, md (default: console)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional output file path for json, html, or md reports.",
    )
    return parser


def resolve_port_selection(args: argparse.Namespace) -> Tuple[int, int, Optional[List[int]]]:
    """
    Resolve CLI or wizard port options into (start_port, end_port, explicit_ports).
    Defaults to Top 100 common ports when no port range/list is supplied.
    """
    existing = getattr(args, "explicit_ports", None)
    if existing is not None:
        return existing[0], existing[-1], list(existing)

    ports_spec = getattr(args, "ports", None)
    top_n = getattr(args, "top_ports", None)
    start_p = getattr(args, "start_port", None)
    end_p = getattr(args, "end_port", None)

    has_positional = start_p is not None or end_p is not None
    if ports_spec and (has_positional or top_n is not None):
        raise ValueError("Cannot combine -p/--ports with positional ports or --top-ports.")
    if top_n is not None and has_positional:
        raise ValueError("Cannot combine --top-ports with positional port arguments.")

    if ports_spec:
        selected = parse_port_spec(ports_spec)
        return selected[0], selected[-1], selected

    if top_n is not None:
        if top_n < 1 or top_n > len(TOP_PORTS_BY_PRIORITY):
            raise ValueError(
                f"--top-ports must be between 1 and {len(TOP_PORTS_BY_PRIORITY)} (got {top_n})."
            )
        selected = sorted(TOP_PORTS_BY_PRIORITY[:top_n])
        return selected[0], selected[-1], selected

    if start_p is not None:
        resolved_end = end_p if end_p is not None else start_p
        validate_port_range(start_p, resolved_end)
        return start_p, resolved_end, None

    # Default when invoked as `syn <target>` without explicit port arguments
    selected = list(TOP_100_PORTS)
    return selected[0], selected[-1], selected


def resolve_scan_targets(raw_target: str, expand_subdomains: bool) -> List[Tuple[str, str]]:
    """Parse target, optionally expand subdomains, and discover live hosts for multi-IP targets."""
    try:
        pairs, target_type = TargetParser.parse_target_with_hosts(raw_target)
    except ValueError as exc:
        logger.error(f"[RECON] {exc}")
        return []

    if target_type == "UNKNOWN" or not pairs:
        logger.error(f"[RECON] Could not resolve or validate target: '{raw_target}'.")
        return []

    ordered_targets: "OrderedDict[str, str]" = OrderedDict()
    for ip, host in pairs:
        ordered_targets.setdefault(ip, host)

    if target_type == "DOMAIN":
        domain_host = pairs[0][1]
        logger.info(f"[RECON] Target resolved as domain: {domain_host} -> {pairs[0][0]}")
        if expand_subdomains:
            subs = SubdomainEnum.query_crt_sh(domain_host)
            for sub_ip, sub_name in SubdomainEnum.resolve_subdomains_mapped(subs):
                ordered_targets.setdefault(sub_ip, sub_name)
            logger.info(f"[RECON] Expanded target scope to {len(ordered_targets)} unique IPs.")

    if len(ordered_targets) > 1:
        live_ips = asyncio.run(HostDiscovery().discover_live_hosts(list(ordered_targets.keys())))
        if not live_ips:
            logger.error("[RECON] No live hosts found in target scope.")
            return []
        return [(ip, ordered_targets[ip]) for ip in live_ips]

    return list(ordered_targets.items())


def decide_smart_mode(
    ip: str,
    start_port: int,
    end_port: int,
    jitter: bool,
    analyzer: AIAnalyzer,
    explicit_ports: Optional[List[int]] = None,
) -> str:
    """Execute SMART OODA pre-probe using AI inference and return the chosen scan engine."""
    logger.info("[MODULE] Initializing OODA Loop (SMART Mode)...")
    capable, reason = StealthScanner.is_available()
    if not capable:
        logger.warning(f"[SMART] {reason} Falling back to ASYNC scan.")
        return "ASYNC"

    if explicit_ports:
        explicit_set = set(explicit_ports)
        ports_to_check = [p for p in QUICK_SCAN_PORTS if p in explicit_set]
        if not ports_to_check:
            ports_to_check = explicit_ports[:10]
    else:
        ports_to_check = [p for p in QUICK_SCAN_PORTS if start_port <= p <= end_port]
        if not ports_to_check:
            ports_to_check = list(range(start_port, min(end_port + 1, start_port + 10)))

    probe_scanner = StealthScanner(
        ip,
        ports_to_check[0],
        ports_to_check[-1],
        scan_type="S",
        jitter_enabled=jitter,
        ports_override=ports_to_check,
        show_progress=False,
    )
    initial_results = probe_scanner.scan()
    initial_analyzed = analyzer.analyze(initial_results)

    if not initial_analyzed or all(r["status"] == STATUS_ERROR for r in initial_analyzed):
        logger.warning("[SMART] Raw probe encountered transport errors. Falling back to ASYNC scan.")
        return "ASYNC"

    os_votes = [
        r.get("ai_os_tahmini", "")
        for r in initial_analyzed
        if r.get("ai_os_tahmini") and "Unknown" not in str(r.get("ai_os_tahmini"))
    ]
    if os_votes:
        dominant_os = max(set(os_votes), key=os_votes.count)
        logger.info(f"[OS_FINGERPRINT] AI detected OS footprint: {dominant_os}")

    open_count = sum(1 for r in initial_analyzed if r["status"] == STATUS_OPEN)
    all_dropped = all(r["status"] == STATUS_NO_RESPONSE for r in initial_analyzed)

    if open_count == 0 and all_dropped:
        logger.info("[AI_DECISION] Probes dropped silently (suspected stateful/packet filter). Pivoting to FIN scan.")
        return "F"

    logger.info("[EXEC] Triggering payload phase using engine: ASYNC")
    return "ASYNC"


def scan_single_target(
    ip: str,
    hostname: str,
    args: argparse.Namespace,
    analyzer: AIAnalyzer,
    http_analyzer: HttpAnalyzer,
) -> List[Dict[str, Any]]:
    logger.info(f">>> Scanning Target: {ip} ({hostname}) <<<")
    scan_mode = args.mode
    start_p, end_p, explicit_ports = resolve_port_selection(args)
    timeout = float(getattr(args, "timeout", ASYNC_TIMEOUT))
    show_progress = not bool(getattr(args, "quiet", False))

    if scan_mode == "SMART":
        scan_mode = decide_smart_mode(
            ip,
            start_p,
            end_p,
            getattr(args, "jitter", False),
            analyzer,
            explicit_ports=explicit_ports,
        )

    if scan_mode != "ASYNC":
        capable, reason = StealthScanner.is_available()
        if not capable:
            logger.error(f"[STEALTH] Cannot run mode '{scan_mode}': {reason}")
            return []

    if scan_mode == "ASYNC":
        scanner = AsyncScanner(
            ip,
            start_p,
            end_p,
            timeout=timeout,
            ports=explicit_ports,
            show_progress=show_progress,
        )
        target_results = scanner.scan()
    else:
        scanner = StealthScanner(
            ip,
            start_p,
            end_p,
            scan_mode,
            getattr(args, "jitter", False),
            ports=explicit_ports,
            show_progress=show_progress,
        )
        target_results = scanner.scan()

    # Batch TCP banner grabbing only on open TCP ports (never on UDP)
    if scan_mode != "U":
        ports_needing_banners = [
            res["port"]
            for res in target_results
            if res["status"] == STATUS_OPEN and not res.get("banner")
        ]
        if ports_needing_banners:
            logger.info("[EXEC] Commencing deep service fingerprinting...")
            banner_grabber = BannerGrabber(ip, hostname=hostname)
            banners_map = banner_grabber.get_banners(ports_needing_banners)
            for res in target_results:
                if res["port"] in banners_map:
                    res["banner"] = banners_map[res["port"]]

    for res in target_results:
        if res["status"] == STATUS_OPEN:
            srv_info = ServiceIdentifier.identify(res["port"], res.get("banner", ""))
            res["banner_is_fallback"] = bool(srv_info["is_fallback"])
            if srv_info.get("banner_summary"):
                res["banner_summary"] = srv_info["banner_summary"]
            if (
                not res.get("banner") or res.get("banner") == "Unknown (No Banner)"
            ) and srv_info["service_name"] != "Unknown (No Banner)":
                res["banner"] = srv_info["service_name"]
                res["banner_summary"] = srv_info["service_name"]

            if srv_info["is_web"] and scan_mode != "U":
                logger.info(f"[WEB] Analyzing HTTP surface dynamically on port {res['port']}...")
                web_data = http_analyzer.analyze_web_service(ip, res["port"], hostname=hostname)
                if web_data["is_web"]:
                    res["web_info"] = web_data

    analyzed = analyzer.analyze(target_results)
    for res in analyzed:
        res["target_ip"] = ip
        res["target_host"] = hostname
    return analyzed


def dispatch_report(
    all_results: List[Dict[str, Any]],
    report_format: str,
    output_path: Optional[str],
    cve_engine: CVEEngine,
) -> None:
    reporter = Reporter(cve_engine=cve_engine)
    if report_format == "json":
        reporter.export_json(all_results, filename=output_path, cve_engine=cve_engine)
    elif report_format == "html":
        out = HTMLReporter().generate(all_results, cve_engine, filename=output_path)
        logger.info(f"[REPORT] HTML report saved to: {out}")
    elif report_format == "md":
        out = MarkdownReporter().generate(all_results, cve_engine, filename=output_path)
        logger.info(f"[REPORT] Markdown report saved to: {out}")
    else:
        reporter.print_console_report(all_results, cve_engine=cve_engine)


def main() -> None:
    parser = build_arg_parser()

    try:
        if len(sys.argv) == 1:
            args = interactive_wizard()
        else:
            args = parser.parse_args()
            if args.target is None:
                parser.print_help(sys.stderr)
                sys.exit(1)
            try:
                if getattr(args, "timeout", ASYNC_TIMEOUT) <= 0:
                    raise ValueError("--timeout must be a positive number.")
                start_p, end_p, explicit_ports = resolve_port_selection(args)
                args.start_port = start_p
                args.end_port = end_p
                args.explicit_ports = explicit_ports
            except ValueError as exc:
                console.print(f"[red][!] {exc}[/red]")
                sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Interrupted by user. Exiting...[/bold red]")
        sys.exit(0)

    target_level = logging.WARNING if getattr(args, "quiet", False) else logging.INFO
    for handler in logger.handlers:
        if not isinstance(handler, logging.FileHandler):
            handler.setLevel(target_level)
    if not getattr(args, "quiet", False):
        console.print("\n[bold cyan]    [ SYN ENGINE INITIALIZATION ]    [/bold cyan]\n")

    enable_file_logging()

    targets = resolve_scan_targets(args.target, getattr(args, "subdomains", False))
    if not targets:
        sys.exit(1)

    model_manager = ModelManager()
    classifier, anomaly_detector, scaler = model_manager.load_or_train_models()
    analyzer = AIAnalyzer(classifier, anomaly_detector, scaler)
    http_analyzer = HttpAnalyzer()
    cve_engine = CVEEngine()

    all_results: List[Dict[str, Any]] = []
    try:
        for ip, hostname in targets:
            all_results.extend(scan_single_target(ip, hostname, args, analyzer, http_analyzer))
    except KeyboardInterrupt:
        logger.warning("[SYSTEM] Scan interrupted by user. Generating partial report...")

    if all_results:
        dispatch_report(all_results, args.report, getattr(args, "output", None), cve_engine)
    else:
        logger.warning("[SYSTEM] No scan results collected.")

    logger.info("[SYSTEM] Execution halted. Scan complete.")


if __name__ == "__main__":
    main()
