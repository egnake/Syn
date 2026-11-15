"""
SYN - Scapy Stealth & UDP Scanner Engine
"""

from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import ctypes
import ipaddress
import os
import random
import threading
import time
from typing import Any, Deque, Dict, List, Optional, Tuple
from scapy.all import ICMP, IP, IPv6, Raw, TCP, UDP, conf, send, sr1
from .base_scanner import BaseScanner
from syn.core.config import (
    STATUS_CLOSED,
    STATUS_ERROR,
    STATUS_FILTERED,
    STATUS_NO_RESPONSE,
    STATUS_OPEN,
    STATUS_OPEN_FILTERED,
    STATUS_UNFILTERED,
)
from syn.core.logger import logger

conf.verb = 0

# Lightweight UDP protocol probes to avoid 0-byte silence on common UDP services
UDP_PROBES: Dict[int, bytes] = {
    53: b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123: b"\x1b" + b"\x00" * 47,
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05+\x06\x01\x02\x01\x05\x00",
}


class StealthScanner(BaseScanner):
    """
    Scapy-based raw packet scanner supporting SYN (S), ACK (A), FIN (F),
    XMAS (X), NULL (N), and UDP (U) modes with thread-safe AI jitter throttling.
    """

    SCAN_INFO = {
        "S": {"name": "SYN", "flag": "S"},
        "A": {"name": "ACK", "flag": "A"},
        "F": {"name": "FIN", "flag": "F"},
        "X": {"name": "XMAS", "flag": "FPU"},
        "N": {"name": "NULL", "flag": ""},
        "U": {"name": "UDP", "flag": ""},
    }

    def __init__(
        self,
        target: str,
        start_port: int,
        end_port: int,
        scan_type: str = "S",
        jitter_enabled: bool = False,
        ports_override: Optional[List[int]] = None,
        max_workers: int = 32,
    ):
        super().__init__(target, start_port, end_port)
        self.scan_type = scan_type.upper()
        self.jitter_enabled = jitter_enabled
        self.max_workers = max(1, max_workers)
        if ports_override is not None:
            self.port_range = ports_override

        self.latencies: Deque[float] = deque(maxlen=50)
        self._latency_lock = threading.Lock()
        self._is_ipv6 = self._detect_ipv6(target)

        if self.scan_type not in self.SCAN_INFO:
            logger.warning(f"[MODULE] Invalid scan flag ({self.scan_type}). Defaulting to SYN stealth (S).")
            self.scan_type = "S"

    @staticmethod
    def _detect_ipv6(target: str) -> bool:
        try:
            return ipaddress.ip_address(target).version == 6
        except ValueError:
            return False

    @staticmethod
    def is_available() -> Tuple[bool, str]:
        """Cross-platform check for raw packet privileges and pcap provider."""
        if os.name == "nt":
            try:
                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                is_admin = False
            if not is_admin:
                return False, "Administrator privileges are required for raw packet stealth scans on Windows."
            l2_cls_name = getattr(conf.L2socket, "__name__", "")
            if not conf.use_pcap and l2_cls_name.startswith("_NotAvailable"):
                return False, "Npcap/WinPcap provider is missing; layer-2/raw packet stealth scan is unavailable."
            return True, ""

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return False, "Root privileges (euid=0) are required for raw socket stealth scans."
        return True, ""

    def _build_packet(self, port: int, sport: int, seq: int):
        ip_layer = IPv6(dst=self.target) if self._is_ipv6 else IP(dst=self.target)
        if self.scan_type == "U":
            payload = UDP_PROBES.get(port, b"")
            pkt = ip_layer / UDP(dport=port, sport=sport)
            return pkt / Raw(load=payload) if payload else pkt
        tcp_flag = self.SCAN_INFO[self.scan_type]["flag"]
        return ip_layer / TCP(dport=port, sport=sport, flags=tcp_flag, seq=seq)

    def _send_rst_teardown(self, port: int, sport: int, seq: int, ack: int):
        try:
            ip_layer = IPv6(dst=self.target) if self._is_ipv6 else IP(dst=self.target)
            rst_pkt = ip_layer / TCP(dport=port, sport=sport, flags="R", seq=seq, ack=ack)
            send(rst_pkt, verbose=0)
        except Exception:
            pass

    def _classify_response(self, port: int, sport: int, seq: int, response) -> str:
        if self.scan_type == "U":
            if response.haslayer(UDP):
                return STATUS_OPEN
            if response.haslayer(ICMP):
                icmp_type = int(response[ICMP].type)
                icmp_code = int(response[ICMP].code)
                if icmp_type == 3 and icmp_code == 3:
                    return STATUS_CLOSED
                if icmp_type == 3 and icmp_code in (0, 1, 2, 9, 10, 13):
                    return STATUS_FILTERED
            return STATUS_NO_RESPONSE

        if response.haslayer(ICMP):
            icmp_type = int(response[ICMP].type)
            icmp_code = int(response[ICMP].code)
            if icmp_type == 3 and icmp_code in (0, 1, 2, 3, 9, 10, 13):
                return STATUS_FILTERED
            return STATUS_NO_RESPONSE

        if not response.haslayer(TCP):
            return STATUS_FILTERED if self.scan_type == "A" else STATUS_NO_RESPONSE

        flags = int(response[TCP].flags)
        if self.scan_type == "S":
            if (flags & 0x12) == 0x12:  # SYN+ACK (also handles ECN bits)
                self._send_rst_teardown(port, sport, seq + 1, int(response[TCP].seq) + 1)
                return STATUS_OPEN
            if flags & 0x04:  # RST or RST+ACK
                return STATUS_CLOSED
            return STATUS_NO_RESPONSE

        if self.scan_type == "A":
            if flags & 0x04:  # RST / RST+ACK
                return STATUS_UNFILTERED
            return STATUS_FILTERED

        if self.scan_type in ("F", "X", "N"):
            if flags & 0x04:  # RST or RST+ACK
                return STATUS_CLOSED
            return STATUS_NO_RESPONSE

        return STATUS_NO_RESPONSE

    def _scan_port_worker(self, port: int) -> Dict[str, Any]:
        sport = random.randint(32768, 60999)
        seq = random.randint(1000, 0xFFFFFFFF)
        pkt = self._build_packet(port, sport, seq)

        result: Dict[str, Any] = {
            "port": port,
            "status": STATUS_NO_RESPONSE,
            "latency_ms": -1.0,
            "ttl": -1,
            "tcp_flags": None,
            "banner": "",
        }

        try:
            start_time = time.perf_counter()
            response = sr1(pkt, timeout=2.0, verbose=0)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        except (ValueError, PermissionError, OSError, RuntimeError) as exc:
            logger.debug(f"[STEALTH] Packet send failed on port {port}: {exc}")
            result["status"] = STATUS_ERROR
            result["error"] = str(exc)
            return result

        if response is not None:
            with self._latency_lock:
                self.latencies.append(elapsed_ms)
            ttl_val = getattr(response, "ttl", getattr(response, "hlim", -1))
            tcp_flags_val = int(response[TCP].flags) if response.haslayer(TCP) else None
            result.update(
                {
                    "latency_ms": elapsed_ms,
                    "ttl": int(ttl_val) if ttl_val is not None else -1,
                    "tcp_flags": tcp_flags_val,
                    "status": self._classify_response(port, sport, seq, response),
                }
            )
        else:
            if self.scan_type in ("F", "X", "N", "U"):
                result["status"] = STATUS_OPEN_FILTERED
            elif self.scan_type == "A":
                result["status"] = STATUS_FILTERED

        return result

    def scan(self) -> List[Dict[str, Any]]:
        scan_name = self.SCAN_INFO[self.scan_type]["name"]
        jitter_status = "enabled" if self.jitter_enabled else "disabled"
        logger.info(
            f"[EXEC] Commencing Stealth {scan_name} Scan (Jitter: {jitter_status}): "
            f"{self.target} ({self.start_port}-{self.end_port})"
        )

        ports = list(self.port_range)
        if not ports:
            return []

        base_sleep = 0.01
        current_sleep = base_sleep
        all_results: List[Dict[str, Any]] = []
        workers = min(self.max_workers, len(ports))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for port in ports:
                futures.append(executor.submit(self._scan_port_worker, port))

                if self.jitter_enabled:
                    with self._latency_lock:
                        recent = list(self.latencies)[-5:]
                    if len(recent) >= 5:
                        recent_avg = sum(recent) / len(recent)
                        if recent_avg > 500:
                            current_sleep = min(1.0, current_sleep * 1.5)
                        elif recent_avg < 100:
                            current_sleep = max(base_sleep, current_sleep * 0.9)
                    time.sleep(current_sleep)

            for fut in as_completed(futures):
                all_results.append(fut.result())

        all_results.sort(key=lambda item: item["port"])
        return all_results
