"""
SYN - Gizli (Stealth) Scapy Tarama Motoru
"""

import time
import threading
from queue import Queue
from typing import List, Dict, Any
from tqdm import tqdm
from scapy.all import IP, TCP, sr1, conf
from .base_scanner import BaseScanner
from syn.core.logger import logger

conf.verb = 0

class StealthScanner(BaseScanner):
    """
    Scapy kütüphanesini kullanarak SYN, ACK, FIN, XMAS, NULL taramaları
    yapan, güvenlik duvarlarını aşmayı hedefleyen tarayıcı motoru.
    Aynı zamanda hedefin TTL ve TCP Flag bilgilerini toplayarak 
    YZ analizi için zemin hazırlar.
    """
    
    def __init__(self, target: str, start_port: int, end_port: int, scan_type: str = "S"):
        super().__init__(target, start_port, end_port)
        self.scan_type = scan_type.upper()
        self.scan_info = {
            "S": {"name": "SYN", "flag": "S"},
            "A": {"name": "ACK", "flag": "A"},
            "F": {"name": "FIN", "flag": "F"},
            "X": {"name": "XMAS", "flag": "FPU"},
            "N": {"name": "NULL", "flag": ""}
        }
        
        if self.scan_type not in self.scan_info:
            logger.warning(f"[MODULE] Invalid scan flag ({self.scan_type}). Defaulting to SYN stealth (S).")
            self.scan_type = "S"

    def _scan_port_worker(self, port: int, results_queue: Queue):
        tcp_flag = self.scan_info[self.scan_type]["flag"]
        
        ip_layer = IP(dst=self.target, ttl=128)
        tcp_layer = TCP(dport=port, flags=tcp_flag, sport=42000)
        
        try:
            start_time = time.time()
            response = sr1(ip_layer / tcp_layer, timeout=2.0, verbose=0)
            end_time = time.time()
        except (ValueError, PermissionError, OSError) as e:
            # PermissionError: root/admin gerekli, ValueError: adapter bulunamadı
            response = None
            end_time = time.time()
        
        result = {
            'port': port, 
            'status': 'NO_RESPONSE', 
            'latency_ms': -1.0, 
            'ttl': -1, 
            'tcp_flags': None, 
            'banner': ''
        }

        if response:
            latency = (end_time - start_time) * 1000
            result.update({
                'latency_ms': latency, 
                'ttl': response.ttl, 
                'tcp_flags': response[TCP].flags if response.haslayer(TCP) else None
            })
            
            if self.scan_type == "S":
                if response[TCP].flags == 0x12: # SYN/ACK
                    result['status'] = 'OPEN'

                    sr1(IP(dst=self.target)/TCP(dport=port, flags="R", sport=42000, ack=(response[TCP].seq + 1)), timeout=0.1, verbose=0)
                elif response[TCP].flags == 0x14: # RST
                    result['status'] = 'CLOSED'
            elif self.scan_type == "A":
                if not response.haslayer(TCP): 
                    result['status'] = 'FILTRELENMIS'
                elif response[TCP].flags == 0x4: # RST
                    result['status'] = 'FILTRELENMEMIS'
            elif self.scan_type in ["F", "X", "N"]:
                if response[TCP].flags == 0x14: # RST
                    result['status'] = 'CLOSED'
        else:
            if self.scan_type in ["F", "X", "N"]:
                result['status'] = 'OPEN | FILTERED'
        
        results_queue.put(result)

    def scan(self) -> List[Dict[str, Any]]:
        scan_name = self.scan_info[self.scan_type]["name"]
        logger.info(f"[EXEC] Commencing Stealth TCP {scan_name} Scan: {self.target} ({self.start_port}-{self.end_port})")
        
        results_queue = Queue()
        threads = []
        all_results = []

        for port in tqdm(self.port_range, desc=f"{scan_name} Taraması", unit="port"):
            thread = threading.Thread(target=self._scan_port_worker, args=(port, results_queue))
            threads.append(thread)
            thread.start()

            time.sleep(0.01) 
            
        for thread in threads:
            thread.join()
            
        while not results_queue.empty():
            all_results.append(results_queue.get())
            
        return all_results














