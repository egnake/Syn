"""
SYN - Tarama Motoru Arayüzü (Base)
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseScanner(ABC):
    """
    Liskov Substitution Principle'a (LSP) uymak üzere tüm tarayıcıların
    miras alması gereken temel arayüz.
    """
    
    def __init__(self, target: str, start_port: int, end_port: int):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.port_range = range(start_port, end_port + 1)
        
    @abstractmethod
    def scan(self) -> List[Dict[str, Any]]:
        """
        Taramayı başlatır ve sonuçları standart bir sözlük listesi olarak döndürür.
        Örnek Dönüş: [{'port': 80, 'status': 'OPEN', 'latency_ms': 15.2, 'ttl': 64, 'banner': 'nginx/1.18.0'}]
        """
        pass









