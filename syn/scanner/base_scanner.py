"""
SYN - Tarama Motoru ArayÃ¼zÃ¼ (Base)
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseScanner(ABC):
    """
    Liskov Substitution Principle'a (LSP) uymak Ã¼zere tÃ¼m tarayÄ±cÄ±larÄ±n
    miras almasÄ± gereken temel arayÃ¼z.
    """
    
    def __init__(self, target: str, start_port: int, end_port: int):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.port_range = range(start_port, end_port + 1)
        
    @abstractmethod
    def scan(self) -> List[Dict[str, Any]]:
        """
        TaramayÄ± baÅŸlatÄ±r ve sonuÃ§larÄ± standart bir sÃ¶zlÃ¼k listesi olarak dÃ¶ndÃ¼rÃ¼r.
        Ã–rnek DÃ¶nÃ¼ÅŸ: [{'port': 80, 'status': 'AÃ‡IK', 'latency_ms': 15.2, 'ttl': 64, 'banner': 'nginx/1.18.0'}]
        """
        pass




