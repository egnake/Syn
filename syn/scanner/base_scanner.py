"""
SYN - Base Scanner Interface
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
from syn.core.sanitizer import validate_port_range


class BaseScanner(ABC):
    """Abstract base interface for all port scanners (Liskov Substitution Principle)."""

    def __init__(self, target: str, start_port: int, end_port: int):
        validate_port_range(start_port, end_port)
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.port_range = range(start_port, end_port + 1)

    @abstractmethod
    def scan(self) -> List[Dict[str, Any]]:
        """
        Execute scan and return standardized port result dictionaries:
        [{'port': int, 'status': str, 'latency_ms': float, 'ttl': int, 'tcp_flags': Optional[int], 'banner': str}]
        """
        raise NotImplementedError
