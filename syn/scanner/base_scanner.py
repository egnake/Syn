"""
SYN - Base Scanner Interface
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Sequence
from syn.core.sanitizer import is_valid_port, validate_port_range


class BaseScanner(ABC):
    """Abstract base interface for all port scanners (Liskov Substitution Principle)."""

    def __init__(
        self,
        target: str,
        start_port: int = 1,
        end_port: int = 1,
        ports: Optional[Sequence[int]] = None,
    ):
        self.target = target
        if ports is not None:
            unique_ports = sorted({int(p) for p in ports if is_valid_port(p) and True})
            if len(unique_ports) == 0 or any(not is_valid_port(p) for p in ports):
                raise ValueError("Explicit port list must contain valid integer ports (1-65535).")
            self.start_port = unique_ports[0]
            self.end_port = unique_ports[-1]
            self.port_range: Sequence[int] = unique_ports
        else:
            validate_port_range(start_port, end_port)
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
