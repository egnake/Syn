"""
SYN - Host Discovery Engine
"""

import asyncio
from typing import List
from syn.core.logger import logger
from syn.core.config import ASYNC_CONCURRENCY_LIMIT

class HostDiscovery:
    """Performs rapid host discovery (Ping Sweep) on a list of IPs using async TCP connections to common ports."""
    
    # Common ports to check if a host is alive
    DISCOVERY_PORTS = [80, 443, 22, 445, 3389, 135]
    
    def __init__(self):
        self.semaphore = asyncio.Semaphore(ASYNC_CONCURRENCY_LIMIT)

    async def _check_host(self, ip: str) -> bool:
        """Tries to connect to a few common ports to determine if the host is up."""
        for port in self.DISCOVERY_PORTS:
            async with self.semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=0.5
                    )
                    writer.close()
                    await writer.wait_closed()
                    return True
                except (asyncio.TimeoutError, ConnectionRefusedError):
                    # Connection refused means the host is alive but the port is closed.
                    # Timeout means the packet dropped (could be firewall, could be dead).
                    # A refused connection is a strong indicator of a live host.
                    pass
                except Exception:
                    pass
        return False

    async def discover_live_hosts(self, ips: List[str]) -> List[str]:
        """Runs the host discovery against a list of IPs and returns the alive ones."""
        logger.info(f"[RECON] Initiating Host Discovery on {len(ips)} targets...")
        
        tasks = [self._check_host(ip) for ip in ips]
        results = await asyncio.gather(*tasks)
        
        live_hosts = [ip for ip, is_alive in zip(ips, results) if is_alive]
        logger.info(f"[RECON] Discovery complete. Found {len(live_hosts)} live hosts out of {len(ips)}.")
        
        return live_hosts
