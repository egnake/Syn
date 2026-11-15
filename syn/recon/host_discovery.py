"""
SYN - Host Discovery Engine
"""

import asyncio
import os
from typing import List
from syn.core.config import ASYNC_CONCURRENCY_LIMIT
from syn.core.logger import logger


class HostDiscovery:
    """Performs rapid concurrent TCP host discovery on a list of IPs."""

    DISCOVERY_PORTS = [80, 443, 22, 445, 3389, 135, 8080, 21, 25, 3306]

    async def _probe_port(self, ip: str, port: int, semaphore: asyncio.Semaphore, timeout: float) -> bool:
        writer = None
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=timeout,
                )
                return True
            except ConnectionRefusedError:
                # Active TCP RST proves the host stack is alive even if port is closed
                return True
            except (asyncio.TimeoutError, OSError):
                return False
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

    async def _check_host(self, ip: str, semaphore: asyncio.Semaphore) -> bool:
        """Probe discovery ports concurrently and return True as soon as any proves host is up."""
        timeout = 2.2 if os.name == "nt" else 0.8
        tasks = [
            asyncio.create_task(self._probe_port(ip, port, semaphore, timeout))
            for port in self.DISCOVERY_PORTS
        ]
        try:
            for fut in asyncio.as_completed(tasks):
                if await fut:
                    for pending in tasks:
                        if not pending.done():
                            pending.cancel()
                    return True
            return False
        finally:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def discover_live_hosts(self, ips: List[str]) -> List[str]:
        """Run concurrent TCP host discovery and return reachable IPs."""
        if not ips:
            return []

        logger.info(f"[RECON] Initiating Host Discovery on {len(ips)} targets...")
        semaphore = asyncio.Semaphore(ASYNC_CONCURRENCY_LIMIT)
        tasks = [self._check_host(ip, semaphore) for ip in ips]
        results = await asyncio.gather(*tasks)

        live_hosts = [ip for ip, is_alive in zip(ips, results) if is_alive]
        logger.info(f"[RECON] Discovery complete. Found {len(live_hosts)} live hosts out of {len(ips)}.")
        return live_hosts
