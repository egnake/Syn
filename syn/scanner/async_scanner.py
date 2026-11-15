"""
SYN - Fast Asynchronous TCP Connect Scanner
"""

import asyncio
import time
from typing import Any, Dict, Iterator, List
from .base_scanner import BaseScanner
from syn.core.config import (
    ASYNC_CONCURRENCY_LIMIT,
    ASYNC_TIMEOUT,
    STATUS_CLOSED,
    STATUS_ERROR,
    STATUS_FILTERED,
    STATUS_OPEN,
)
from syn.core.logger import logger
from syn.core.sanitizer import strip_control_chars


class AsyncScanner(BaseScanner):
    """High-concurrency asyncio TCP connect port scanner."""

    def __init__(self, target: str, start_port: int, end_port: int, timeout: float = ASYNC_TIMEOUT):
        super().__init__(target, start_port, end_port)
        self.timeout = timeout

    async def _check_port(self, port: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "port": port,
            "status": STATUS_FILTERED,
            "latency_ms": -1.0,
            "ttl": -1,
            "tcp_flags": None,
            "banner": "",
        }

        writer = None
        start_time = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=self.timeout,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            result["status"] = STATUS_OPEN
            result["latency_ms"] = elapsed_ms

            # Passively read server greeting if pushed immediately (avoid sending \r\n to TLS/HTTP ports)
            try:
                banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=0.35)
                if banner_bytes:
                    result["banner"] = strip_control_chars(
                        banner_bytes.decode("utf-8", errors="ignore"),
                        single_line=True,
                    )
            except Exception:
                pass
        except ConnectionRefusedError:
            result["status"] = STATUS_CLOSED
        except asyncio.TimeoutError:
            result["status"] = STATUS_FILTERED
        except OSError as exc:
            logger.debug(f"[ASYNC] Socket error on {self.target}:{port}: {exc}")
            result["status"] = STATUS_ERROR
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        return result

    async def _worker(self, port_iter: Iterator[int], lock: asyncio.Lock, results: List[Dict[str, Any]]):
        while True:
            async with lock:
                try:
                    port = next(port_iter)
                except StopIteration:
                    return
            res = await self._check_port(port)
            results.append(res)

    async def _run_scan_async(self) -> List[Dict[str, Any]]:
        logger.info(f"[EXEC] Commencing Async TCP Scan: {self.target} ({self.start_port}-{self.end_port})")
        total_ports = len(self.port_range)
        worker_count = min(ASYNC_CONCURRENCY_LIMIT, max(1, total_ports))
        port_iter = iter(self.port_range)
        lock = asyncio.Lock()
        results: List[Dict[str, Any]] = []

        workers = [asyncio.create_task(self._worker(port_iter, lock, results)) for _ in range(worker_count)]
        await asyncio.gather(*workers)
        results.sort(key=lambda item: item["port"])
        return results

    def scan(self) -> List[Dict[str, Any]]:
        """Run the async scanner synchronously via asyncio.run()."""
        return asyncio.run(self._run_scan_async())
