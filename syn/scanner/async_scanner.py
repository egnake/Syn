"""
SYN - Fast Asynchronous TCP Connect Scanner
"""

import asyncio
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeRemainingColumn
from .base_scanner import BaseScanner
from syn.core.config import (
    ASYNC_CONCURRENCY_LIMIT,
    ASYNC_TIMEOUT,
    STATUS_CLOSED,
    STATUS_ERROR,
    STATUS_FILTERED,
    STATUS_OPEN,
)
from syn.core.logger import console, logger
from syn.core.sanitizer import strip_control_chars


class AsyncScanner(BaseScanner):
    """High-concurrency asyncio TCP connect port scanner."""

    def __init__(
        self,
        target: str,
        start_port: int = 1,
        end_port: int = 1,
        timeout: float = ASYNC_TIMEOUT,
        ports: Optional[Sequence[int]] = None,
        show_progress: bool = True,
    ):
        super().__init__(target, start_port, end_port, ports=ports)
        self.timeout = timeout
        self.show_progress = show_progress

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

    async def _worker(
        self,
        port_iter: Iterator[int],
        lock: asyncio.Lock,
        results: List[Dict[str, Any]],
        on_done: Optional[Callable[[], None]] = None,
    ):
        while True:
            async with lock:
                try:
                    port = next(port_iter)
                except StopIteration:
                    return
            res = await self._check_port(port)
            results.append(res)
            if on_done is not None:
                on_done()

    async def _run_scan_async(self) -> List[Dict[str, Any]]:
        total_ports = len(self.port_range)
        scope_label = f"{total_ports} ports" if total_ports != (self.end_port - self.start_port + 1) else f"{self.start_port}-{self.end_port}"
        logger.info(f"[EXEC] Commencing Async TCP Scan: {self.target} ({scope_label})")

        worker_count = min(ASYNC_CONCURRENCY_LIMIT, max(1, total_ports))
        port_iter = iter(self.port_range)
        lock = asyncio.Lock()
        results: List[Dict[str, Any]] = []

        use_bar = bool(self.show_progress and console.is_terminal and total_ports > 1)
        if use_bar:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=True,
            ) as progress:
                task_id = progress.add_task(f"Scanning {self.target}", total=total_ports)
                workers = [
                    asyncio.create_task(
                        self._worker(port_iter, lock, results, lambda: progress.advance(task_id, 1))
                    )
                    for _ in range(worker_count)
                ]
                await asyncio.gather(*workers)
        else:
            workers = [asyncio.create_task(self._worker(port_iter, lock, results)) for _ in range(worker_count)]
            await asyncio.gather(*workers)

        results.sort(key=lambda item: item["port"])
        return results

    def scan(self) -> List[Dict[str, Any]]:
        """Run the async scanner synchronously via asyncio.run()."""
        return asyncio.run(self._run_scan_async())
