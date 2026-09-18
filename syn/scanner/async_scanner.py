"""
SYN - Hızlı Asenkron Tarama Motoru
"""

import asyncio
import time
from typing import List, Dict, Any
from .base_scanner import BaseScanner
from syn.core.config import ASYNC_TIMEOUT, ASYNC_CONCURRENCY_LIMIT
from syn.core.logger import logger

class AsyncScanner(BaseScanner):
    """
    Hedefteki portların Stateunu saniyede binlerce port hızında kontrol eden 
    asenkronTCP tarayıcı motoru. (Hızlı keşif için)
    """
    
    def __init__(self, target: str, start_port: int, end_port: int):
        super().__init__(target, start_port, end_port)
        
    async def _check_port(self, port: int, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        async with semaphore:
            result = {
                'port': port, 
                'status': 'NO_RESPONSE', 
                'latency_ms': -1.0, 
                'ttl': -1, 
                'tcp_flags': None, 
                'banner': ''
            }
            
            start_time = time.time()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, port), 
                    timeout=ASYNC_TIMEOUT
                )
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                result['status'] = 'CLOSED'
                return result
                
            end_time = time.time()
            result['status'] = 'OPEN'
            result['latency_ms'] = (end_time - start_time) * 1000

            try:
                writer.write(b'\r\n')
                await writer.drain()
                
                banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if banner_bytes:
                    result['banner'] = banner_bytes.decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            
            return result

    async def _run_scan_async(self) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(ASYNC_CONCURRENCY_LIMIT)
        tasks = [self._check_port(port, semaphore) for port in self.port_range]
        
        logger.info(f"[EXEC] Commencing Async TCP Scan: {self.target} ({self.start_port}-{self.end_port})")
        results = await asyncio.gather(*tasks)
        return list(results)

    def scan(self) -> List[Dict[str, Any]]:
        """
        BaseScanner arayüzünün senkron olarak uygulanması. 
        Arkada asenkron event loop çalıştırır.
        """

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(self._run_scan_async())
            return results
        finally:
            loop.close()














