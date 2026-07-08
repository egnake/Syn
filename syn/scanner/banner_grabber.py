"""
SYN - Asenkron Banner ve Servis Tespiti
"""

import asyncio
from syn.core.config import SERVICE_PROBES

class BannerGrabber:
    """
    Belirtilen hedefe servislere Ã¶zel problar gÃ¶ndererek detaylÄ± 
    banner bilgisini yakalar.
    """
    
    def __init__(self, target: str):
        self.target = target
        
    async def get_banner_async(self, port: int) -> str:
        probes = SERVICE_PROBES.get(port, ['\r\n'])
        
        for probe_str in probes:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, port), 
                    timeout=2.0
                )
                
                # Ä°lk baÄŸlantÄ±da hemen bir banner geliyor mu kontrol et
                try:
                    initial_banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                    if initial_banner:
                        writer.close()
                        await writer.wait_closed()
                        return initial_banner.decode('utf-8', errors='ignore').strip()
                except asyncio.TimeoutError:
                    pass

                # EÄŸer gelmiyorsa, Ã¶zel prob'u gÃ¶nder
                if port in [139, 445]:
                    probe_bytes = eval('b"' + probe_str + '"')
                else:
                    probe_bytes = probe_str.format(target=self.target).encode('utf-8', errors='ignore')

                writer.write(probe_bytes)
                await writer.drain()
                
                response_banner = await asyncio.wait_for(reader.read(2048), timeout=2.0)
                writer.close()
                await writer.wait_closed()
                
                if response_banner:
                    return response_banner.decode('utf-8', errors='ignore').strip()
                    
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                continue

        return "Bilinmiyor (Banner AlÄ±namadÄ±)"

    def get_banner(self, port: int) -> str:
        """Asenkron metodu senkron olarak Ã§aÄŸÄ±rÄ±r."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.get_banner_async(port))
        finally:
            loop.close()

