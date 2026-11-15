"""
SYN - Asynchronous Service Banner Grabber (TLS-Aware, No eval)
"""

import asyncio
import ipaddress
import ssl
from typing import Dict, List, Optional
from syn.core.config import HTTP_CLIENT_FIRST_PORTS, SERVICE_PROBES, TLS_PORTS
from syn.core.sanitizer import strip_control_chars


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class BannerGrabber:
    """Probes open TCP ports asynchronously to retrieve clean service banners."""

    def __init__(self, target: str, hostname: Optional[str] = None):
        self.target = target
        self.hostname = hostname or target
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def _prepare_probe(self, probe_template: bytes) -> bytes:
        host_bytes = self.hostname.encode("ascii", errors="ignore")
        return probe_template.replace(b"{target}", host_bytes)

    async def _probe_once(self, port: int, probe_bytes: bytes, use_tls: bool) -> Optional[str]:
        writer = None
        try:
            ssl_arg = self._ssl_ctx if use_tls else None
            server_hostname = (
                self.hostname if (use_tls and not _is_ip_literal(self.hostname)) else None
            )
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.target,
                    port,
                    ssl=ssl_arg,
                    server_hostname=server_hostname,
                ),
                timeout=2.0,
            )

            # For server-first protocols (SSH, FTP, SMTP, etc.), read greeting first
            if port not in HTTP_CLIENT_FIRST_PORTS:
                try:
                    initial_banner = await asyncio.wait_for(reader.read(1024), timeout=0.6)
                    if initial_banner:
                        cleaned = strip_control_chars(
                            initial_banner.decode("utf-8", errors="ignore"),
                            single_line=True,
                        )
                        if cleaned:
                            return cleaned
                except asyncio.TimeoutError:
                    pass

            writer.write(probe_bytes)
            await writer.drain()

            response_banner = await asyncio.wait_for(reader.read(2048), timeout=2.0)
            if response_banner:
                cleaned = strip_control_chars(
                    response_banner.decode("utf-8", errors="ignore"),
                    single_line=True,
                )
                if cleaned:
                    return cleaned
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
            return None
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
        return None

    async def get_banner_async(self, port: int) -> str:
        default_probes = [
            b"\r\n",
            b"HEAD / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: syn-Scanner\r\nConnection: close\r\n\r\n",
        ]
        probes = SERVICE_PROBES.get(port, default_probes)
        use_tls_first = port in TLS_PORTS

        for probe_template in probes:
            probe_bytes = self._prepare_probe(probe_template)
            banner = await self._probe_once(port, probe_bytes, use_tls=use_tls_first)
            if banner:
                return banner
            # If TLS port rejected TLS or non-TLS port requires TLS, try opposite once
            if use_tls_first:
                banner = await self._probe_once(port, probe_bytes, use_tls=False)
                if banner:
                    return banner

        return "Unknown (No Banner)"

    async def get_banners_batch(self, ports: List[int], concurrency: int = 20) -> Dict[int, str]:
        """Concurrently grab banners for a list of open ports."""
        if not ports:
            return {}
        semaphore = asyncio.Semaphore(max(1, concurrency))

        async def _bounded(p: int):
            async with semaphore:
                return p, await self.get_banner_async(p)

        pairs = await asyncio.gather(*(_bounded(p) for p in ports))
        return dict(pairs)

    def get_banners(self, ports: List[int]) -> Dict[int, str]:
        """Synchronous batch banner grabbing via asyncio.run()."""
        if not ports:
            return {}
        return asyncio.run(self.get_banners_batch(ports))

    def get_banner(self, port: int) -> str:
        """Backward-compatible single-port synchronous wrapper."""
        return asyncio.run(self.get_banner_async(port))
