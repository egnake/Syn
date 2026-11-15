"""
SYN - Subdomain Enumeration Engine
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re
import socket
from typing import List, Tuple
import urllib.error
import urllib.parse
import urllib.request
from syn.core.config import MAX_SUBDOMAIN_JSON_BYTES
from syn.core.logger import logger

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


class SubdomainEnum:
    """Uses OSINT (crt.sh) to discover and resolve subdomains for a valid domain."""

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        return bool(domain and _HOSTNAME_RE.match(domain.strip().lower()))

    @staticmethod
    def query_crt_sh(domain: str, limit: int = 50) -> List[str]:
        """Query crt.sh safely for subdomains matching the domain."""
        clean_domain = domain.strip().lower().rstrip(".")
        if not SubdomainEnum.is_valid_domain(clean_domain):
            logger.warning(f"[RECON] Invalid domain for OSINT subdomain lookup: {domain!r}")
            return []

        logger.info(f"[RECON] Querying crt.sh for subdomains of: {clean_domain}")
        subdomains = set()
        encoded = urllib.parse.quote(f"%.{clean_domain}", safe="")
        url = f"https://crt.sh/?q={encoded}&output=json"

        try:
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler())
            req = urllib.request.Request(url, headers={"User-Agent": "SYN-Recon-Agent"})
            with opener.open(req, timeout=10) as response:
                if response.status == 200:
                    raw = response.read(MAX_SUBDOMAIN_JSON_BYTES + 1)
                    if len(raw) > MAX_SUBDOMAIN_JSON_BYTES:
                        logger.warning("[RECON] crt.sh response exceeded size cap; truncating/skipping.")
                        return []
                    data = json.loads(raw.decode("utf-8", errors="replace"))
                    if isinstance(data, list):
                        for entry in data:
                            name_value = entry.get("name_value", "")
                            for sub in str(name_value).split("\n"):
                                sub = sub.strip().lower().rstrip(".")
                                if (
                                    sub
                                    and "*" not in sub
                                    and (sub == clean_domain or sub.endswith("." + clean_domain))
                                    and SubdomainEnum.is_valid_domain(sub)
                                ):
                                    subdomains.add(sub)
        except urllib.error.URLError as exc:
            logger.warning(f"[RECON] Failed to query crt.sh: {exc}")
        except Exception as exc:
            logger.warning(f"[RECON] Unexpected error during crt.sh query: {exc}")

        results = sorted(subdomains)[:limit]
        logger.info(f"[RECON] Discovered {len(results)} subdomains via OSINT.")
        return results

    @staticmethod
    def _resolve_one(subdomain: str) -> Tuple[str, str]:
        try:
            infos = socket.getaddrinfo(subdomain, None, type=socket.SOCK_STREAM)
            ipv4 = [info[4][0] for info in infos if info[0] == socket.AF_INET]
            ip = ipv4[0] if ipv4 else (infos[0][4][0] if infos else "")
            return subdomain, ip
        except socket.gaierror:
            return subdomain, ""

    @staticmethod
    def resolve_subdomains_mapped(subdomains: List[str]) -> List[Tuple[str, str]]:
        """Resolve subdomains concurrently and return (ip, subdomain) pairs."""
        if not subdomains:
            return []

        logger.info("[RECON] Resolving discovered subdomains to IPs...")
        resolved: List[Tuple[str, str]] = []
        with ThreadPoolExecutor(max_workers=min(20, len(subdomains))) as pool:
            futures = [pool.submit(SubdomainEnum._resolve_one, sub) for sub in subdomains]
            for fut in as_completed(futures):
                sub, ip = fut.result()
                if ip:
                    resolved.append((ip, sub))
                    logger.info(f"[RECON] Resolved: {sub} -> {ip}")
        return resolved

    @staticmethod
    def resolve_subdomains(subdomains: List[str]) -> List[str]:
        """Backward-compatible wrapper returning unique resolved IP strings."""
        seen = set()
        ips = []
        for ip, _ in SubdomainEnum.resolve_subdomains_mapped(subdomains):
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return ips
