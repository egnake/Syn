"""
SYN - Subdomain Enumeration Engine
"""

import json
import urllib.request
import urllib.error
import socket
from typing import List
from syn.core.logger import logger

class SubdomainEnum:
    """Uses OSINT (crt.sh) to discover subdomains for a given root domain."""

    @staticmethod
    def query_crt_sh(domain: str) -> List[str]:
        """Queries crt.sh for SSL certificates matching the domain to extract subdomains."""
        logger.info(f"[RECON] Querying crt.sh for subdomains of: {domain}")
        subdomains = set()
        
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'SYN-Recon-Agent'})
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        # crt.sh can return multiple domains separated by newlines
                        for sub in name_value.split('\n'):
                            sub = sub.strip().lower()
                            if sub.endswith(domain) and '*' not in sub:
                                subdomains.add(sub)
        except urllib.error.URLError as e:
            logger.warning(f"[RECON] Failed to query crt.sh: {e}")
        except Exception as e:
            logger.warning(f"[RECON] Unexpected error during crt.sh query: {e}")

        # Limit to first 50 to prevent huge scans unless overridden later
        results = list(subdomains)[:50]
        logger.info(f"[RECON] Discovered {len(results)} subdomains via OSINT.")
        return results

    @staticmethod
    def resolve_subdomains(subdomains: List[str]) -> List[str]:
        """Resolves a list of subdomains to their IP addresses."""
        logger.info("[RECON] Resolving discovered subdomains to IPs...")
        resolved_ips = set()
        
        for sub in subdomains:
            try:
                ip = socket.gethostbyname(sub)
                resolved_ips.add(ip)
                logger.info(f"[RECON] Resolved: {sub} -> {ip}")
            except socket.gaierror:
                # Subdomain exists in certs but doesn't resolve currently (offline/internal)
                pass
                
        return list(resolved_ips)
