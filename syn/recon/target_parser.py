"""
SYN - Target Parsing & Identification Engine
"""

import ipaddress
import re
import socket
from typing import List, Tuple
from urllib.parse import urlparse
from syn.core.config import MAX_CIDR_HOSTS


class TargetParser:
    """Parses target strings (IP, CIDR, URL, Domain) and expands them safely."""

    @staticmethod
    def is_ip(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_cidr(target: str) -> bool:
        try:
            ipaddress.ip_network(target, strict=False)
            return "/" in target
        except ValueError:
            return False

    @staticmethod
    def _extract_host_from_input(target_string: str) -> str:
        """Extract clean host/IP/CIDR from raw user input or URL."""
        cleaned = target_string.strip()
        if not cleaned:
            return ""

        # Handle URLs (case-insensitive scheme)
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
            parsed = urlparse(cleaned)
            return parsed.hostname or ""

        # If not CIDR, strip path/query/fragment and optional port
        if not TargetParser.is_cidr(cleaned):
            cleaned = cleaned.split("/")[0].split("?")[0].split("#")[0]
            if "@" in cleaned:
                cleaned = cleaned.rsplit("@", 1)[-1]
            # Bracketed IPv6 e.g. [::1]:8080
            if cleaned.startswith("["):
                if "]" in cleaned:
                    return cleaned[1 : cleaned.index("]")]
            # host:port (avoid splitting unbracketed IPv6 like ::1)
            elif cleaned.count(":") == 1:
                host_part, port_part = cleaned.split(":", 1)
                if port_part.isdigit():
                    return host_part

        return cleaned

    @staticmethod
    def resolve_domain(domain: str) -> str:
        """Resolve a domain/hostname to an IP address (prefers IPv4, falls back to IPv6)."""
        try:
            infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
            ipv4 = [info[4][0] for info in infos if info[0] == socket.AF_INET]
            if ipv4:
                return ipv4[0]
            if infos:
                return infos[0][4][0]
        except socket.gaierror:
            return ""
        return ""

    @staticmethod
    def parse_target_with_hosts(target_string: str) -> Tuple[List[Tuple[str, str]], str]:
        """
        Parse input string into a list of (ip, hostname) pairs and target type.
        Target types: 'IP', 'CIDR', 'DOMAIN', 'LOCAL', 'UNKNOWN'
        """
        if not target_string or not target_string.strip():
            return [], "UNKNOWN"

        host = TargetParser._extract_host_from_input(target_string)
        if not host:
            return [], "UNKNOWN"

        if TargetParser.is_cidr(host):
            network = ipaddress.ip_network(host, strict=False)
            if network.num_addresses > MAX_CIDR_HOSTS:
                raise ValueError(
                    f"CIDR '{host}' expands to {network.num_addresses} addresses, "
                    f"exceeding the safety limit of {MAX_CIDR_HOSTS}."
                )
            if network.num_addresses == 1:
                addr = str(network.network_address)
                return [(addr, addr)], "IP"
            ips = [(str(ip), str(ip)) for ip in network.hosts()]
            if not ips:
                addr = str(network.network_address)
                return [(addr, addr)], "IP"
            return ips, "CIDR"

        if TargetParser.is_ip(host):
            norm_ip = str(ipaddress.ip_address(host))
            return [(norm_ip, norm_ip)], "IP"

        ip = TargetParser.resolve_domain(host)
        if ip:
            if host.lower() == "localhost" or "." not in host:
                return [(ip, host)], "LOCAL"
            return [(ip, host)], "DOMAIN"

        return [], "UNKNOWN"

    @staticmethod
    def parse_target(target_string: str) -> Tuple[List[str], str]:
        """Backward-compatible wrapper returning ([ip, ...], target_type)."""
        pairs, target_type = TargetParser.parse_target_with_hosts(target_string)
        return [ip for ip, _ in pairs], target_type
