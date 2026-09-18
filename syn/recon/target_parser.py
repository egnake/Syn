"""
SYN - Target Parsing & Identification Engine
"""

import ipaddress
import socket
import re
from typing import List, Tuple
from syn.core.logger import logger

class TargetParser:
    """Parses target strings (IP, CIDR, Domain) and expands them into a list of target IPs."""

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
            network = ipaddress.ip_network(target, strict=False)
            return network.num_addresses > 1
        except ValueError:
            return False

    @staticmethod
    def resolve_domain(domain: str) -> str:
        """Resolves a domain name to its IPv4 address."""
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return ""

    @staticmethod
    def parse_target(target_string: str) -> Tuple[List[str], str]:
        """
        Parses the input string and returns a list of IPs and the identified target type.
        Target Type: 'IP', 'CIDR', 'DOMAIN'
        """
        target_string = target_string.strip()
        
        if TargetParser.is_cidr(target_string):
            network = ipaddress.ip_network(target_string, strict=False)
            ips = [str(ip) for ip in network.hosts()]
            return ips, 'CIDR'
            
        if TargetParser.is_ip(target_string):
            return [target_string], 'IP'
            
        # If neither, assume it's a domain or hostname
        # Strip common URI schemes if the user accidentally pasted a URL
        target_string = re.sub(r'^https?://', '', target_string)
        target_string = target_string.split('/')[0]
        
        ip = TargetParser.resolve_domain(target_string)
        if ip:
            return [ip], 'DOMAIN'
            
        return [], 'UNKNOWN'
