"""
SYN - Generic Service Identifier Engine
"""

import re
from typing import Any, Dict

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9092: "Kafka",
    9200: "Elasticsearch",
    10000: "Webmin",
    27017: "MongoDB",
}

FINGERPRINTS = {
    "HTTP/HTTPS": (
        re.compile(r"^(?:HTTP/[0123](?:\.[0-9])?\s|<!doctype\s+html|<html[\s>])", re.IGNORECASE),
        True,
    ),
    "SSH": (re.compile(r"^SSH-[12]\.[0-9]"), False),
    "FTP": (re.compile(r"^220[- ].*(?:FTP|FileZilla|vsFTPd|ProFTPD|Pure-FTPd)", re.IGNORECASE), False),
    "SMTP": (re.compile(r"^220[- ].*(?:ESMTP|SMTP|Postfix|Exim|Sendmail)", re.IGNORECASE), False),
    "POP3": (re.compile(r"^\+OK\b"), False),
    "IMAP": (re.compile(r"^\*\s+OK\b"), False),
    "MySQL": (re.compile(r"(?:^[0-9]+\.[0-9]+\.[0-9]+.*MySQL|MariaDB|mysql_native_password)", re.IGNORECASE), False),
    "Redis": (re.compile(r"^(?:-ERR\s|-NOAUTH\s|-WRONGPASS\s|\+PONG)"), False),
    "PostgreSQL": (re.compile(r"^E.*FATAL.*(?:password|database)", re.IGNORECASE), False),
    "VNC": (re.compile(r"^RFB\s+\d{3}\.\d{3}"), False),
    "RDP": (re.compile(r"^\x03\x00"), False),
}

_HTTP_HEURISTIC_RE = re.compile(
    r"(?:^|\s)(?:HTTP/[0-9.]+|Server:\s|Content-Type:\s|X-Powered-By:\s|<html[\s>]|<head[\s>]|<title[\s>])",
    re.IGNORECASE,
)


class ServiceIdentifier:
    """Identifies network service protocol and whether an HTTP web surface is present."""

    @staticmethod
    def identify(port: int, banner: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "service_name": "Unknown (No Banner)",
            "is_web": False,
            "confidence": 0.0,
            "is_fallback": False,
        }

        has_banner = bool(banner and banner != "Unknown (No Banner)")

        if has_banner:
            for srv_name, (pattern, is_web) in FINGERPRINTS.items():
                if pattern.search(banner):
                    result["service_name"] = srv_name
                    result["is_web"] = is_web
                    result["confidence"] = 1.0
                    return result

            if _HTTP_HEURISTIC_RE.search(banner):
                result["service_name"] = "HTTP/HTTPS (Heuristic)"
                result["is_web"] = True
                result["confidence"] = 0.8
                return result

        if port in COMMON_PORTS:
            srv = COMMON_PORTS[port]
            result["service_name"] = f"{srv} (Port Fallback)"
            result["is_web"] = srv.startswith("HTTP") or srv in ("Webmin", "Elasticsearch")
            result["confidence"] = 0.5
            result["is_fallback"] = True

        return result
