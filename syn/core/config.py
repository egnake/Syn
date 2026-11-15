"""
SYN - Configuration and Constants
"""

import os
from typing import Dict, List, Set

PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resolve_writable_dir(subdir: str, env_var: str, create: bool = False) -> str:
    """Resolve a writable directory from env var, package subdir, or user home fallback."""
    override = os.environ.get(env_var)
    if override:
        target = os.path.abspath(override)
        if create:
            os.makedirs(target, exist_ok=True)
        return target

    pkg_target = os.path.join(PACKAGE_DIR, subdir)
    home_target = os.path.join(os.path.expanduser("~"), ".syn", subdir)

    for candidate in (pkg_target, home_target):
        try:
            if os.path.isdir(candidate) and os.access(candidate, os.W_OK):
                return candidate
            parent = os.path.dirname(candidate)
            if os.path.isdir(parent) and os.access(parent, os.W_OK):
                if create:
                    os.makedirs(candidate, exist_ok=True)
                return candidate
        except OSError:
            continue

    if create:
        os.makedirs(home_target, exist_ok=True)
    return home_target


def get_models_dir() -> str:
    return resolve_writable_dir("models", "SYN_MODELS_DIR", create=False)


def get_cache_dir() -> str:
    return resolve_writable_dir("cache", "SYN_CACHE_DIR", create=False)


def get_logs_dir() -> str:
    return resolve_writable_dir("logs", "SYN_LOGS_DIR", create=False)


def get_reports_dir() -> str:
    return os.environ.get("SYN_REPORTS_DIR") or "."


MODELS_DIR = get_models_dir()
CACHE_DIR = get_cache_dir()
LOGS_DIR = get_logs_dir()
REPORTS_DIR = get_reports_dir()

MODEL_CLASSIFIER_FILE = os.path.join(MODELS_DIR, "umay_mk25_os_classifier.joblib")
MODEL_ANOMALY_FILE = os.path.join(MODELS_DIR, "umay_mk25_anomaly_detector.joblib")
MODEL_SCALER_FILE = os.path.join(MODELS_DIR, "umay_mk25_scaler.joblib")
MODEL_MANIFEST_FILE = os.path.join(MODELS_DIR, "model_checksums.json")

ANOMALY_THRESHOLD = -0.15

ASYNC_TIMEOUT = 2.5 if os.name == "nt" else 1.5  # Async TCP timeout (accounts for Windows 2s RST backoff)
ASYNC_CONCURRENCY_LIMIT = 100  # Max concurrent sockets
MAX_CIDR_HOSTS = 65536  # Safety cap to prevent OOM on huge CIDR inputs like /8
MAX_HTTP_BODY_BYTES = 524288  # 512 KB cap for HTTP/OSINT responses
MAX_SUBDOMAIN_JSON_BYTES = 5 * 1024 * 1024  # 5 MB cap for crt.sh JSON

# Standardized Port States
STATUS_OPEN = "OPEN"
STATUS_CLOSED = "CLOSED"
STATUS_FILTERED = "FILTERED"
STATUS_OPEN_FILTERED = "OPEN | FILTERED"
STATUS_UNFILTERED = "UNFILTERED"
STATUS_NO_RESPONSE = "NO_RESPONSE"
STATUS_ERROR = "ERROR"

# Standardized Risk Levels
RISK_CRITICAL = "CRITICAL RISK"
RISK_HIGH = "HIGH RISK"
RISK_MEDIUM = "MEDIUM RISK"
RISK_LOW = "LOW RISK"
RISK_SAFE = "SAFE"
RISK_NONE = "NO_ACTION"

TLS_PORTS: Set[int] = {443, 465, 636, 993, 995, 8443}
HTTP_CLIENT_FIRST_PORTS: Set[int] = {80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000, 9200}
TLS_DEPRECATED_VERSIONS: Set[str] = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}

# Top 100 high-value TCP service ports ordered by real-world prevalence
TOP_PORTS_BY_PRIORITY: List[int] = [
    80, 443, 22, 21, 25, 3389, 110, 445, 139, 143,
    53, 135, 3306, 8080, 8443, 5432, 6379, 27017, 5900, 23,
    587, 993, 995, 465, 1433, 1521, 8000, 8081, 8888, 3000,
    5000, 9000, 9200, 2375, 2376, 6443, 111, 2049, 389, 636,
    88, 179, 873, 1080, 3128, 5601, 5672, 9090, 5985, 1883,
    81, 5001, 4443, 4444, 4848, 5800, 5984, 7001, 7070, 8008,
    2082, 2083, 1194, 1723, 3690, 5060, 4000, 4369, 6000, 6667,
    514, 515, 548, 554, 631, 902, 990, 1720, 2000, 2121,
    1025, 1026, 1027, 7, 9, 13, 26, 37, 79, 106,
    113, 119, 144, 199, 427, 444, 513, 543, 544, 646,
]
TOP_100_PORTS: List[int] = sorted(TOP_PORTS_BY_PRIORITY)

QUICK_SCAN_PORTS: List[int] = [21, 22, 23, 80, 135, 139, 443, 445, 3389]

# Validated raw byte probes (no eval or UTF-8 corruption of binary payloads)
SERVICE_PROBES: Dict[int, List[bytes]] = {
    80: [
        b"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: syn-Scanner\r\nConnection: close\r\n\r\n",
        b"HEAD / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: syn-Scanner\r\nConnection: close\r\n\r\n",
    ],
    443: [
        b"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: syn-Scanner\r\nConnection: close\r\n\r\n",
        b"HEAD / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: syn-Scanner\r\nConnection: close\r\n\r\n",
    ],
    8080: [
        b"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: syn-Scanner\r\nConnection: close\r\n\r\n",
    ],
    8443: [
        b"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: syn-Scanner\r\nConnection: close\r\n\r\n",
    ],
    21: [
        b"\r\n",
        b"USER anonymous\r\n",
    ],
    22: [
        b"SSH-2.0-syn-Scanner\r\n",
    ],
    23: [
        b"\r\n",
    ],
    25: [
        b"EHLO syn.local\r\n",
    ],
    139: [
        # NetBIOS Session Request
        b"\x81\x00\x00D CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00",
    ],
    445: [
        # Minimal SMBv1 Negotiate Protocol Request (NT LM 0.12 + SMB 2.002)
        (
            b"\x00\x00\x00\x54\xffSMBr\x00\x00\x00\x00\x18\x53\xc8\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00"
            b"\x00\x00\x00\x31\x00\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
        ),
    ],
    3389: [
        # Valid 19-byte TPKT + X.224 COTP RDP Connection Request
        b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
    ],
}

QUICK_SCAN_PORTS = [21, 22, 23, 80, 135, 139, 443, 445, 3389]
