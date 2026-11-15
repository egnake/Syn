"""
SYN - Web Attack Surface Analyzer
"""

import html
import ipaddress
import re
import socket
import ssl
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.parse
import urllib.request
from syn.core.config import MAX_HTTP_BODY_BYTES, TLS_DEPRECATED_VERSIONS
from syn.core.sanitizer import strip_control_chars


class _SameTargetRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow redirects only within the same scanned IP/hostname to avoid off-scope scraping."""

    def __init__(self, allowed_hosts: set):
        super().__init__()
        self.allowed_hosts = {h.lower() for h in allowed_hosts if h}

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.hostname and parsed.hostname.lower() not in self.allowed_hosts:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpAnalyzer:
    """Performs safe HTTP/HTTPS surface analysis on discovered web services."""

    # Use header keys or unambiguous signatures (avoid short 2-char hex collisions like 'f5')
    WAF_SIGNATURES = {
        "cloudflare": ("cf-ray", "cf-cache-status", "__cf_bm", "cloudflare"),
        "akamai": ("x-akamai-", "akamai-grn", "akamaighost"),
        "imperva": ("x-iinfo", "visid_incap", "incapsula"),
        "f5": ("bigipserver", "x-wa-info", "f5-ltm", "f5_"),
        "aws": ("awselb", "x-amz-cf-id", "x-amz-cf-pop"),
        "sucuri": ("x-sucuri-id", "x-sucuri-cache", "sucuri"),
    }

    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
    ]

    _ACCEPTED_HTTP_ERRORS = {401, 403, 404, 405, 429, 500, 502, 503}

    def __init__(self):
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    @staticmethod
    def _format_host_for_url(ip: str) -> str:
        try:
            if ipaddress.ip_address(ip).version == 6:
                return f"[{ip}]"
        except ValueError:
            pass
        return ip

    def _build_opener(self, allowed_hosts: set):
        return urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.ctx),
            _SameTargetRedirectHandler(allowed_hosts),
        )

    @staticmethod
    def _detect_wafs(headers: Dict[str, str]) -> List[str]:
        detected: List[str] = []
        for waf_name, signatures in HttpAnalyzer.WAF_SIGNATURES.items():
            for h_key, h_val in headers.items():
                if any(sig in h_key or sig in h_val for sig in signatures):
                    detected.append(waf_name.upper())
                    break
        return detected

    @staticmethod
    def _is_valid_robots_txt(status: int, content_type: str, body: str) -> bool:
        if status != 200:
            return False
        body_lower = body.lower()
        if "<html" in body_lower or "<!doctype" in body_lower:
            return False
        if "text/plain" in content_type.lower():
            return True
        return any(tok in body_lower for tok in ("user-agent:", "disallow:", "allow:", "sitemap:"))

    @staticmethod
    def _is_ip_literal(value: Optional[str]) -> bool:
        if not value:
            return False
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _inspect_tls(
        self, ip: str, port: int, hostname: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Inspect negotiated TLS protocol, cipher, and certificate verification status."""
        sni_host = hostname if hostname and not self._is_ip_literal(hostname) else None
        verified_ctx = ssl.create_default_context()
        verified_ctx.check_hostname = bool(sni_host)
        verified_ctx.verify_mode = ssl.CERT_REQUIRED

        tls_info: Dict[str, Any] = {
            "tls_version": None,
            "cipher": None,
            "cert_subject": "",
            "cert_expires": "",
            "cert_verified": False,
            "tls_issue": None,
        }

        try:
            with socket.create_connection((ip, port), timeout=3) as sock:
                with verified_ctx.wrap_socket(sock, server_hostname=sni_host) as ssock:
                    tls_info["tls_version"] = ssock.version()
                    cipher = ssock.cipher()
                    tls_info["cipher"] = cipher[0] if cipher else None
                    cert = ssock.getpeercert() or {}
                    subject = {
                        k: v for rdn in cert.get("subject", ()) for k, v in rdn if len(rdn) > 0
                    }
                    tls_info["cert_subject"] = strip_control_chars(subject.get("commonName", ""))
                    tls_info["cert_expires"] = strip_control_chars(cert.get("notAfter", ""))
                    tls_info["cert_verified"] = True
                    if tls_info["tls_version"] in TLS_DEPRECATED_VERSIONS:
                        tls_info["tls_issue"] = f"Deprecated TLS protocol ({tls_info['tls_version']})"
                    return tls_info
        except ssl.SSLError as exc:
            tls_info["tls_issue"] = strip_control_chars(str(exc), single_line=True)[:120]
        except (socket.timeout, TimeoutError, OSError):
            return None

        # Verification failed; inspect negotiated protocol/cipher safely without trusting cert
        try:
            with socket.create_connection((ip, port), timeout=3) as sock:
                with self.ctx.wrap_socket(sock, server_hostname=sni_host) as ssock:
                    tls_info["tls_version"] = ssock.version()
                    cipher = ssock.cipher()
                    tls_info["cipher"] = cipher[0] if cipher else None
                    if tls_info["tls_version"] in TLS_DEPRECATED_VERSIONS:
                        dep = f"Deprecated TLS protocol ({tls_info['tls_version']})"
                        tls_info["tls_issue"] = (
                            f"{dep}; {tls_info['tls_issue']}" if tls_info["tls_issue"] else dep
                        )
        except (ssl.SSLError, socket.timeout, TimeoutError, OSError):
            pass

        return tls_info

    def analyze_web_service(
        self, ip: str, port: int, hostname: Optional[str] = None
    ) -> Dict[str, Any]:
        """Analyze a web service with automatic HTTP/HTTPS fallback and safe caps."""
        result: Dict[str, Any] = {
            "is_web": False,
            "scheme": None,
            "title": "Unknown",
            "waf": "None Detected",
            "missing_security_headers": [],
            "has_robots": False,
            "tls_info": None,
        }

        url_host = self._format_host_for_url(ip)
        host_header = hostname or ip
        allowed_hosts = {ip, hostname} if hostname else {ip}
        opener = self._build_opener(allowed_hosts)
        schemes = ["https", "http"] if port in (443, 8443) else ["http", "https"]

        success = False
        working_scheme = None
        working_html = ""
        working_headers: Dict[str, str] = {}

        base_headers = {"User-Agent": "SYN-Web-Recon", "Host": host_header}

        for scheme in schemes:
            url = f"{scheme}://{url_host}:{port}/"
            req = urllib.request.Request(url, headers=base_headers)

            try:
                with opener.open(req, timeout=3) as response:
                    working_headers = {k.lower(): v.lower() for k, v in response.getheaders()}
                    working_html = response.read(MAX_HTTP_BODY_BYTES).decode("utf-8", errors="ignore")

                    if "plain http request was sent to https port" in working_html.lower():
                        continue

                    success = True
                    working_scheme = scheme
                    break
            except urllib.error.HTTPError as exc:
                body = ""
                try:
                    body = exc.read(MAX_HTTP_BODY_BYTES).decode("utf-8", errors="ignore")
                except Exception:
                    pass
                if exc.code == 400 and scheme == "http" and "https" in body.lower():
                    continue
                if exc.code in self._ACCEPTED_HTTP_ERRORS or (exc.code == 400 and body):
                    success = True
                    working_scheme = scheme
                    working_html = body
                    working_headers = {k.lower(): v.lower() for k, v in exc.headers.items()} if exc.headers else {}
                    break
            except Exception:
                continue

        if not success:
            return result

        result["is_web"] = True
        result["scheme"] = working_scheme

        title_match = re.search(r"<title[^>]*>(.*?)</title>", working_html, re.IGNORECASE | re.DOTALL)
        if title_match:
            raw_title = html.unescape(title_match.group(1))
            clean_title = strip_control_chars(raw_title, single_line=True)
            if clean_title:
                result["title"] = clean_title

        wafs = self._detect_wafs(working_headers)
        if wafs:
            result["waf"] = ", ".join(wafs)

        for sec_hdr in self.SECURITY_HEADERS:
            if sec_hdr.lower() not in working_headers:
                result["missing_security_headers"].append(sec_hdr)

        robots_url = f"{working_scheme}://{url_host}:{port}/robots.txt"
        req_robots = urllib.request.Request(robots_url, headers=base_headers)
        try:
            with opener.open(req_robots, timeout=2) as resp:
                ctype = resp.headers.get("Content-Type", "") if resp.headers else ""
                robots_body = resp.read(65536).decode("utf-8", errors="ignore")
                result["has_robots"] = self._is_valid_robots_txt(resp.status, ctype, robots_body)
        except Exception:
            pass

        if working_scheme == "https":
            result["tls_info"] = self._inspect_tls(ip, port, hostname=hostname)

        return result
