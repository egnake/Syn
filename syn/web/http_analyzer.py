"""
SYN - Web Attack Surface Analyzer
"""

import urllib.request
import urllib.error
import ssl
import re
from typing import Dict, Any
from syn.core.logger import logger

class HttpAnalyzer:
    """Performs deep HTTP analysis on discovered web services."""

    WAF_SIGNATURES = {
        'cloudflare': ['cloudflare', 'cf-ray'],
        'akamai': ['akamai', 'x-akamai'],
        'imperva': ['incapsula', 'x-iinfo'],
        'f5': ['bigip', 'f5'],
        'aws': ['awselb', 'x-amz-cf-id']
    }

    SECURITY_HEADERS = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']

    def __init__(self):
        # Ignore SSL cert verification errors for reconnaissance
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def analyze_web_service(self, ip: str, port: int) -> Dict[str, Any]:
        """Analyzes a single web service with HTTP/HTTPS automatic fallback."""
        
        result = {
            'is_web': False,
            'title': 'Unknown',
            'waf': 'None Detected',
            'missing_security_headers': [],
            'has_robots': False
        }

        # Önce portun standart şemasını dene, sonra diğerine geç
        schemes = ["https", "http"] if port in [443, 8443] else ["http", "https"]
        
        success = False
        working_scheme = None
        working_html = ""
        working_headers = {}

        for scheme in schemes:
            url = f"{scheme}://{ip}:{port}/"
            req = urllib.request.Request(url, headers={'User-Agent': 'SYN-Web-Recon'})
            
            try:
                with urllib.request.urlopen(req, timeout=3, context=self.ctx) as response:
                    working_headers = {k.lower(): v.lower() for k, v in response.getheaders()}
                    working_html = response.read().decode('utf-8', errors='ignore')
                    
                    # Başarılı sayılması için saçma bir hata dönmemesi lazım
                    if "The plain HTTP request was sent to HTTPS port" in working_html:
                        continue
                        
                    success = True
                    working_scheme = scheme
                    break
            except urllib.error.HTTPError as e:
                # 400 Bad Request genelde HTTP/HTTPS karışıklığından olur
                if e.code == 400 and scheme == "http":
                    continue
                # 401, 403, 404 gibi hatalar web servisinin yaşadığını gösterir
                if e.code in [401, 403, 404, 500]:
                    success = True
                    working_scheme = scheme
                    working_html = e.read().decode('utf-8', errors='ignore')
                    working_headers = {k.lower(): v.lower() for k, v in e.headers.items()}
                    break
            except Exception:
                continue

        if not success:
            return result

        result['is_web'] = True
        
        # Extract Title
        title_match = re.search(r'<title>(.*?)</title>', working_html, re.IGNORECASE)
        if title_match:
            result['title'] = title_match.group(1).strip()

        # Detect WAF
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for header_key, header_val in working_headers.items():
                if any(sig in header_key or sig in header_val for sig in signatures):
                    result['waf'] = waf_name.upper()
                    break

        # Check Security Headers
        for sec_hdr in self.SECURITY_HEADERS:
            if sec_hdr.lower() not in working_headers:
                result['missing_security_headers'].append(sec_hdr)

        # Check robots.txt (Stealth Dirb)
        robots_url = f"{working_scheme}://{ip}:{port}/robots.txt"
        req_robots = urllib.request.Request(robots_url, headers={'User-Agent': 'SYN-Web-Recon'})
        try:
            with urllib.request.urlopen(req_robots, timeout=2, context=self.ctx) as resp:
                if resp.status == 200:
                    result['has_robots'] = True
        except Exception:
            pass

        return result
