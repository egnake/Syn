"""
SYN - Generic Service Identifier Engine
"""

import re
from typing import Dict, Any, Tuple

# Genişletilmiş Ortak Port Listesi (Sadece fallback amaçlı)
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 
    465: "SMTPS", 514: "Syslog", 587: "SMTP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    9092: "Kafka", 9200: "Elasticsearch", 10000: "Webmin", 27017: "MongoDB"
}

# Regex tabanlı Servis Parmak İzleri (Nmap Stili)
FINGERPRINTS = {
    # Name: (Regex Pattern, is_web_surface)
    'HTTP/HTTPS': (re.compile(r"^(?:HTTP/[012]\.[0-9]|<[Hh][Tt][Mm][Ll]>|<![Dd][Oo][Cc][Tt][Yy][Pp][Ee]|<html>)", re.IGNORECASE), True),
    'SSH': (re.compile(r"^SSH-[12]\.[0-9]"), False),
    'FTP': (re.compile(r"^220[- ](?:.*FTP.*|.*FileZilla.*)"), False),
    'SMTP': (re.compile(r"^220.*(?:SMTP|Postfix|Exim|Sendmail)"), False),
    'MySQL': (re.compile(r"^[0-9]\.[0-9]{1,2}\.[0-9]{1,2}.*MySQL"), False),
    'Redis': (re.compile(r"^-ERR unknown command|-NOAUTH"), False),
    'PostgreSQL': (re.compile(r"^E.*FATAL.*(?:password|database)"), False),
}

class ServiceIdentifier:
    """
    Belirli bir port ve ham banner bilgisinden yola çıkarak servisin 
    kimliğini (parmak izini) ve web yüzeyi olup olmadığını tespit eder.
    """
    @staticmethod
    def identify(port: int, banner: str) -> Dict[str, Any]:
        result = {
            'service_name': "Unknown (No Banner)",
            'is_web': False,
            'confidence': 0.0,
            'is_fallback': False
        }

        has_banner = bool(banner and banner != "Unknown (No Banner)")

        if has_banner:
            # 1. Aşama: Regex Fingerprinting (Yüksek Güvenilirlik)
            for srv_name, (pattern, is_web) in FINGERPRINTS.items():
                if pattern.search(banner):
                    result['service_name'] = srv_name
                    result['is_web'] = is_web
                    result['confidence'] = 1.0
                    return result
            
            # 2. Aşama: Kelime Analizi (Orta Güvenilirlik)
            banner_upper = banner.upper()
            if 'HTTP' in banner_upper or 'HTML' in banner_upper or 'SERVER:' in banner_upper:
                result['service_name'] = "HTTP/HTTPS (Heuristic)"
                result['is_web'] = True
                result['confidence'] = 0.8
                return result
                
            # Regex veya kelime uymadı ama banner var. Banner'ı direk servis adı gibi döndürmüyoruz
            # çünkü çok uzun olabilir, sadece "Unknown Service" diyebiliriz veya port fallback'e geçebiliriz.

        # 3. Aşama: Port Fallback (Düşük Güvenilirlik - Nmap nmap-services mantığı)
        if port in COMMON_PORTS:
            srv = COMMON_PORTS[port]
            result['service_name'] = f"{srv} (Port Fallback)"
            result['is_web'] = srv.startswith("HTTP") or srv == "Webmin"
            result['confidence'] = 0.5
            result['is_fallback'] = True
        
        return result
