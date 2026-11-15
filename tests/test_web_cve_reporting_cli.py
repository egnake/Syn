from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys
import threading
from unittest.mock import MagicMock, patch
import pytest
from scapy.all import TCP

from syn.cli import build_arg_parser, main as cli_main, resolve_port_selection
from syn.core.config import (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_NONE,
    STATUS_CLOSED,
    STATUS_OPEN,
    STATUS_OPEN_FILTERED,
    TOP_100_PORTS,
)
from syn.reporting.html_reporter import HTMLReporter
from syn.reporting.markdown_reporter import MarkdownReporter
from syn.reporting.reporter import Reporter
from syn.vulnerability.api_client import CVEApiClient
from syn.vulnerability.cache_manager import CVECacheManager
from syn.vulnerability.cve_engine import CVEEngine
from syn.web.http_analyzer import HttpAnalyzer


class _DummyWebHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        if self.path == "/robots.txt":
            # Soft-404 HTML page should NOT trigger has_robots=True
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<!doctype html><html><body>Not Found</body></html>")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        # 'f5' inside ETag hex must NOT cause false F5 WAF detection!
        self.send_header("ETag", '"deadbeef5a12"')
        self.end_headers()
        self.wfile.write(
            b"<html><head><title>\n  SYN Test App  \n</title></head><body>OK</body></html>"
        )


class TestHttpAnalyzer:
    def test_web_surface_no_f5_fp_and_multiline_title_and_soft404_robots(self):
        server = HTTPServer(("127.0.0.1", 0), _DummyWebHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            res = HttpAnalyzer().analyze_web_service("127.0.0.1", port)
            assert res["is_web"] is True
            assert res["title"] == "SYN Test App"
            assert res["waf"] == "None Detected"
            assert res["has_robots"] is False
            assert "Content-Security-Policy" in res["missing_security_headers"]
        finally:
            server.shutdown()
            server.server_close()
            t.join(timeout=1.0)


class TestVulnerabilityEngine:
    def test_static_recipes_standardized_risk_and_version_boundaries(self):
        cache = CVECacheManager(db_path=":memory:")
        engine = CVEEngine(cache_manager=cache)

        assert engine.analyze_banner("220 vsFTPd 2.3.4")["risk"] == RISK_CRITICAL
        assert engine.analyze_banner("220 ProFTPD 1.3.5 Server")["risk"] == RISK_CRITICAL
        assert engine.analyze_banner("Apache/2.4.41 (Ubuntu)")["risk"] == RISK_LOW
        assert engine.analyze_banner("SSH-2.0-OpenSSH_7.2p2")["risk"] == RISK_MEDIUM

        # Must NOT false-match adjacent version numbers!
        with patch.object(engine.api_client, "get_latest_cve", return_value=None):
            assert engine.analyze_banner("Apache/2.4.410 (Ubuntu)") is None
            assert engine.analyze_banner("SSH-2.0-OpenSSH_7.2p20") is None

    def test_placeholder_and_unversioned_banners_never_query_circl(self):
        cache = CVECacheManager(db_path=":memory:")
        api = CVEApiClient(cache_manager=cache)
        engine = CVEEngine(cache_manager=cache, api_client=api)

        with patch("syn.vulnerability.api_client.urllib.request.build_opener") as mock_opener:
            assert engine.analyze_banner("Unknown (No Banner)") is None
            assert engine.analyze_banner("MSRPC (Port Fallback)") is None
            assert engine.analyze_banner("HTTP/1.1 200 OK") is None
            assert engine.analyze_banner("Apache") is None
            assert not mock_opener.called

    def test_live_cve_version_matching_prevents_old_cve_fp_and_handles_null_cvss(self):
        cache = CVECacheManager(db_path=":memory:")
        api = CVEApiClient(cache_manager=cache)

        circl_payload = json.dumps(
            [
                {
                    "id": "CVE-1999-0236",
                    "cvss": None,
                    "summary": "Old Apache 1.3 CGI flaw",
                    "vulnerable_configuration": ["cpe:2.3:a:apache:http_server:1.3.0"],
                },
                {
                    "id": "CVE-2024-9999",
                    "cvss": 8.2,
                    "summary": "Affects Apache 2.4.59",
                    "vulnerable_configuration": ["cpe:2.3:a:apache:http_server:2.4.59"],
                },
            ]
        ).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = circl_payload
        mock_resp.__enter__.return_value = mock_resp

        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp

        with patch("syn.vulnerability.api_client.urllib.request.build_opener", return_value=mock_opener):
            # Patched 2.4.62 should NOT match 1.3.0 or 2.4.59
            assert api.get_latest_cve("Apache/2.4.62 (Debian)") is None
            # Exact 2.4.59 matches CVE-2024-9999 and caches it
            hit = api.get_latest_cve("Apache/2.4.59 (Debian)")
            assert hit is not None
            assert hit["cve"] == "CVE-2024-9999"

        # Cache hit works offline
        assert cache.get_cached_result("apache:2.4.59")["cve"] == "CVE-2024-9999"

    def test_anomaly_alert_only_fires_on_open_ports(self):
        engine = CVEEngine(cache_manager=CVECacheManager(db_path=":memory:"))
        closed_res = {"port": 999, "status": STATUS_CLOSED, "anomaly_score": -2.0}
        filtered_res = {"port": 999, "status": STATUS_OPEN_FILTERED, "anomaly_score": -2.0}
        open_res = {"port": 999, "status": STATUS_OPEN, "anomaly_score": -2.0}

        assert engine.evaluate_result(closed_res)["decision"] == RISK_NONE
        assert engine.evaluate_result(filtered_res)["decision"] == RISK_NONE
        assert engine.evaluate_result(open_res)["decision"] == RISK_MEDIUM


class TestReportersSecurityAndConsistency:
    def test_all_reporters_safe_against_injection_and_consistent_risks(self, tmp_path):
        engine = CVEEngine(cache_manager=CVECacheManager(db_path=":memory:"))
        results = [
            {
                "target_ip": "10.0.0.5",
                "port": 21,
                "status": STATUS_OPEN,
                "banner": "220 vsftpd 2.3.4 ` [/bold]<script>alert('x')</script>\x1b[31m",
                "ai_os_tahmini": "Linux/64",
                "anomaly_score": 0.4,
                "tcp_flags": TCP(flags="SA").flags,
            },
            {
                "target_ip": "10.0.0.5",
                "port": 80,
                "status": STATUS_OPEN,
                "banner": "Apache/2.4.41",
                "ai_os_tahmini": "Unknown (No TTL)",
                "anomaly_score": float("nan"),
                "web_info": {
                    "is_web": True,
                    "scheme": "http",
                    "title": "[/][/bold]<img src=x>",
                    "waf": "CLOUDFLARE",
                    "has_robots": True,
                    "missing_security_headers": ["Strict-Transport-Security"],
                },
            },
        ]

        # Console reporter must not raise MarkupError
        reporter = Reporter(cve_engine=engine)
        reporter.print_console_report(results, cve_engine=engine)

        # JSON export must succeed on FlagValue & NaN -> strict JSON null
        json_path = str(tmp_path / "out.json")
        reporter.export_json(results, filename=json_path, cve_engine=engine)
        parsed = json.loads(open(json_path, encoding="utf-8").read())
        assert parsed[0]["risk_analysis"]["decision"] == RISK_CRITICAL
        assert parsed[1]["anomaly_score"] is None
        assert parsed[1]["risk_analysis"]["decision"] == RISK_LOW

        # HTML report must classify vsftpd 2.3.4 as critical & escape XSS
        html_path = str(tmp_path / "out.html")
        HTMLReporter().generate(results, engine, filename=html_path)
        html_txt = open(html_path, encoding="utf-8").read()
        assert '<td class="risk-critical">CRITICAL RISK</td>' in html_txt
        assert "<script>" not in html_txt
        assert "&#x27;x&#x27;" in html_txt
        assert "Strict-Transport-Security" in html_txt

        # Markdown report must classify vsftpd 2.3.4 as CRITICAL (NOT SAFE!) & escape backticks/HTML
        md_path = str(tmp_path / "out.md")
        MarkdownReporter().generate(results, engine, filename=md_path)
        md_txt = open(md_path, encoding="utf-8").read()
        assert "🔴 **CRITICAL**" in md_txt
        assert "✅ SAFE" not in md_txt
        assert "<script>" not in md_txt
        assert "<img" not in md_txt


class TestCLIEndToEnd:
    def test_cli_smart_mode_on_localhost_no_crash_and_exports_json(self, tmp_path, monkeypatch):
        server = HTTPServer(("127.0.0.1", 0), _DummyWebHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        out_json = str(tmp_path / "cli_report.json")
        monkeypatch.setenv("SYN_LOGS_DIR", str(tmp_path / "logs"))
        monkeypatch.setenv("SYN_CACHE_DIR", str(tmp_path / "cache"))
        monkeypatch.setattr(
            sys,
            "argv",
            ["syn", "127.0.0.1", str(port), str(port), "--mode", "SMART", "--report", "json", "-o", out_json],
        )
        try:
            cli_main()
            data = json.loads(open(out_json, encoding="utf-8").read())
            assert len(data) == 1
            assert data[0]["port"] == port
            assert data[0]["status"] == STATUS_OPEN
            assert data[0]["web_info"]["title"] == "SYN Test App"
        finally:
            server.shutdown()
            server.server_close()
            t.join(timeout=1.0)

    def test_cli_invalid_port_exits_with_code_1(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["syn", "127.0.0.1", "0", "80"])
        with pytest.raises(SystemExit) as exc:
            cli_main()
        assert exc.value.code == 1

    def test_cli_port_resolution_modes(self):
        parser = build_arg_parser()

        # Zero-arg port default -> Top 100 ports
        s, e, explicit = resolve_port_selection(parser.parse_args(["127.0.0.1"]))
        assert explicit == TOP_100_PORTS
        assert s == TOP_100_PORTS[0] and e == TOP_100_PORTS[-1]

        # Flexible -p list/range spec
        s, e, explicit = resolve_port_selection(parser.parse_args(["127.0.0.1", "-p", "22,80,8000-8002"]))
        assert explicit == [22, 80, 8000, 8001, 8002]
        assert s == 22 and e == 8002

        # --top-ports N
        s, e, explicit = resolve_port_selection(parser.parse_args(["127.0.0.1", "--top-ports", "5"]))
        assert explicit is not None and len(explicit) == 5 and 80 in explicit

        # Single positional port
        s, e, explicit = resolve_port_selection(parser.parse_args(["127.0.0.1", "443"]))
        assert (s, e, explicit) == (443, 443, None)

        # Conflicting -p and --top-ports
        with pytest.raises(ValueError):
            resolve_port_selection(parser.parse_args(["127.0.0.1", "-p", "80", "--top-ports", "5"]))

    def test_cli_quiet_flag_with_p_flag_end_to_end(self, tmp_path, monkeypatch):
        server = HTTPServer(("127.0.0.1", 0), _DummyWebHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        out_json = str(tmp_path / "quiet_p_report.json")
        monkeypatch.setenv("SYN_LOGS_DIR", str(tmp_path / "logs"))
        monkeypatch.setenv("SYN_CACHE_DIR", str(tmp_path / "cache"))
        monkeypatch.setattr(
            sys,
            "argv",
            ["syn", "127.0.0.1", "-p", str(port), "--mode", "ASYNC", "-q", "--report", "json", "-o", out_json],
        )
        try:
            cli_main()
            data = json.loads(open(out_json, encoding="utf-8").read())
            assert len(data) == 1
            assert data[0]["port"] == port
            assert data[0]["status"] == STATUS_OPEN
        finally:
            server.shutdown()
            server.server_close()
            t.join(timeout=1.0)


class TestCirclV2AndTlsSupport:
    def test_circl_v2_cve5_dict_parsing_and_slugs(self, tmp_path):
        cache = CVECacheManager(db_path=str(tmp_path / "v2.db"))
        client = CVEApiClient(cache_manager=cache)

        assert client.extract_product_version("Server: PHP/8.1.2") == ("php", "8.1.2")
        assert client.extract_product_version("OpenSSL/1.1.1k") == ("openssl", "1.1.1k")
        assert "apache/http_server" in client._build_search_url("apache")
        assert "f5/nginx" in client._build_search_url("nginx")
        assert "microsoft/internet_information_services" in client._build_search_url("iis")

        payload = {
            "results": {
                "nvd": [
                    [
                        "cve-2026-99999",
                        {
                            "dataType": "CVE_RECORD",
                            "dataVersion": "5.2",
                            "cveMetadata": {"cveId": "CVE-2026-99999"},
                            "containers": {
                                "cna": {
                                    "descriptions": [{"lang": "en", "value": "Critical RCE in httpd range"}],
                                    "affected": [
                                        {
                                            "vendor": "Apache Software Foundation",
                                            "product": "Apache HTTP Server",
                                            "versions": [
                                                {
                                                    "status": "affected",
                                                    "version": "2.4.55",
                                                    "lessThanOrEqual": "2.4.70",
                                                }
                                            ],
                                        }
                                    ],
                                },
                                "adp": [
                                    {
                                        "metrics": [
                                            {"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                                        ]
                                    }
                                ],
                            },
                        },
                    ],
                    [
                        "cve-2026-88888",
                        {
                            "dataType": "CVE_RECORD",
                            "dataVersion": "5.2",
                            "cveMetadata": {"cveId": "CVE-2026-88888"},
                            "containers": {
                                "cna": {
                                    "descriptions": [{"lang": "en", "value": "Unaffected branch"}],
                                    "affected": [
                                        {
                                            "versions": [
                                                {
                                                    "status": "unaffected",
                                                    "version": "2.4.60",
                                                }
                                            ]
                                        }
                                    ],
                                }
                            },
                        },
                    ],
                ],
                "cvelistv5": [],
            }
        }

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp

        with patch("syn.vulnerability.api_client.urllib.request.build_opener", return_value=mock_opener):
            found = client.get_latest_cve("Apache/2.4.60 (Unix)")
            # 2.4.60 falls in 2.4.55..2.4.70 and CVE-2026-88888 has status='unaffected'
            assert found is not None
            assert found["cve"] == "CVE-2026-99999"
            assert found["risk"] == RISK_CRITICAL

            # Out-of-range version returns None cleanly
            miss = client.get_latest_cve("Apache/2.4.75 (Unix)")
            assert miss is None

        # Sibling sub-product (NGINX Unit) must never trigger false CVE on NGINX Open Source
        unit_record = {
            "id": "CVE-2025-1695",
            "summary": "NGINX Unit before 1.34.2",
            "affected": [
                {
                    "product": "NGINX Unit",
                    "versions": [{"status": "affected", "version": "0", "lessThan": "1.34.2"}],
                }
            ],
        }
        assert client._cve_matches_version(unit_record, "1.24.0", product="nginx") is False
        oss_record = {
            "id": "CVE-2024-32760",
            "summary": "NGINX OSS QUIC",
            "affected": [
                {
                    "product": "NGINX Open Source",
                    "versions": [{"status": "affected", "version": "1.25.0", "lessThan": "1.25.5"}],
                }
            ],
        }
        assert client._cve_matches_version(oss_record, "1.25.1", product="nginx") is True

    def test_tls_risk_evaluation_and_report_output(self, tmp_path):
        engine = CVEEngine(db_path=str(tmp_path / "tls.db"))
        dep_tls_row = {
            "target_ip": "127.0.0.1",
            "port": 443,
            "status": STATUS_OPEN,
            "banner": "HTTP/1.1 200 OK Date: Sat, 15 Nov Server: nginx/1.24.0 Content-Type: text/html",
            "banner_summary": "HTTP/1.1 200 OK | Server: nginx/1.24.0",
            "banner_is_fallback": False,
            "ai_os_tahmini": "Linux/64",
            "anomaly_score": 0.1,
            "web_info": {
                "is_web": True,
                "scheme": "https",
                "title": "Portal",
                "waf": "None Detected",
                "has_robots": False,
                "missing_security_headers": [],
                "tls_info": {
                    "tls_version": "TLSv1.0",
                    "cert_verified": False,
                    "tls_issue": "self-signed",
                },
            },
        }
        with patch.object(engine.api_client, "get_latest_cve", return_value=None):
            eval_dep = engine.evaluate_result(dep_tls_row)
            assert eval_dep["decision"] == RISK_HIGH
            assert "TLSv1.0" in eval_dep["Warning"]

            untrusted_only = dict(dep_tls_row)
            untrusted_only["web_info"] = dict(dep_tls_row["web_info"])
            untrusted_only["web_info"]["tls_info"] = {
                "tls_version": "TLSv1.3",
                "cert_verified": False,
                "tls_issue": "self-signed certificate",
            }
            eval_untrusted = engine.evaluate_result(untrusted_only)
            assert eval_untrusted["decision"] == RISK_LOW

            html_out = str(tmp_path / "tls.html")
            HTMLReporter().generate([dep_tls_row], engine, filename=html_out)
            html_txt = open(html_out, encoding="utf-8").read()
            assert "TLS=TLSv1.0 (Untrusted Cert)" in html_txt
            assert "HTTP/1.1 200 OK | Server: nginx/1.24.0" in html_txt

            md_out = str(tmp_path / "tls.md")
            MarkdownReporter().generate([dep_tls_row], engine, filename=md_out)
            md_txt = open(md_out, encoding="utf-8").read()
            assert "TLS=TLSv1.0 (Untrusted Cert)" in md_txt
            assert "HTTP/1.1 200 OK / Server: nginx/1.24.0" in md_txt
