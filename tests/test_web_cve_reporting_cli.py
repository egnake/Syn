from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys
import threading
from unittest.mock import MagicMock, patch
import pytest
from scapy.all import TCP

from syn.cli import main as cli_main
from syn.core.config import (
    RISK_CRITICAL,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_NONE,
    STATUS_CLOSED,
    STATUS_OPEN,
    STATUS_OPEN_FILTERED,
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
