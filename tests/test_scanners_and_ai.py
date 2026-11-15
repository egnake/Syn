import json
import socket
import threading
from unittest.mock import patch
import warnings
from scapy.all import ICMP, IP, TCP

from syn.ai.analyzer import AIAnalyzer
from syn.ai.model_manager import ModelManager
from syn.core.config import (
    ANOMALY_THRESHOLD,
    SERVICE_PROBES,
    STATUS_CLOSED,
    STATUS_ERROR,
    STATUS_FILTERED,
    STATUS_OPEN,
    STATUS_UNFILTERED,
)
from syn.scanner.async_scanner import AsyncScanner
from syn.scanner.banner_grabber import BannerGrabber
from syn.scanner.service_identifier import ServiceIdentifier
from syn.scanner.stealth_scanner import StealthScanner


def _find_unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestAsyncScanner:
    def test_local_open_and_closed_ports(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        open_port = srv.getsockname()[1]
        closed_port = _find_unused_port()

        def handle_conn():
            try:
                conn, _ = srv.accept()
                conn.sendall(b"220 TestBanner\r\n")
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=handle_conn, daemon=True)
        t.start()
        try:
            low, high = min(open_port, closed_port), max(open_port, closed_port)
            # Scan individually to keep test deterministic & fast
            res_open = AsyncScanner("127.0.0.1", open_port, open_port).scan()[0]
            res_closed = AsyncScanner("127.0.0.1", closed_port, closed_port).scan()[0]
            assert res_open["status"] == STATUS_OPEN
            assert res_open["latency_ms"] >= 0
            assert "220 TestBanner" in res_open["banner"]
            assert res_closed["status"] == STATUS_CLOSED
        finally:
            srv.close()
            t.join(timeout=1.0)

    def test_timeout_reports_filtered_not_closed(self):
        async def hang(*args, **kwargs):
            await asyncio_sleep(10)

        import asyncio
        asyncio_sleep = asyncio.sleep
        with patch("syn.scanner.async_scanner.asyncio.open_connection", side_effect=asyncio.TimeoutError()):
            res = AsyncScanner("127.0.0.1", 80, 80, timeout=0.05).scan()[0]
            assert res["status"] == STATUS_FILTERED


class TestStealthScanner:
    def test_error_in_sr1_never_becomes_open_filtered(self):
        sc = StealthScanner("127.0.0.1", 80, 80, scan_type="F")
        with patch("syn.scanner.stealth_scanner.sr1", side_effect=PermissionError("no root")):
            res = sc.scan()
        assert len(res) == 1
        assert res[0]["status"] == STATUS_ERROR

    def test_syn_scan_icmp_response_no_index_error(self):
        sc = StealthScanner("127.0.0.1", 80, 80, scan_type="S")
        icmp_pkt = IP(src="127.0.0.1", dst="127.0.0.1", ttl=64) / ICMP(type=3, code=13)
        with patch("syn.scanner.stealth_scanner.sr1", return_value=icmp_pkt):
            res = sc.scan()
        assert res[0]["status"] == STATUS_FILTERED
        assert res[0]["tcp_flags"] is None

    def test_syn_scan_ecn_synack_and_pure_rst(self):
        sc = StealthScanner("127.0.0.1", 80, 81, scan_type="S")
        syn_ack_ece = IP(src="127.0.0.1", dst="127.0.0.1", ttl=128) / TCP(sport=80, dport=40000, flags="SAE", seq=123)
        pure_rst = IP(src="127.0.0.1", dst="127.0.0.1", ttl=128) / TCP(sport=81, dport=40001, flags="R")

        def fake_sr1(pkt, **kwargs):
            return syn_ack_ece if pkt[TCP].dport == 80 else pure_rst

        with patch("syn.scanner.stealth_scanner.sr1", side_effect=fake_sr1), patch(
            "syn.scanner.stealth_scanner.send"
        ) as mock_send:
            res = sc.scan()

        by_port = {r["port"]: r for r in res}
        assert by_port[80]["status"] == STATUS_OPEN
        assert isinstance(by_port[80]["tcp_flags"], int)
        json.dumps(by_port[80])  # Must be JSON serializable (no FlagValue!)
        assert mock_send.called
        assert by_port[81]["status"] == STATUS_CLOSED

    def test_ack_scan_statuses(self):
        sc = StealthScanner("127.0.0.1", 80, 81, scan_type="A")
        rst = IP(src="127.0.0.1", dst="127.0.0.1", ttl=64) / TCP(flags="R")
        with patch("syn.scanner.stealth_scanner.sr1", side_effect=[rst, None]):
            res = sc.scan()
        statuses = {r["status"] for r in res}
        assert statuses == {STATUS_UNFILTERED, STATUS_FILTERED}


class TestBannerGrabberAndServiceId:
    def test_rdp_probe_is_valid_19_bytes(self):
        rdp_probe = SERVICE_PROBES[3389][0]
        assert isinstance(rdp_probe, bytes)
        assert len(rdp_probe) == 19
        assert rdp_probe[5] == 0xE0

    def test_no_eval_in_banner_grabber_source(self):
        import syn.scanner.banner_grabber as bg
        src = open(bg.__file__, encoding="utf-8").read()
        assert "eval(" not in src

    def test_banner_grabber_strips_ansi_and_supports_batch(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]

        def handle():
            try:
                conn, _ = srv.accept()
                conn.sendall(b"220 \x1b[31mTestFTP\x1b[0m\r\n")
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=handle, daemon=True)
        t.start()
        try:
            banners = BannerGrabber("127.0.0.1").get_banners([port])
            assert banners[port] == "220 TestFTP"
        finally:
            srv.close()
            t.join(timeout=1.0)

    def test_service_identifier_protocols_and_no_false_web(self):
        assert ServiceIdentifier.identify(80, "HTTP/2 200 OK")["is_web"] is True
        assert ServiceIdentifier.identify(80, "<html lang='en'><body>hi</body></html>")["is_web"] is True
        assert ServiceIdentifier.identify(3306, "5.5.5-10.11.6-MariaDB")["service_name"] == "MySQL"
        smtp_res = ServiceIdentifier.identify(25, "220 mail.example.com ESMTP Mail Server: ready")
        assert smtp_res["service_name"] == "SMTP"
        assert smtp_res["is_web"] is False


class TestAIModelsAndAnalyzer:
    def test_tampered_model_triggers_retrain(self, tmp_path):
        mm = ModelManager(models_dir=str(tmp_path))
        mm.load_or_train_models()
        # Corrupt/tamper classifier artifact
        with open(mm.classifier_file, "wb") as f:
            f.write(b"tampered")
        assert mm._verify_integrity() is False
        clf, lof, scaler = mm.load_or_train_models()
        assert mm._verify_integrity() is True
        assert clf is not None and lof is not None and scaler is not None

    def test_analyzer_skips_missing_ttl_and_avoids_false_linux_and_warnings(self):
        mm = ModelManager()
        clf, lof, scaler = mm.load_or_train_models()
        analyzer = AIAnalyzer(clf, lof, scaler)

        sample = [
            {"port": 445, "status": STATUS_OPEN, "ttl": -1, "latency_ms": 2.5, "banner": ""},
            {"port": 80, "status": STATUS_OPEN, "ttl": 128, "latency_ms": 300.0, "banner": "IIS"},
            {"port": 99, "status": STATUS_OPEN, "ttl": 10, "latency_ms": 5000.0, "banner": "odd"},
        ]
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            out = analyzer.analyze(sample)

        user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
        assert user_warnings == []

        # ASYNC ttl=-1 must NOT guess Linux/64 and must NOT erase latency_ms!
        assert out[0]["ai_os_tahmini"] == "Unknown (No TTL)"
        assert out[0]["anomaly_score"] is None
        assert out[0]["latency_ms"] == 2.5

        # Normal WAN Windows latency (300ms) must NOT falsely trip anomaly threshold
        assert out[1]["ai_os_tahmini"] == "Windows/128"
        assert out[1]["anomaly_score"] >= ANOMALY_THRESHOLD

        # Extreme outlier triggers anomaly detection
        assert out[2]["anomaly_score"] < ANOMALY_THRESHOLD
