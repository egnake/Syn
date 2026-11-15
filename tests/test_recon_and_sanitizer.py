import asyncio
import json
from unittest.mock import MagicMock, patch
import pytest

from syn.core.sanitizer import (
    escape_html,
    escape_markdown_cell,
    sanitize_terminal_text,
    strip_control_chars,
    validate_port_range,
)
from syn.recon.host_discovery import HostDiscovery
from syn.recon.subdomain_enum import SubdomainEnum
from syn.recon.target_parser import TargetParser


class TestSanitizer:
    def test_strip_ansi_and_control_chars(self):
        dirty = "Banner\x1b[31mRED\x1b[0m\x07\x00\nLine2"
        assert strip_control_chars(dirty) == "BannerRED Line2"

    def test_sanitize_terminal_escapes_rich_markup(self):
        malicious = "[/bold red][red]FAKE[/red]\x1b[2J"
        safe = sanitize_terminal_text(malicious)
        assert "\x1b" not in safe
        assert "\\[/bold red]" in safe

    def test_escape_html_includes_quotes(self):
        payload = "<script>alert('xss' & \"y\")</script>"
        escaped = escape_html(payload)
        assert "<" not in escaped
        assert ">" not in escaped
        assert "&#x27;" in escaped
        assert "&quot;" in escaped

    def test_escape_markdown_cell_blocks_injection(self):
        payload = "srv` <img src=x> | [link]\nnext"
        escaped = escape_markdown_cell(payload)
        assert "`" not in escaped
        assert "<" not in escaped
        assert "|" not in escaped
        assert "\n" not in escaped

    @pytest.mark.parametrize("start,end", [(0, 80), (-1, 10), (1, 65536), (500, 100)])
    def test_validate_port_range_rejects_invalid(self, start, end):
        with pytest.raises(ValueError):
            validate_port_range(start, end)

    def test_validate_port_range_valid(self):
        assert validate_port_range(1, 65535) == (1, 65535)


class TestTargetParser:
    def test_ipv4_and_single_host_cidr(self):
        assert TargetParser.parse_target_with_hosts("192.168.1.5") == ([("192.168.1.5", "192.168.1.5")], "IP")
        assert TargetParser.parse_target_with_hosts("192.168.1.5/32") == ([("192.168.1.5", "192.168.1.5")], "IP")

    def test_ipv6_and_bracketed_url(self):
        assert TargetParser.parse_target_with_hosts("::1") == ([(" ::1".strip(), "::1")], "IP")
        assert TargetParser.parse_target_with_hosts("http://[::1]:8080/admin") == ([(" ::1".strip(), "::1")], "IP")

    def test_url_with_ip_stays_ip(self):
        pairs, ttype = TargetParser.parse_target_with_hosts("HTTP://127.0.0.1:8080/test?a=1#frag")
        assert pairs == [("127.0.0.1", "127.0.0.1")]
        assert ttype == "IP"

    def test_domain_url_preserves_hostname(self):
        with patch("syn.recon.target_parser.TargetParser.resolve_domain", return_value="93.184.216.34"):
            pairs, ttype = TargetParser.parse_target_with_hosts("HTTPS://EXAMPLE.COM:8443/login")
            assert pairs == [("93.184.216.34", "example.com")]
            assert ttype == "DOMAIN"

    def test_localhost_is_local_not_domain(self):
        with patch("syn.recon.target_parser.TargetParser.resolve_domain", return_value="127.0.0.1"):
            pairs, ttype = TargetParser.parse_target_with_hosts("localhost")
            assert pairs == [("127.0.0.1", "localhost")]
            assert ttype == "LOCAL"

    def test_huge_cidr_blocked(self):
        with pytest.raises(ValueError):
            TargetParser.parse_target_with_hosts("10.0.0.0/8")

    def test_unknown_target(self):
        with patch("syn.recon.target_parser.TargetParser.resolve_domain", return_value=""):
            assert TargetParser.parse_target_with_hosts("nonexistent.invalid") == ([], "UNKNOWN")


class TestHostDiscovery:
    def test_connection_refused_marks_host_alive(self):
        hd = HostDiscovery()

        async def fake_open(ip, port):
            if ip == "10.0.0.2":
                raise ConnectionRefusedError()
            raise asyncio.TimeoutError()

        with patch("syn.recon.host_discovery.asyncio.open_connection", side_effect=fake_open):
            alive = asyncio.run(hd.discover_live_hosts(["10.0.0.1", "10.0.0.2"]))
        assert alive == ["10.0.0.2"]


class TestSubdomainEnum:
    def test_rejects_invalid_domain(self):
        assert SubdomainEnum.query_crt_sh("127.0.0.1") == []
        assert SubdomainEnum.query_crt_sh("evil.com&x=1") == []

    def test_dot_boundary_and_deterministic_sort(self):
        payload = json.dumps(
            [
                {"name_value": "b.example.com\n*.example.com\nbadexample.com\na.example.com"},
            ]
        ).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = payload
        mock_resp.__enter__.return_value = mock_resp

        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp

        with patch("syn.recon.subdomain_enum.urllib.request.build_opener", return_value=mock_opener):
            subs = SubdomainEnum.query_crt_sh("example.com")

        assert subs == ["a.example.com", "b.example.com"]
        assert "badexample.com" not in subs
