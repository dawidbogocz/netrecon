"""Tests for the port scanner module."""

from unittest.mock import patch, MagicMock

import pytest

from netrecon.scan import (
    tcp_connect_scan,
    syn_scan,
    parse_ports,
    resolve_service,
    COMMON_PORTS,
)


class TestParsePorts:
    """Tests for parse_ports function."""

    def test_single_ports(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_port_range(self):
        result = parse_ports("1-10")
        assert result == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

    def test_mixed(self):
        result = parse_ports("22,80,443,8000-8010")
        assert 22 in result
        assert 80 in result
        assert 443 in result
        assert 8000 in result
        assert 8010 in result
        assert len(result) == 3 + 11  # 3 singles + 11 range

    def test_top_100(self):
        result = parse_ports("top-100")
        assert len(result) <= 100
        assert 22 in result
        assert 443 in result

    def test_empty_returns_common(self):
        result = parse_ports("")
        assert result == COMMON_PORTS

    def test_duplicates_removed(self):
        result = parse_ports("22,22,80,80")
        assert result == [22, 80]

    def test_port_range_reversed(self):
        result = parse_ports("10-5")  # empty range
        assert 5 not in result
        assert 10 not in result


class TestResolveService:
    """Tests for resolve_service function."""

    def test_common_ports(self):
        assert resolve_service(22) == "ssh"
        assert resolve_service(80) == "http"
        assert resolve_service(443) == "https"

    def test_unknown_port(self):
        result = resolve_service(99999)
        assert isinstance(result, str)

    def test_common_ports_dict(self):
        assert resolve_service(3389) == "ms-wbt-server"
        assert resolve_service(5432) == "postgresql"


class TestTcpConnectScan:
    """Tests for tcp_connect_scan function."""

    @patch("socket.socket")
    def test_open_ports(self, mock_socket):
        """Should detect open ports."""
        mock_instance = MagicMock()
        mock_instance.connect_ex.return_value = 0  # 0 = success
        mock_socket.return_value = mock_instance

        results = tcp_connect_scan("192.168.1.1", ports=[22, 80, 443], timeout=0.5)

        assert len(results) == 3
        for r in results:
            assert r["state"] == "open"

    @patch("socket.socket")
    def test_closed_ports(self, mock_socket):
        """Should detect closed ports."""
        mock_instance = MagicMock()
        mock_instance.connect_ex.return_value = 111  # ECONNREFUSED
        mock_socket.return_value = mock_instance

        results = tcp_connect_scan("192.168.1.1", ports=[22, 80], timeout=0.5)

        for r in results:
            assert r["state"] == "closed"

    @patch("socket.socket")
    def test_filtered_ports(self, mock_socket):
        """Should detect filtered ports (timeout)."""
        mock_instance = MagicMock()
        mock_instance.connect_ex.return_value = 110  # ETIMEDOUT
        mock_socket.return_value = mock_instance

        results = tcp_connect_scan("192.168.1.1", ports=[22], timeout=0.5)

        assert results[0]["state"] == "filtered"

    def test_no_ports_specified_uses_default(self):
        """Should use COMMON_PORTS when no ports specified."""
        with patch("netrecon.scan._tcp_connect_port") as mock_scan:
            mock_scan.return_value = {"port": 22, "state": "open", "service": "ssh"}
            results = tcp_connect_scan("192.168.1.1", timeout=0.5)
            assert len(results) == len(COMMON_PORTS)


class TestSynScan:
    """Tests for syn_scan function."""

    def test_fallback_when_no_scapy(self):
        """Should fall back to connect scan when scapy unavailable."""
        with patch("netrecon.scan.HAS_SCAPY", False):
            with patch("netrecon.scan.tcp_connect_scan") as mock_connect:
                mock_connect.return_value = [{"port": 22, "state": "open", "service": "ssh"}]
                results = syn_scan("192.168.1.1", ports=[22], timeout=0.5)
                assert results[0]["port"] == 22
                mock_connect.assert_called_once()