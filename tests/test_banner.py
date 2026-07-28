"""Tests for the banner grabber module."""

import socket
from unittest.mock import patch, MagicMock

import pytest

from netrecon.banner import grab_banners, _get_probe, _guess_service_from_banner, HTTP_PROBE


class TestGetProbe:
    """Tests for _get_probe function."""

    def test_http_port(self):
        assert _get_probe(80) == HTTP_PROBE
        assert _get_probe(8080) == HTTP_PROBE

    def test_default_probe(self):
        assert _get_probe(22) == b"\r\n"
        assert _get_probe(9999) == b"\r\n"


class TestGuessServiceFromBanner:
    """Tests for _guess_service_from_banner function."""

    def test_ssh_detection(self):
        assert _guess_service_from_banner("SSH-2.0-OpenSSH_9.0", 22) == "ssh"

    def test_http_detection(self):
        assert _guess_service_from_banner("HTTP/1.1 200 OK", 80) == "http"
        assert _guess_service_from_banner("Server: nginx", 443) == "http"

    def test_unknown_banner(self):
        assert _guess_service_from_banner("Some random text", 1234) == ""

    def test_smtp_detection(self):
        assert _guess_service_from_banner("220 mail.example.com ESMTP", 25) == "smtp"


class TestGrabBanners:
    """Tests for grab_banners function."""

    @patch("socket.socket")
    def test_banner_found(self, mock_socket):
        """Should return banner when server responds."""
        mock_instance = MagicMock()
        mock_instance.recv.side_effect = [b"SSH-2.0-OpenSSH_9.0\r\n", b""]
        mock_socket.return_value = mock_instance

        results = grab_banners("192.168.1.1", ports=[22], timeout=1.0)

        assert len(results) == 1
        assert results[0]["port"] == 22
        assert "OpenSSH" in results[0]["banner"]
        assert results[0]["service"] == "ssh"

    @patch("socket.socket")
    def test_no_banner(self, mock_socket):
        """Should return empty banner when no data."""
        mock_instance = MagicMock()
        mock_instance.recv.side_effect = [b""]
        mock_socket.return_value = mock_instance

        results = grab_banners("192.168.1.1", ports=[80], timeout=1.0)

        assert len(results) == 1
        assert results[0]["banner"] == ""

    @patch("socket.socket")
    def test_connection_refused(self, mock_socket):
        """Should handle connection refused gracefully."""
        mock_instance = MagicMock()
        mock_instance.connect.side_effect = ConnectionRefusedError
        mock_socket.return_value = mock_instance

        results = grab_banners("192.168.1.1", ports=[22], timeout=1.0)

        assert len(results) == 1
        assert results[0]["banner"] == ""

    @patch("socket.socket")
    def test_timeout(self, mock_socket):
        """Should handle socket timeout gracefully."""
        mock_instance = MagicMock()
        mock_instance.connect.side_effect = socket.timeout
        mock_socket.return_value = mock_instance

        results = grab_banners("192.168.1.1", ports=[22], timeout=1.0)

        assert len(results) == 1
        assert results[0]["banner"] == ""

    @patch("socket.socket")
    def test_multiple_ports(self, mock_socket):
        """Should grab banners from multiple ports."""
        mock_instance = MagicMock()
        mock_instance.recv.side_effect = [
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\n", b"",
            b"220 mail ESMTP\r\n", b"",
            b"",  # no banner for port 3
        ]
        mock_socket.return_value = mock_instance

        results = grab_banners("192.168.1.1", ports=[80, 25, 443], timeout=1.0, workers=3)

        assert len(results) == 3
        banners = {r["port"]: r for r in results}
        assert banners[80]["banner"]
        assert banners[25]["banner"]
        assert not banners[443]["banner"]