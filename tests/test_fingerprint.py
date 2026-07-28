"""Tests for the OS fingerprinting module."""

from unittest.mock import patch, MagicMock

import pytest

from netrecon.fingerprint import (
    fingerprint_os,
    _match_signature,
    _get_ttl_from_ping,
)


class TestMatchSignature:
    """Tests for _match_signature function."""

    def test_linux_signature(self):
        result, confidence = _match_signature(64, 65535)
        assert result == "Linux"
        assert confidence >= 80

    def test_windows_signature(self):
        result, confidence = _match_signature(128, 65535)
        assert result == "Windows 10/11/Server"
        assert confidence >= 80

    def test_macos_signature(self):
        result, confidence = _match_signature(64, 65535)
        assert result == "Linux"  # Linux and macOS share same TTL/window
        assert confidence >= 80

    def test_cisco_signature(self):
        result, confidence = _match_signature(255, 4128)
        assert result == "Cisco IOS"
        assert confidence >= 80

    def test_unknown_ttl(self):
        result, confidence = _match_signature(1, 1000)
        assert result == "Unknown"
        assert confidence == 0

    def test_no_ttl(self):
        result, confidence = _match_signature(None, None)
        assert result == "Unknown"
        assert confidence == 0

    def test_solaris_signature(self):
        result, confidence = _match_signature(255, 8760)
        assert result == "Solaris"


class TestFingerprintOS:
    """Tests for fingerprint_os function."""

    @patch("netrecon.fingerprint._get_tcp_fingerprint")
    def test_linux_detected(self, mock_tcp_fp):
        """Should detect Linux from TCP SYN-ACK."""
        mock_tcp_fp.return_value = (64, 65535)

        result = fingerprint_os("192.168.1.1", timeout=1.0)

        assert result["os_guess"] == "Linux"
        assert result["confidence"] >= 80
        assert result["ttl"] == 64
        assert result["window_size"] == 65535
        assert result["method"] == "tcp_syn"

    @patch("netrecon.fingerprint._get_tcp_fingerprint")
    def test_windows_detected(self, mock_tcp_fp):
        """Should detect Windows from TCP SYN-ACK."""
        mock_tcp_fp.return_value = (128, 65535)

        result = fingerprint_os("192.168.1.1", timeout=1.0)

        assert "Windows" in result["os_guess"]
        assert result["confidence"] >= 80

    @patch("netrecon.fingerprint._get_tcp_fingerprint")
    def test_host_unreachable(self, mock_tcp_fp):
        """Should return Unknown when host doesn't respond."""
        mock_tcp_fp.return_value = (None, None)
        with patch("netrecon.fingerprint._get_ttl_from_ping", return_value=None):
            result = fingerprint_os("192.168.1.1", timeout=1.0)

            assert result["os_guess"] == "Unknown"
            assert result["confidence"] == 0
            assert result["method"] == "unreachable"

    def test_get_ttl_from_ping_found(self):
        """Should extract TTL from ping output."""
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.stdout = "64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=12.3 ms"
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            ttl = _get_ttl_from_ping("8.8.8.8", 2.0)
            assert ttl == 117

    def test_get_ttl_from_ping_not_found(self):
        """Should return None when ping fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError

            ttl = _get_ttl_from_ping("192.168.1.1", 1.0)
            assert ttl is None