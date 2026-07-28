"""Tests for the ping sweep module."""

from unittest.mock import patch, MagicMock

import pytest

from netrecon.ping import ping_sweep


class TestPingSweep:
    """Test suite for ping_sweep function."""

    @patch("netrecon.ping._ping_host")
    def test_ping_sweep_some_responsive(self, mock_ping_host):
        """Should return responsive IPs when some hosts reply."""
        def side_effect(ip, timeout, use_scapy):
            return ip in ("192.168.1.1", "192.168.1.10")

        mock_ping_host.side_effect = side_effect

        result = ping_sweep("192.168.1.0/28", timeout=0.5, workers=10)

        assert isinstance(result, list)
        assert "192.168.1.1" in result
        assert "192.168.1.10" in result
        assert "192.168.1.2" not in result

    @patch("netrecon.ping._ping_host")
    def test_ping_sweep_no_responsive(self, mock_ping_host):
        """Should return empty list when no hosts respond."""
        mock_ping_host.return_value = False

        result = ping_sweep("192.168.1.0/30", timeout=0.5, workers=10)

        assert isinstance(result, list)
        assert len(result) == 0

    @patch("netrecon.ping._ping_host")
    def test_ping_sweep_all_responsive(self, mock_ping_host):
        """Should return all hosts when all respond."""
        mock_ping_host.return_value = True

        result = ping_sweep("192.168.1.0/29", timeout=0.5, workers=10)

        assert len(result) == 6  # /29 = 6 host addresses

    @patch("netrecon.ping.HAS_SCAPY", False)
    @patch("netrecon.ping._ping_host_subprocess")
    def test_ping_sweep_fallback_subprocess(self, mock_subprocess):
        """Should fall back to subprocess ping when scapy is unavailable."""
        mock_subprocess.return_value = True

        result = ping_sweep("192.168.1.0/30", timeout=0.5, workers=5)

        assert len(result) > 0
        assert mock_subprocess.call_count > 0