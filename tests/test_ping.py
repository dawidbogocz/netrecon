"""Tests for the ping sweep module."""

from unittest.mock import patch, MagicMock

import pytest

from netrecon.ping import ping_sweep, parse_target


class TestParseTarget:
    """Tests for parse_target function."""

    def test_cidr(self):
        ips = parse_target("192.168.1.0/30")
        assert ips == ["192.168.1.1", "192.168.1.2"]

    def test_range_partial(self):
        ips = parse_target("192.168.0.1-5")
        assert ips == ["192.168.0.1", "192.168.0.2", "192.168.0.3", "192.168.0.4", "192.168.0.5"]

    def test_range_full(self):
        ips = parse_target("192.168.0.5-192.168.0.7")
        assert ips == ["192.168.0.5", "192.168.0.6", "192.168.0.7"]

    def test_range_auto_swap(self):
        """Should swap start/end if reversed."""
        ips = parse_target("192.168.0.10-192.168.0.5")
        assert ips == ["192.168.0.5", "192.168.0.6", "192.168.0.7", "192.168.0.8", "192.168.0.9", "192.168.0.10"]

    def test_range_larger(self):
        ips = parse_target("192.168.0.1-200")
        assert len(ips) == 200
        assert ips[0] == "192.168.0.1"
        assert ips[-1] == "192.168.0.200"

    def test_single_ip(self):
        ips = parse_target("192.168.0.1")
        assert ips == ["192.168.0.1"]

    def test_invalid(self):
        with pytest.raises(ValueError):
            parse_target("not-a-valid-target")


class TestPingSweep:
    """Test suite for ping_sweep function."""

    @patch("netrecon.ping._ping_host")
    def test_ping_sweep_cidr(self, mock_ping_host):
        """Should work with CIDR format."""
        mock_ping_host.side_effect = lambda ip, t, u: ip == "192.168.1.1"

        result = ping_sweep("192.168.1.0/30", timeout=0.5, workers=5)

        assert "192.168.1.1" in result
        assert "192.168.1.2" not in result

    @patch("netrecon.ping._ping_host")
    def test_ping_sweep_range(self, mock_ping_host):
        """Should work with range format."""
        mock_ping_host.side_effect = lambda ip, t, u: ip in ("192.168.0.5", "192.168.0.10")

        result = ping_sweep("192.168.0.1-10", timeout=0.5, workers=5)

        assert "192.168.0.5" in result
        assert "192.168.0.10" in result
        assert "192.168.0.1" not in result
        assert len(result) == 2

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

        result = ping_sweep("192.168.0.1-5", timeout=0.5, workers=5)

        assert len(result) > 0
        assert mock_subprocess.call_count > 0