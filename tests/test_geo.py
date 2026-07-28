"""Tests for geolocation module."""

from unittest.mock import patch, MagicMock

from netrecon.geo import geo_lookup, _is_private_ip


class TestIsPrivateIP:
    def test_private_10(self):
        assert _is_private_ip("10.0.0.1") is True

    def test_private_192_168(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_private_172(self):
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("172.31.0.1") is True

    def test_public_ip(self):
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("1.1.1.1") is False

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_tailscale(self):
        assert _is_private_ip("100.64.0.1") is True
        assert _is_private_ip("100.77.251.25") is True


class TestGeoLookup:
    def test_private_ip_returns_early(self):
        result = geo_lookup("192.168.1.1")
        assert result["country"] == "Private"
        assert result["source"] == "private"

    @patch("netrecon.geo.HAS_URLLIB", True)
    @patch("netrecon.geo.urllib.request.urlopen")
    def test_public_ip_lookup(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b'''{
            "status": "success",
            "country": "United States",
            "regionName": "California",
            "city": "Mountain View",
            "isp": "Google LLC",
            "lat": 37.4056,
            "lon": -122.0775
        }'''
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = geo_lookup("8.8.8.8", timeout=2)
        assert result["country"] == "United States"
        assert result["isp"] == "Google LLC"
        assert result["lat"] == 37.4056
        assert result["source"] == "ip-api"

    @patch("netrecon.geo.HAS_URLLIB", True)
    @patch("netrecon.geo.urllib.request.urlopen")
    def test_rate_limited(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "/", 429, "Too Many Requests", {}, None
        )

        result = geo_lookup("8.8.8.8", timeout=2)
        assert "error" in result