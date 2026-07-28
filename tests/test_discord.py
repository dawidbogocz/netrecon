"""Tests for Discord webhook module."""

from unittest.mock import patch, MagicMock

from netrecon.discord import send_webhook, build_alert_embed, send_host_alert


class TestBuildEmbed:
    def test_basic_embed(self):
        embed = build_alert_embed("Test Alert", "Something happened", 0x3FB950)
        assert embed["title"] == "Test Alert"
        assert embed["description"] == "Something happened"
        assert embed["color"] == 0x3FB950
        assert "timestamp" in embed

    def test_embed_with_fields(self):
        embed = build_alert_embed(
            "Scan Complete", "12 hosts found",
            fields=[{"name": "Hosts", "value": "12", "inline": True}],
        )
        assert len(embed["fields"]) == 1

    def test_embed_with_footer(self):
        embed = build_alert_embed("Test", "Desc", footer="netrecon")
        assert embed["footer"]["text"] == "netrecon"


class TestSendWebhook:
    @patch("netrecon.discord.HAS_URLLIB", True)
    @patch("netrecon.discord.urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 204
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = send_webhook(
            "https://discord.com/api/webhooks/test",
            content="Hello",
        )
        assert result is True

    @patch("netrecon.discord.HAS_URLLIB", True)
    @patch("netrecon.discord.urllib.request.urlopen")
    def test_failure(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "/", 400, "Bad Request", {}, None
        )

        result = send_webhook(
            "https://discord.com/api/webhooks/test",
            content="Hello",
        )
        assert result is False


class TestSendHostAlert:
    @patch("netrecon.discord.send_webhook")
    def test_join_alert(self, mock_send):
        mock_send.return_value = True
        result = send_host_alert(
            "https://discord.com/api/webhooks/test",
            "join", "192.168.1.1", hostname="laptop",
        )
        assert result is True

    @patch("netrecon.discord.send_webhook")
    def test_leave_alert(self, mock_send):
        mock_send.return_value = True
        result = send_host_alert(
            "https://discord.com/api/webhooks/test",
            "leave", "192.168.1.1",
        )
        assert result is True

    @patch("netrecon.discord.send_webhook")
    def test_scan_complete(self, mock_send):
        mock_send.return_value = True
        result = send_host_alert(
            "https://discord.com/api/webhooks/test",
            "scan_complete", "",
            details="12 hosts online",
        )
        assert result is True