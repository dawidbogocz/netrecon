"""Tests for DNS module."""

from unittest.mock import patch, MagicMock

from netrecon.dns import dns_lookup, dns_reverse, dns_enum


class TestLookup:
    @patch("netrecon.dns.HAS_DNSPYTHON", True)
    @patch("netrecon.dns.dns.resolver.resolve")
    def test_a_record(self, mock_resolve):
        mock_ans = MagicMock()
        mock_ans.address = "93.184.216.34"
        mock_ans.__str__ = MagicMock(return_value="93.184.216.34")
        mock_rrset = MagicMock()
        mock_rrset.ttl = 300
        mock_resolve.return_value.rrset = mock_rrset
        mock_resolve.return_value.__iter__.return_value = iter([mock_ans])

        result = dns_lookup("example.com", timeout=2)

        assert "A" in result
        assert result["A"][0][0] == "93.184.216.34"

    @patch("netrecon.dns.HAS_DNSPYTHON", True)
    @patch("netrecon.dns.dns.resolver.resolve")
    def test_mx_record(self, mock_resolve):
        mock_ans = type("MockAns", (), {"preference": 10, "exchange": "mail.example.com."})()
        mock_rrset = type("MockRRset", (), {"ttl": 300})()
        mock_resolve.return_value.rrset = mock_rrset
        mock_resolve.return_value.__iter__.return_value = [mock_ans]

        result = dns_lookup("example.com", timeout=2)

        assert "MX" in result
        assert "10 mail.example.com." in result["MX"][0][0]

    @patch("netrecon.dns.HAS_DNSPYTHON", True)
    @patch("netrecon.dns.dns.resolver.resolve")
    def test_no_records(self, mock_resolve):
        mock_resolve.side_effect = type("Err", (Exception,), {})("NXDOMAIN")
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NXDOMAIN

        result = dns_lookup("nonexistent.example.com", timeout=2)
        assert len(result) == 0


class TestReverse:
    @patch("netrecon.dns.HAS_DNSPYTHON", True)
    @patch("netrecon.dns.dns.reversename.from_address")
    @patch("netrecon.dns.dns.resolver.resolve")
    def test_reverse_found(self, mock_resolve, mock_revname):
        mock_ans = MagicMock()
        mock_ans.__str__ = MagicMock(return_value="dns.google.")
        mock_resolve.return_value = [mock_ans]
        mock_revname.return_value = "8.8.8.8.in-addr.arpa"

        result = dns_reverse("8.8.8.8", timeout=2)
        assert result == "dns.google."

    @patch("netrecon.dns.HAS_DNSPYTHON", True)
    @patch("netrecon.dns.dns.reversename.from_address")
    @patch("netrecon.dns.dns.resolver.resolve")
    def test_reverse_not_found(self, mock_resolve, mock_revname):
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        mock_revname.return_value = "1.1.1.1.in-addr.arpa"

        result = dns_reverse("1.1.1.1", timeout=2)
        assert result is None


class TestEnum:
    @patch("netrecon.dns.SUBDOMAIN_WORDLIST", ["www"])
    @patch("netrecon.dns.HAS_DNSPYTHON", True)
    @patch("netrecon.dns.dns.resolver.resolve")
    def test_found_subdomain(self, mock_resolve):
        mock_ans = type("MockAns", (), {})()
        mock_ans.address = "93.184.216.34"
        mock_resolve.return_value.__iter__.return_value = [mock_ans]

        results = dns_enum("example.com", timeout=1, workers=1)
        assert len(results) == 1
        assert results[0]["subdomain"] == "www"
        assert results[0]["full_domain"] == "www.example.com"

    @patch("netrecon.dns.SUBDOMAIN_WORDLIST", ["doesnotexist"])
    @patch("netrecon.dns.HAS_DNSPYTHON", True)
    @patch("netrecon.dns.dns.resolver.resolve")
    def test_no_subdomain(self, mock_resolve):
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NXDOMAIN

        results = dns_enum("example.com", timeout=1, workers=1)
        assert len(results) == 0