"""Tests for the Phishing URL Analyzer module."""

from unittest.mock import patch

import pytest

from netrecon.phish import (
    analyze_url,
    _check_suspicious_tld,
    _check_url_shortener,
    _check_at_symbol,
    _check_excessive_subdomains,
    _check_typosquatting,
    _check_ip_hostname,
    _get_risk_level,
)


class TestRiskLevel:
    """Tests for _get_risk_level function."""

    def test_safe(self):
        assert _get_risk_level(0) == "Safe"
        assert _get_risk_level(20) == "Safe"

    def test_suspicious(self):
        assert _get_risk_level(21) == "Suspicious"
        assert _get_risk_level(50) == "Suspicious"

    def test_likely_phishing(self):
        assert _get_risk_level(51) == "Likely Phishing"
        assert _get_risk_level(80) == "Likely Phishing"

    def test_confirmed_phishing(self):
        assert _get_risk_level(81) == "Confirmed Phishing"
        assert _get_risk_level(100) == "Confirmed Phishing"


class TestCheckSuspiciousTLD:
    """Tests for _check_suspicious_tld."""

    def test_suspicious_tld_detected(self):
        parsed = {"hostname": "login.secure-paypal.tk"}
        result = _check_suspicious_tld(parsed)
        assert result.passed is True
        assert result.score == 10  # 10 from hostname, 15 if in @ redirect path

    def test_normal_tld(self):
        parsed = {"hostname": "www.google.com"}
        result = _check_suspicious_tld(parsed)
        assert result.passed is False
        assert result.score == 0


class TestCheckURLShortener:
    """Tests for _check_url_shortener."""

    def test_shortener_detected(self):
        parsed = {"hostname": "bit.ly"}
        result = _check_url_shortener(parsed)
        assert result.passed is True
        assert result.score == 15

    def test_not_a_shortener(self):
        parsed = {"hostname": "github.com"}
        result = _check_url_shortener(parsed)
        assert result.passed is False
        assert result.score == 0


class TestCheckAtSymbol:
    """Tests for _check_at_symbol."""

    def test_at_symbol_present(self):
        parsed = {"full": "http://legitimate.com@evil.com/login"}
        result = _check_at_symbol(parsed)
        assert result.passed is True
        assert result.score == 10

    def test_no_at_symbol(self):
        parsed = {"full": "https://www.google.com"}
        result = _check_at_symbol(parsed)
        assert result.passed is False
        assert result.score == 0


class TestCheckExcessiveSubdomains:
    """Tests for _check_excessive_subdomains."""

    def test_excessive_subdomains(self):
        parsed = {"hostname": "a.b.c.d.e.f.evil.com"}
        result = _check_excessive_subdomains(parsed)
        assert result.passed is True
        assert result.score == 10

    def test_normal_subdomains(self):
        parsed = {"hostname": "www.google.com"}
        result = _check_excessive_subdomains(parsed)
        assert result.passed is False
        assert result.score == 0


class TestCheckTyposquatting:
    """Tests for _check_typosquatting."""

    def test_typosquatting_google(self):
        parsed = {"hostname": "gooogle.com"}
        result = _check_typosquatting(parsed)
        assert result.passed is True
        assert result.score == 15
        assert "google" in result.detail.lower()

    def test_typosquatting_paypal(self):
        parsed = {"hostname": "paypall.com"}
        result = _check_typosquatting(parsed)
        assert result.passed is True

    def test_no_typosquatting(self):
        parsed = {"hostname": "my-legitimate-site.com"}
        result = _check_typosquatting(parsed)
        assert result.passed is False
        assert result.score == 0


class TestCheckIPHostname:
    """Tests for _check_ip_hostname."""

    def test_ipv4_address(self):
        parsed = {"hostname": "192.168.1.1"}
        result = _check_ip_hostname(parsed)
        assert result.passed is True
        assert result.score == 10

    def test_domain_name(self):
        parsed = {"hostname": "www.google.com"}
        result = _check_ip_hostname(parsed)
        assert result.passed is False
        assert result.score == 0


class TestAnalyzeURL:
    """Integration tests for analyze_url function."""

    @patch("netrecon.phish._check_domain_age")
    @patch("netrecon.phish._check_https_validity")
    def test_safe_url(self, mock_https, mock_age):
        """A normal URL should get a low risk score."""
        mock_https.return_value.score = 0
        mock_https.return_value.max_score = 10
        mock_https.return_value.passed = False
        mock_https.return_value.detail = "Valid HTTPS cert"
        mock_https.return_value.name = "HTTPS Validity"

        mock_age.return_value.score = 0
        mock_age.return_value.max_score = 15
        mock_age.return_value.passed = False
        mock_age.return_value.detail = "Domain is old"
        mock_age.return_value.name = "Domain Age"

        result = analyze_url("https://github.com/dawidbogocz")

        assert result["risk_score"] < 21
        assert result["risk_level"] == "Safe"
        assert "github.com" in result["url"]

    def test_obviously_phishing(self):
        """A clearly malicious URL should get a high risk score."""
        result = analyze_url("http://paypall.tk@192.168.1.1/login")

        assert result["risk_score"] >= 50
        assert result["risk_level"] in ("Likely Phishing", "Confirmed Phishing")

    @patch("netrecon.phish._check_domain_age")
    @patch("netrecon.phish._check_https_validity")
    def test_suspicious_url(self, mock_https, mock_age):
        """A suspicious URL should score moderately."""
        mock_https.return_value.score = 0
        mock_https.return_value.max_score = 10
        mock_https.return_value.passed = False
        mock_https.return_value.detail = ""
        mock_https.return_value.name = "HTTPS Validity"

        mock_age.return_value.score = 0
        mock_age.return_value.max_score = 15
        mock_age.return_value.passed = False
        mock_age.return_value.detail = ""
        mock_age.return_value.name = "Domain Age"

        result = analyze_url("https://login.google.com.xyz.secure.example/login")

        assert result["risk_level"] in ("Suspicious", "Safe")

    def test_invalid_url(self):
        """An invalid URL should return max risk."""
        result = analyze_url("")
        assert result["risk_level"] == "Invalid URL"