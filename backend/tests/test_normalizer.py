"""
ReconIQ Phase 2 Normalization Engine Unit Tests
"""

import pytest
from app.utils.normalizer import Normalizer


def test_url_normalization_defanged_and_ports():
    """Test defanged URL refanging, scheme/domain lowercasing, and default port removal."""
    url = "HXXPS://MALICIOUS-PORTAL[.]COM:443//LOGIN//PAGE/?user=123."
    normalized = Normalizer.normalize_url(url)
    assert normalized == "https://malicious-portal.com/LOGIN/PAGE?user=123"


def test_url_normalization_duplicate_slashes_and_default_http_port():
    """Test duplicate slash collapsing in URL path and HTTP default port 80 removal."""
    url = "http://EXAMPLE.COM:80///api///v1///check/"
    normalized = Normalizer.normalize_url(url)
    assert normalized == "http://example.com/api/v1/check"


def test_url_normalization_non_default_port():
    """Test non-default port retention."""
    url = "http://example.com:8080/path"
    normalized = Normalizer.normalize_url(url)
    assert normalized == "http://example.com:8080/path"


def test_domain_normalization_uppercase_and_defanged():
    """Test uppercase domain lowercasing, trailing dot removal, and defanged bracket replacement."""
    domain = "SUB[DOT]MALICIOUS-SITE[DOT]COM."
    normalized = Normalizer.normalize_domain(domain)
    assert normalized == "sub.malicious-site.com"


def test_domain_normalization_invalid():
    """Test invalid domain filtering."""
    assert Normalizer.normalize_domain("invalid_no_dot") is None
    assert Normalizer.normalize_domain("") is None


def test_email_normalization_defanged_and_cases():
    """Test email refanging, domain lowercasing, and local-part case preservation."""
    email = " User.Name [at] MALICIOUS-BANK [dot] COM "
    normalized = Normalizer.normalize_email(email)
    assert normalized == "User.Name@malicious-bank.com"


def test_email_normalization_malformed():
    """Test malformed email skipping."""
    assert Normalizer.normalize_email("no_at_sign.com") is None
    assert Normalizer.normalize_email("@no_local.com") is None
    assert Normalizer.normalize_email("no_domain@") is None


def test_phone_normalization_e164():
    """Test valid phone number formatting into E.164 standard."""
    phone = "+1 (415) 555-2671"
    normalized = Normalizer.normalize_phone(phone)
    assert normalized == "+14155552671"


def test_phone_normalization_invalid():
    """Test invalid phone number skipping."""
    assert Normalizer.normalize_phone("1234") is None
    assert Normalizer.normalize_phone("not_a_phone") is None


def test_ipv4_normalization():
    """Test IPv4 zero stripping and normalization."""
    ip = "192.168.001.001"
    normalized = Normalizer.normalize_ipv4(ip)
    assert normalized == "192.168.1.1"


def test_ipv4_normalization_invalid():
    """Test invalid IPv4 address skipping."""
    assert Normalizer.normalize_ipv4("999.999.999.999") is None


def test_ipv6_normalization():
    """Test IPv6 expansion to compressed standard RFC representation."""
    ip = "2001:0db8:0000:0000:0000:0000:0000:0001"
    normalized = Normalizer.normalize_ipv6(ip)
    assert normalized == "2001:db8::1"


def test_ipv6_normalization_invalid():
    """Test invalid IPv6 address skipping."""
    assert Normalizer.normalize_ipv6("invalid:ipv6:address:zz") is None


def test_normalize_all_integration():
    """Test normalize_all() helper with evidence dictionary input."""
    raw_evidence = {
        "ipv4": ["192.168.001.001", "10.0.0.1", "invalid_ip"],
        "ipv6": ["2001:0db8:0000:0000:0000:0000:0000:0001"],
        "urls": ["HXXPS://EXAMPLE[.]COM:443//PATH///"],
        "domains": ["TEST[DOT]COM."],
        "emails": ["Admin [at] SECURE-BANK [dot] COM"],
        "phone_numbers": ["+1-800-555-0199", "123"],
    }

    normalized = Normalizer.normalize_all(raw_evidence)

    assert normalized["ipv4"] == ["10.0.0.1", "192.168.1.1"]
    assert normalized["ipv6"] == ["2001:db8::1"]
    assert normalized["urls"] == ["https://example.com/PATH"]
    assert normalized["domains"] == ["test.com"]
    assert normalized["emails"] == ["Admin@secure-bank.com"]
    assert normalized["phone_numbers"] == ["+18005550199"]
