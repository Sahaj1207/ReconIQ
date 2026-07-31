"""
ReconIQ Phase 3 Validation Engine Unit Tests
"""

import pytest
from app.validators.validator import Validator, ValidationResult


# --- URL Validation Tests ---

def test_validate_url_valid():
    """Test valid HTTP/HTTPS URLs."""
    res = Validator.validate_url("https://example.com/path?query=1")
    assert res.valid is True
    assert res.artifact_type == "url"
    assert res.properties["scheme"] == "https"
    assert res.properties["hostname"] == "example.com"


def test_validate_url_invalid():
    """Test malformed URL."""
    res = Validator.validate_url("http://")
    assert res.valid is False
    assert "error" in res.properties


def test_validate_url_unsupported_scheme():
    """Test unsupported URL scheme (e.g. gopher://)."""
    res = Validator.validate_url("gopher://example.com")
    assert res.valid is False
    assert "Unsupported scheme" in res.properties.get("error", "")


# --- Domain Validation Tests ---

def test_validate_domain_valid():
    """Test valid domains and subdomains."""
    res = Validator.validate_domain("sub.example.com")
    assert res.valid is True
    assert res.artifact_type == "domain"
    assert res.properties["tld"] == "com"
    assert res.properties["subdomain_count"] == 1


def test_validate_domain_invalid():
    """Test invalid domain syntax."""
    res = Validator.validate_domain("invalid_no_tld")
    assert res.valid is False
    assert "error" in res.properties


def test_validate_domain_ip_masquerade():
    """Test IP address submitted as domain name."""
    res = Validator.validate_domain("192.168.1.1")
    assert res.valid is False
    assert res.properties.get("is_ip_masquerade") is True


# --- Email Validation Tests ---

def test_validate_email_valid():
    """Test valid email address."""
    res = Validator.validate_email("user@example.com")
    assert res.valid is True
    assert res.artifact_type == "email"
    assert res.properties["local_part"] == "user"
    assert res.properties["domain"] == "example.com"


def test_validate_email_invalid():
    """Test invalid email format."""
    res = Validator.validate_email("invalid_email.com")
    assert res.valid is False
    assert "Missing '@'" in res.properties.get("error", "")


# --- IPv4 Validation Tests ---

def test_validate_ipv4_public():
    """Test public global IPv4 address."""
    res = Validator.validate_ipv4("8.8.8.8")
    assert res.valid is True
    assert res.properties["is_global"] is True
    assert res.properties["is_private"] is False


def test_validate_ipv4_private():
    """Test RFC 1918 private IPv4 address."""
    res = Validator.validate_ipv4("192.168.1.1")
    assert res.valid is True
    assert res.properties["is_private"] is True
    assert res.properties["is_global"] is False


def test_validate_ipv4_loopback():
    """Test IPv4 loopback address."""
    res = Validator.validate_ipv4("127.0.0.1")
    assert res.valid is True
    assert res.properties["is_loopback"] is True


def test_validate_ipv4_reserved():
    """Test IPv4 reserved address."""
    res = Validator.validate_ipv4("240.0.0.1")
    assert res.valid is True
    assert res.properties["is_reserved"] is True


# --- IPv6 Validation Tests ---

def test_validate_ipv6_global():
    """Test global unicast IPv6 address."""
    res = Validator.validate_ipv6("2001:db8::1")
    assert res.valid is True
    assert res.artifact_type == "ipv6"


def test_validate_ipv6_link_local():
    """Test link-local IPv6 address."""
    res = Validator.validate_ipv6("fe80::1")
    assert res.valid is True
    assert res.properties["is_link_local"] is True


def test_validate_ipv6_loopback():
    """Test IPv6 loopback address."""
    res = Validator.validate_ipv6("::1")
    assert res.valid is True
    assert res.properties["is_loopback"] is True


# --- Phone Number Validation Tests ---

def test_validate_phone_valid():
    """Test valid international phone number."""
    res = Validator.validate_phone("+14155552671")
    assert res.valid is True
    assert res.artifact_type == "phone_number"
    assert res.properties["is_valid"] is True
    assert res.properties["country_code"] == 1


def test_validate_phone_invalid():
    """Test invalid phone number."""
    res = Validator.validate_phone("123")
    assert res.valid is False
    assert "error" in res.properties


# --- Bulk Validation Integration Tests ---

def test_validate_all_integration():
    """Test validate_all() facade with normalized evidence dictionary."""
    evidence = {
        "ipv4": ["8.8.8.8", "192.168.1.1", "invalid_ip"],
        "ipv6": ["2001:db8::1"],
        "urls": ["https://example.com"],
        "domains": ["example.com"],
        "emails": ["user@example.com"],
        "phone_numbers": ["+14155552671"],
    }

    validated = Validator.validate_all(evidence)

    assert len(validated["ipv4"]) == 3
    assert validated["ipv4"][0].valid is True
    assert validated["ipv4"][0].properties["is_global"] is True
    assert validated["ipv4"][1].valid is True
    assert validated["ipv4"][1].properties["is_private"] is True
    assert validated["ipv4"][2].valid is False

    assert len(validated["urls"]) == 1
    assert validated["urls"][0].valid is True
