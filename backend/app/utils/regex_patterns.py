"""
ReconIQ Regex Patterns Module

Compiled regular expressions for extracting Indicators of Compromise (IOCs):
- IPv4 (0-255 octets)
- IPv6 (RFC 4291 compliant compressed/uncompressed formats)
- URLs (http, https, ftp, ws, wss)
- Domains (valid TLD string matches)
- Email addresses (RFC 5322 compatible)
- Phone numbers (E.164 and international formats)
"""

import re

# IPv4 Pattern (Strict 0-255 boundaries per octet)
IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# IPv6 Candidate Pattern (Validates via ipaddress.IPv6Address)
IPV6_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:)+:(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b|'
    r'\b::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b',
    re.IGNORECASE
)

# URL Pattern (http, https, ftp, ws, wss schemes with path, port, query params)
URL_PATTERN = re.compile(
    r'\b(?:https?|ftp|ws|wss)://'
    r'(?:[a-zA-Z0-9\.\-_]+(?::[a-zA-Z0-9\.\-_]+)?@)?'
    r'(?:(?:[a-zA-Z0-9\-_]+\.)+[a-zA-Z]{2,63}|(?:\d{1,3}\.){3}\d{1,3})'
    r'(?::\d{1,5})?'
    r'(?:/[^\s()<>"]*)?',
    re.IGNORECASE
)

# Email Pattern (Standard user@domain.tld matching)
EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,63}\b',
    re.IGNORECASE
)

# Domain Name Pattern (Hostnames with valid 2+ char TLDs, excluding standalone IPs)
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?:[a-zA-Z]{2,63})\b',
    re.IGNORECASE
)

# File Hash Patterns (MD5 / SHA-1 / SHA-256 hex digests)
HASH_PATTERN = re.compile(r'\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b')

# Fallback Phone Number Pattern (Matches international formats +1-800-555-0199 or +44 20 7946 0958)
PHONE_PATTERN = re.compile(
    r'(?:\+\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b'
)
