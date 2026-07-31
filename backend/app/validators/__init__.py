"""
ReconIQ Validators Package

Purpose:
Provides verification engine components for structural validation of normalized cybersecurity artifacts.

Responsibilities:
- Validate syntax and format of URLs, Domains, Emails, IPv4, IPv6, and Phone Numbers
- Extract non-malicious structural metadata properties (RFC ranges, scopes, regions)
- Expose the central Validator engine facade

Future Extension Notes:
- Integration with IANA TLD zone files and WHOIS domain syntax checkers.
"""

from app.validators.validator import Validator, ValidationResult

__all__ = ["Validator", "ValidationResult"]
