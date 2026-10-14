"""
ReconIQ Artifact Validation Engine

Purpose:
Production-grade validation engine responsible for verifying the correctness, syntax,
and structural properties of normalized cybersecurity evidence.

IMPORTANT:
This module NEVER determines whether an artifact is malicious.
It strictly validates structural correctness, RFC specifications, and IP address scopes.

Responsibilities:
- Validate URLs (scheme support, netloc syntax, path/query validity)
- Validate Domains (RFC hostname rules, TLD presence, IP masquerading detection)
- Validate Email Addresses (RFC 5322 syntax, local & domain component checks)
- Validate IPv4 Addresses (IPv4 structure, private/loopback/multicast/reserved/global classification)
- Validate IPv6 Addresses (IPv6 structure, global/loopback/link-local/multicast/private classification)
- Validate Phone Numbers (E.164 validity, country code, region detection via phonenumbers)
- Provide bulk validate_all() facade for evidence dictionaries

Future Extension Notes:
- Plug-in hook for IANA top-level domain (TLD) authoritative zone validation.
- ASN & Subnet CIDR block range validators.
"""

import re
import time
import logging
import urllib.parse
import ipaddress
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
import phonenumbers

logger = logging.getLogger(__name__)


class ValidationResult(BaseModel):
    """
    Structured validation result response DTO.
    """
    valid: bool = Field(..., description="Whether the artifact passed structural validation")
    artifact: str = Field(..., description="The original artifact string tested")
    artifact_type: str = Field(..., description="Category of artifact (url, domain, email, ipv4, ipv6, phone_number)")
    properties: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extracted structural properties, network scopes, or validation error details"
    )


class Validator:
    """
    Reusable Validation Engine for cybersecurity evidence artifacts.
    """

    SUPPORTED_URL_SCHEMES = {"http", "https", "ftp", "ws", "wss"}

    @classmethod
    def validate_url(cls, url: str) -> ValidationResult:
        """
        Validates URL syntax, scheme support, and hostname structure.

        Args:
            url (str): Normalized URL string.

        Returns:
            ValidationResult: Structured validation response object.
        """
        if not url or not isinstance(url, str):
            return ValidationResult(
                valid=False,
                artifact=str(url),
                artifact_type="url",
                properties={"error": "Empty or non-string input"}
            )

        try:
            parsed = urllib.parse.urlparse(url.strip())
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc

            if not scheme:
                return ValidationResult(
                    valid=False,
                    artifact=url,
                    artifact_type="url",
                    properties={"error": "Missing URL scheme"}
                )

            if scheme not in cls.SUPPORTED_URL_SCHEMES:
                return ValidationResult(
                    valid=False,
                    artifact=url,
                    artifact_type="url",
                    properties={
                        "error": f"Unsupported scheme '{scheme}'",
                        "supported_schemes": sorted(list(cls.SUPPORTED_URL_SCHEMES))
                    }
                )

            if not netloc:
                return ValidationResult(
                    valid=False,
                    artifact=url,
                    artifact_type="url",
                    properties={"error": "Missing network location / hostname"}
                )

            # Extract hostname and port
            hostname = parsed.hostname
            if not hostname:
                return ValidationResult(
                    valid=False,
                    artifact=url,
                    artifact_type="url",
                    properties={"error": "Invalid host syntax in netloc"}
                )

            return ValidationResult(
                valid=True,
                artifact=url,
                artifact_type="url",
                properties={
                    "scheme": scheme,
                    "hostname": hostname,
                    "port": parsed.port,
                    "path": parsed.path or "/",
                    "has_query": bool(parsed.query),
                    "has_fragment": bool(parsed.fragment)
                }
            )
        except Exception as exc:
            logger.debug(f"URL validation exception for '{url}': {exc}")
            return ValidationResult(
                valid=False,
                artifact=url,
                artifact_type="url",
                properties={"error": f"Parsing exception: {str(exc)}"}
            )

    @classmethod
    def validate_domain(cls, domain: str) -> ValidationResult:
        """
        Validates domain name syntax according to RFC rules and detects IP masquerading.

        Args:
            domain (str): Normalized domain string.

        Returns:
            ValidationResult: Structured validation response object.
        """
        if not domain or not isinstance(domain, str):
            return ValidationResult(
                valid=False,
                artifact=str(domain),
                artifact_type="domain",
                properties={"error": "Empty or non-string input"}
            )

        cleaned = domain.strip().lower()

        # Check for IP masquerading as a domain (e.g. 192.168.1.1 submitted as domain)
        try:
            ipaddress.ip_address(cleaned)
            return ValidationResult(
                valid=False,
                artifact=domain,
                artifact_type="domain",
                properties={"error": "IP address masquerading as domain", "is_ip_masquerade": True}
            )
        except ValueError:
            pass

        # Total domain length check (max 253 chars per RFC 1035)
        if len(cleaned) > 253 or "." not in cleaned:
            return ValidationResult(
                valid=False,
                artifact=domain,
                artifact_type="domain",
                properties={"error": "Invalid domain length or missing TLD delimiter"}
            )

        labels = cleaned.split(".")
        tld = labels[-1]

        # TLD check: must be at least 2 characters (or valid punycode xn--)
        if len(tld) < 2 and not tld.startswith("xn--"):
            return ValidationResult(
                valid=False,
                artifact=domain,
                artifact_type="domain",
                properties={"error": f"Invalid TLD '{tld}'"}
            )

        # Label syntax checks
        label_pattern = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$')
        for label in labels:
            if not label or not label_pattern.match(label):
                return ValidationResult(
                    valid=False,
                    artifact=domain,
                    artifact_type="domain",
                    properties={"error": f"Invalid domain label '{label}'"}
                )

        return ValidationResult(
            valid=True,
            artifact=domain,
            artifact_type="domain",
            properties={
                "tld": tld,
                "subdomain_count": len(labels) - 2 if len(labels) > 2 else 0,
                "is_punycode": any(l.startswith("xn--") for l in labels)
            }
        )

    @classmethod
    def validate_email(cls, email: str) -> ValidationResult:
        """
        Validates RFC 5322 compliant email syntax and domain portion.

        Args:
            email (str): Normalized email string.

        Returns:
            ValidationResult: Structured validation response object.
        """
        if not email or not isinstance(email, str):
            return ValidationResult(
                valid=False,
                artifact=str(email),
                artifact_type="email",
                properties={"error": "Empty or non-string input"}
            )

        cleaned = email.strip()
        if "@" not in cleaned:
            return ValidationResult(
                valid=False,
                artifact=email,
                artifact_type="email",
                properties={"error": "Missing '@' symbol"}
            )

        local_part, domain_part = cleaned.rsplit("@", 1)
        if not local_part or len(local_part) > 64:
            return ValidationResult(
                valid=False,
                artifact=email,
                artifact_type="email",
                properties={"error": "Invalid local-part length"}
            )

        # Validate domain portion using domain validator rules
        domain_val = cls.validate_domain(domain_part)
        if not domain_val.valid:
            return ValidationResult(
                valid=False,
                artifact=email,
                artifact_type="email",
                properties={"error": f"Invalid email domain: {domain_val.properties.get('error')}"}
            )

        return ValidationResult(
            valid=True,
            artifact=email,
            artifact_type="email",
            properties={
                "local_part": local_part,
                "domain": domain_part,
                "tld": domain_val.properties.get("tld")
            }
        )

    @classmethod
    def validate_ipv4(cls, ip: str) -> ValidationResult:
        """
        Validates IPv4 structure and detects RFC address classifications.

        Args:
            ip (str): Normalized IPv4 address string.

        Returns:
            ValidationResult: Structured validation response object with IPv4 properties.
        """
        if not ip or not isinstance(ip, str):
            return ValidationResult(
                valid=False,
                artifact=str(ip),
                artifact_type="ipv4",
                properties={"error": "Empty or non-string input"}
            )

        try:
            ip_obj = ipaddress.IPv4Address(ip.strip())
            return ValidationResult(
                valid=True,
                artifact=str(ip_obj),
                artifact_type="ipv4",
                properties={
                    "is_global": ip_obj.is_global,
                    "is_private": ip_obj.is_private,
                    "is_loopback": ip_obj.is_loopback,
                    "is_multicast": ip_obj.is_multicast,
                    "is_reserved": ip_obj.is_reserved,
                    "is_link_local": ip_obj.is_link_local,
                }
            )
        except Exception as exc:
            return ValidationResult(
                valid=False,
                artifact=ip,
                artifact_type="ipv4",
                properties={"error": f"Invalid IPv4 syntax: {str(exc)}"}
            )

    @classmethod
    def validate_ipv6(cls, ip: str) -> ValidationResult:
        """
        Validates IPv6 structure and detects RFC scope classifications.

        Args:
            ip (str): Normalized IPv6 address string.

        Returns:
            ValidationResult: Structured validation response object with IPv6 properties.
        """
        if not ip or not isinstance(ip, str):
            return ValidationResult(
                valid=False,
                artifact=str(ip),
                artifact_type="ipv6",
                properties={"error": "Empty or non-string input"}
            )

        try:
            ip_obj = ipaddress.IPv6Address(ip.strip())
            return ValidationResult(
                valid=True,
                artifact=str(ip_obj.compressed),
                artifact_type="ipv6",
                properties={
                    "is_global": ip_obj.is_global,
                    "is_private": ip_obj.is_private,
                    "is_loopback": ip_obj.is_loopback,
                    "is_link_local": ip_obj.is_link_local,
                    "is_multicast": ip_obj.is_multicast,
                    "is_reserved": ip_obj.is_reserved,
                    "is_site_local": ip_obj.is_site_local,
                }
            )
        except Exception as exc:
            return ValidationResult(
                valid=False,
                artifact=ip,
                artifact_type="ipv6",
                properties={"error": f"Invalid IPv6 syntax: {str(exc)}"}
            )

    @classmethod
    def validate_phone(cls, phone: str, default_region: Optional[str] = None) -> ValidationResult:
        """
        Validates phone number using Google phonenumbers library and extracts country & region properties.

        Args:
            phone (str): Normalized phone string.
            default_region (Optional[str]): Country ISO code fallback.

        Returns:
            ValidationResult: Structured validation response object.
        """
        if not phone or not isinstance(phone, str):
            return ValidationResult(
                valid=False,
                artifact=str(phone),
                artifact_type="phone_number",
                properties={"error": "Empty or non-string input"}
            )

        try:
            parsed = phonenumbers.parse(phone.strip(), default_region)
            is_valid = phonenumbers.is_valid_number(parsed)
            is_possible = phonenumbers.is_possible_number(parsed)
            region = phonenumbers.region_code_for_number(parsed)

            if not is_possible:
                return ValidationResult(
                    valid=False,
                    artifact=phone,
                    artifact_type="phone_number",
                    properties={"error": "Impossible phone number format", "is_possible": False}
                )

            e164_format = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            ) if is_valid else None

            return ValidationResult(
                valid=is_valid,
                artifact=phone,
                artifact_type="phone_number",
                properties={
                    "is_valid": is_valid,
                    "is_possible": is_possible,
                    "country_code": parsed.country_code,
                    "region": region or "UNKNOWN",
                    "e164_format": e164_format
                }
            )
        except Exception as exc:
            return ValidationResult(
                valid=False,
                artifact=phone,
                artifact_type="phone_number",
                properties={"error": f"Phone validation exception: {str(exc)}"}
            )

    HASH_ALGORITHMS = {32: "md5", 40: "sha1", 64: "sha256"}

    @classmethod
    def validate_hash(cls, value: str) -> ValidationResult:
        """Validates an MD5 / SHA-1 / SHA-256 hex digest."""
        candidate = (value or "").strip().lower()
        algorithm = cls.HASH_ALGORITHMS.get(len(candidate))
        if algorithm and re.fullmatch(r"[a-f0-9]+", candidate):
            return ValidationResult(valid=True, artifact=value, artifact_type="hash", properties={"algorithm": algorithm})
        return ValidationResult(
            valid=False, artifact=value, artifact_type="hash",
            properties={"error": "Not a valid MD5, SHA-1 or SHA-256 hex digest"}
        )

    @classmethod
    def validate_all(cls, evidence: Dict[str, List[str]]) -> Dict[str, List[ValidationResult]]:
        """
        Validates all categorized artifacts in a normalized evidence dictionary.

        Args:
            evidence (Dict[str, List[str]]): Evidence dictionary with keys
                'ipv4', 'ipv6', 'urls', 'domains', 'emails', 'phone_numbers'.

        Returns:
            Dict[str, List[ValidationResult]]: Categorized dictionary containing ValidationResult objects.
        """
        start_time = time.perf_counter()

        if not evidence or not isinstance(evidence, dict):
            return {
                "ipv4": [],
                "ipv6": [],
                "urls": [],
                "domains": [],
                "emails": [],
                "phone_numbers": []
            }

        total_artifacts = sum(len(v) for v in evidence.values() if isinstance(v, list))
        logger.info(f"Starting evidence validation across {total_artifacts} total artifacts")

        failures_count = 0

        # 1. Validate IPv4
        ipv4_results: List[ValidationResult] = []
        for artifact in evidence.get("ipv4", []):
            res = cls.validate_ipv4(artifact)
            if not res.valid:
                failures_count += 1
            ipv4_results.append(res)

        # 2. Validate IPv6
        ipv6_results: List[ValidationResult] = []
        for artifact in evidence.get("ipv6", []):
            res = cls.validate_ipv6(artifact)
            if not res.valid:
                failures_count += 1
            ipv6_results.append(res)

        # 3. Validate URLs
        url_results: List[ValidationResult] = []
        for artifact in evidence.get("urls", []):
            res = cls.validate_url(artifact)
            if not res.valid:
                failures_count += 1
            url_results.append(res)

        # 4. Validate Domains
        domain_results: List[ValidationResult] = []
        for artifact in evidence.get("domains", []):
            res = cls.validate_domain(artifact)
            if not res.valid:
                failures_count += 1
            domain_results.append(res)

        # 5. Validate Emails
        email_results: List[ValidationResult] = []
        for artifact in evidence.get("emails", []):
            res = cls.validate_email(artifact)
            if not res.valid:
                failures_count += 1
            email_results.append(res)

        # 6. Validate Phone Numbers
        phone_results: List[ValidationResult] = []
        for artifact in evidence.get("phone_numbers", []):
            res = cls.validate_phone(artifact)
            if not res.valid:
                failures_count += 1
            phone_results.append(res)

        # 7. Validate File Hashes
        hash_results: List[ValidationResult] = []
        for artifact in evidence.get("hashes", []):
            res = cls.validate_hash(artifact)
            if not res.valid:
                failures_count += 1
            hash_results.append(res)

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        logger.info(
            f"Evidence validation completed | Total Artifacts: {total_artifacts} | "
            f"Failures: {failures_count} | Latency: {duration_ms}ms"
        )

        return {
            "ipv4": ipv4_results,
            "ipv6": ipv6_results,
            "urls": url_results,
            "domains": domain_results,
            "emails": email_results,
            "phone_numbers": phone_results,
            "hashes": hash_results,
        }
