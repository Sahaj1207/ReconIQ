"""
ReconIQ IOC Extractor Sub-Component

Purpose:
Production-quality Indicator of Compromise (IOC) extractor.
Extracts IPv4, IPv6, URLs, Domains, Email addresses, and Phone numbers from plain or defanged text.

Responsibilities:
- Perform defang normalization (hxxp/hxxps -> http/https, [.]/[dot] -> ., [at] -> @)
- Validate IPv4 and IPv6 syntax via standard Python `ipaddress` module
- Validate and format phone numbers using Google's `phonenumbers` library into E.164 standard
- Validate and sanitize email addresses and domain names
- Eliminate duplicates while preserving deterministic sorting order
- Handle extraction errors gracefully to yield partial results without crashing

Future Implementation Notes:
- Integration with IANA top-level domain (TLD) validation lists.
- RFC 1918 private IP classification tagging.
"""

import ipaddress
import logging
from typing import List, Dict, Set, Any
import phonenumbers

from app.ingestion.ingested_input import IngestedInput, IngestionSourceType
from app.ingestion.extractors.base import BaseExtractor
from app.utils.normalizer import refang_text, clean_canonical_string
from app.utils.regex_patterns import (
    IPV4_PATTERN,
    IPV6_PATTERN,
    URL_PATTERN,
    EMAIL_PATTERN,
    DOMAIN_PATTERN,
    PHONE_PATTERN,
    HASH_PATTERN,
)

logger = logging.getLogger(__name__)


class IOCExtractor(BaseExtractor):
    """
    Production-grade IOC Extractor implementing BaseExtractor interface.
    """

    @property
    def name(self) -> str:
        """Returns extractor component name."""
        return "ioc_extractor"

    @property
    def supported_source_types(self) -> List[IngestionSourceType]:
        """Returns list of supported ingestion source types."""
        return [
            IngestionSourceType.RAW_TEXT,
            IngestionSourceType.EMAIL,
            IngestionSourceType.OCR_TEXT,
            IngestionSourceType.BROWSER_UPLOAD,
            IngestionSourceType.PDF_FILE,
            IngestionSourceType.QR_CODE,
            IngestionSourceType.IMAGE,
            IngestionSourceType.APK_FILE,
        ]

    def extract(self, input_data: IngestedInput) -> Dict[str, List[str]]:
        """
        Executes IOC extraction on input content.

        Args:
            input_data (IngestedInput): Standardized input payload object.

        Returns:
            Dict[str, List[str]]: Categorized dictionary of extracted indicator strings.
        """
        if not input_data or not input_data.content:
            return {
                "ipv4": [],
                "ipv6": [],
                "urls": [],
                "domains": [],
                "emails": [],
                "phone_numbers": [],
                "hashes": [],
            }

        # Refang text artifacts if refang flag is set in metadata (default True)
        should_refang = input_data.metadata.get("refang", True)
        processed_text = refang_text(input_data.content) if should_refang else input_data.content

        # Extracted indicator sets
        ipv4_set: Set[str] = set()
        ipv6_set: Set[str] = set()
        email_set: Set[str] = set()
        url_set: Set[str] = set()
        domain_set: Set[str] = set()
        phone_set: Set[str] = set()
        hash_set: Set[str] = set()

        # 1. IPv4 Extraction & Validation
        try:
            for match in IPV4_PATTERN.findall(processed_text):
                cleaned = clean_canonical_string(match)
                try:
                    ip_obj = ipaddress.IPv4Address(cleaned)
                    ipv4_set.add(str(ip_obj))
                except ValueError:
                    continue
        except Exception as exc:
            logger.warning(f"Error during IPv4 extraction phase: {exc}")

        # 2. IPv6 Extraction & Validation
        try:
            for match in IPV6_PATTERN.findall(processed_text):
                cleaned = clean_canonical_string(match)
                if cleaned in ipv4_set:
                    continue
                try:
                    ip_obj = ipaddress.IPv6Address(cleaned)
                    ipv6_set.add(str(ip_obj))
                except ValueError:
                    continue
        except Exception as exc:
            logger.warning(f"Error during IPv6 extraction phase: {exc}")

        # 3. Email Extraction & Normalization
        try:
            for match in EMAIL_PATTERN.findall(processed_text):
                cleaned = clean_canonical_string(match).lower()
                email_set.add(cleaned)
        except Exception as exc:
            logger.warning(f"Error during Email extraction phase: {exc}")

        # 4. URL Extraction & Sanitization
        try:
            for match in URL_PATTERN.findall(processed_text):
                cleaned = clean_canonical_string(match)
                url_set.add(cleaned)
        except Exception as exc:
            logger.warning(f"Error during URL extraction phase: {exc}")

        # 5. Domain Name Extraction & Normalization
        try:
            # Derive domains from extracted emails
            for email in email_set:
                if "@" in email:
                    domain_set.add(email.split("@")[-1].lower())

            for match in DOMAIN_PATTERN.findall(processed_text):
                cleaned = clean_canonical_string(match).lower()
                # Verify match is not an IP address
                try:
                    ipaddress.ip_address(cleaned)
                    continue
                except ValueError:
                    pass

                if cleaned not in ipv4_set and cleaned not in ipv6_set:
                    domain_set.add(cleaned)
        except Exception as exc:
            logger.warning(f"Error during Domain extraction phase: {exc}")

        # 6. Phone Number Extraction via phonenumbers & fallback
        try:
            for match in phonenumbers.PhoneNumberMatcher(processed_text, None):
                formatted = phonenumbers.format_number(
                    match.number, phonenumbers.PhoneNumberFormat.E164
                )
                phone_set.add(formatted)
        except Exception as exc:
            logger.debug(f"phonenumbers lib matcher notice: {exc}")

        if not phone_set:
            try:
                for match in PHONE_PATTERN.findall(processed_text):
                    cleaned = clean_canonical_string(match)
                    digits_only = "".join(c for c in cleaned if c.isdigit() or c == "+")
                    if len(digits_only.replace("+", "")) >= 7:
                        phone_set.add(digits_only)
            except Exception as exc:
                logger.warning(f"Error during Phone fallback extraction phase: {exc}")

        # 7. File Hash Extraction (MD5 / SHA-1 / SHA-256)
        try:
            for match in HASH_PATTERN.findall(processed_text):
                hash_set.add(match.lower())
        except Exception as exc:
            logger.warning(f"Error during Hash extraction phase: {exc}")

        # Return deterministically sorted indicator lists
        return {
            "ipv4": sorted(list(ipv4_set)),
            "ipv6": sorted(list(ipv6_set)),
            "urls": sorted(list(url_set)),
            "domains": sorted(list(domain_set)),
            "emails": sorted(list(email_set)),
            "phone_numbers": sorted(list(phone_set)),
            "hashes": sorted(list(hash_set)),
        }
