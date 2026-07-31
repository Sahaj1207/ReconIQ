"""
ReconIQ Artifact Normalization Engine

Purpose:
Production-grade normalization engine responsible for converting extracted artifacts
into canonical, deterministic formats before validation and threat intelligence lookups.

Responsibilities:
- Normalize URLs (lowercase scheme/hostname, strip default ports, collapse path slashes, preserve case-sensitive path/query)
- Normalize Domains (lowercase, strip trailing dots, IDNA unicode encoding, refang obfuscations)
- Normalize Email Addresses (lowercase domain-part, preserve local-part, refang obfuscations)
- Normalize Phone Numbers (E.164 conversion via phonenumbers library)
- Normalize IPv4 / IPv6 Addresses (RFC compressed representation via ipaddress module)
- Provide reusable Normalizer class and normalize_all() helper for evidence dictionaries
"""

import re
import time
import logging
import urllib.parse
import ipaddress
from typing import List, Dict, Optional, Any, Set
import phonenumbers

logger = logging.getLogger(__name__)


def refang_text(text: str) -> str:
    """
    Refangs defanged text artifacts to standard representation.

    Args:
        text (str): Raw input text containing obfuscated/defanged indicators.

    Returns:
        str: Refanged text ready for indicator extraction or normalization.
    """
    if not text:
        return ""

    refanged = text

    # Scheme refanging
    refanged = re.sub(r'\bhxxp(s)?://', r'http\1://', refanged, flags=re.IGNORECASE)
    refanged = re.sub(r'\bhxxp\b', 'http', refanged, flags=re.IGNORECASE)
    refanged = re.sub(r'\bhxxps\b', 'https', refanged, flags=re.IGNORECASE)
    refanged = re.sub(r'\bfxp(s)?://', r'ftp\1://', refanged, flags=re.IGNORECASE)
    refanged = re.sub(r'\bmeow://', 'http://', refanged, flags=re.IGNORECASE)

    # Dot refanging inside brackets/parentheses (with optional surrounding whitespace)
    refanged = re.sub(r'\s*(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\})\s*', '.', refanged, flags=re.IGNORECASE)

    # At-sign refanging inside brackets/parentheses (with optional surrounding whitespace)
    refanged = re.sub(r'\s*(?:\[at\]|\(at\)|\{at\})\s*', '@', refanged, flags=re.IGNORECASE)

    # Colon refanging inside brackets/parentheses (with optional surrounding whitespace)
    refanged = re.sub(r'\s*(?:\[:\]|\(colon\)|\{colon\})\s*', ':', refanged, flags=re.IGNORECASE)

    return refanged


def clean_canonical_string(value: str) -> str:
    """
    Strips trailing punctuation and whitespaces from extracted IOC strings.

    Args:
        value (str): Raw extracted string matching regex.

    Returns:
        str: Sanitized, canonicalized string token.
    """
    if not value:
        return ""
    cleaned = value.strip().rstrip('.,;:!?"\'>)]}')
    cleaned = cleaned.lstrip('<\'("({[')
    return cleaned


class Normalizer:
    """
    Production-grade cybersecurity artifact normalization engine.
    """

    @staticmethod
    def normalize_url(url: str) -> Optional[str]:
        """
        Normalizes a URL to canonical format:
        - Refangs obfuscated schemes (hxxp/hxxps) and defanged dots
        - Lowercases scheme and hostname
        - Preserves case-sensitive path, query parameters, and fragment
        - Collapses duplicate slashes in path
        - Strips default ports (80 for HTTP, 443 for HTTPS, 21 for FTP)
        - Removes trailing dot from hostname
        - Removes unnecessary trailing slash from non-root paths

        Args:
            url (str): Input URL string.

        Returns:
            Optional[str]: Canonicalized URL string, or None if unparseable/invalid.
        """
        if not url or not isinstance(url, str):
            return None

        try:
            # Step 1: Refang and clean whitespace
            refanged_url = refang_text(url.strip())
            cleaned_url = clean_canonical_string(refanged_url)

            # Prepend default scheme if missing but looks like URL with scheme delimiter
            if "://" not in cleaned_url and (cleaned_url.startswith("http") or cleaned_url.startswith("ftp")):
                cleaned_url = re.sub(r'^(https?|ftp)', r'\1://', cleaned_url, count=1, flags=re.IGNORECASE)

            # Step 2: Parse URL using urllib.parse
            parsed = urllib.parse.urlparse(cleaned_url)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc

            if not scheme or not netloc:
                logger.debug(f"Skipping invalid URL scheme/netloc: '{url}'")
                return None

            # Separate userinfo, hostname, and port from netloc
            userinfo = ""
            host_and_port = netloc
            if "@" in netloc:
                userinfo, host_and_port = netloc.rsplit("@", 1)
                userinfo = userinfo + "@"

            hostname = host_and_port
            port: Optional[int] = None
            if ":" in host_and_port:
                # Handle IPv6 host in netloc e.g. [::1]:8080 vs domain:port
                if host_and_port.startswith("["):
                    end_bracket = host_and_port.find("]")
                    if end_bracket != -1:
                        hostname = host_and_port[:end_bracket + 1]
                        port_str = host_and_port[end_bracket + 1:].lstrip(":")
                        if port_str.isdigit():
                            port = int(port_str)
                else:
                    host_part, port_str = host_and_port.rsplit(":", 1)
                    if port_str.isdigit():
                        hostname = host_part
                        port = int(port_str)

            # Lowercase hostname & strip trailing dots
            hostname = hostname.lower().rstrip(".")

            # IDNA unicode domain normalization if applicable
            try:
                if not hostname.startswith("[") and any(ord(c) > 127 for c in hostname):
                    hostname = hostname.encode("idna").decode("ascii")
            except Exception:
                pass

            # Strip default ports for standard schemes
            default_ports = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443}
            if port is not None and default_ports.get(scheme) == port:
                port = None

            # Reconstruct netloc
            new_netloc = f"{userinfo}{hostname}"
            if port is not None:
                new_netloc += f":{port}"

            # Normalize path: collapse duplicate slashes
            path = parsed.path
            if path:
                path = re.sub(r'/{2,}', '/', path)
                # Strip trailing slash if path is longer than root '/'
                if len(path) > 1 and path.endswith("/"):
                    path = path.rstrip("/")

            # Reconstruct canonical URL
            canonical_url = urllib.parse.urlunparse((
                scheme,
                new_netloc,
                path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))

            return canonical_url
        except Exception as exc:
            logger.debug(f"URL normalization exception for '{url}': {exc}")
            return None

    @staticmethod
    def normalize_domain(domain: str) -> Optional[str]:
        """
        Normalizes a domain name:
        - Refangs obfuscated notation ([.], [dot])
        - Lowercases domain string
        - Strips trailing dots and whitespace
        - Converts IDNA unicode characters to ASCII punycode if needed

        Args:
            domain (str): Input domain string.

        Returns:
            Optional[str]: Canonicalized domain hostname, or None if invalid.
        """
        if not domain or not isinstance(domain, str):
            return None

        try:
            # Step 1: Refang & clean
            refanged = refang_text(domain.strip())
            cleaned = clean_canonical_string(refanged).lower().rstrip(".")

            # Remove scheme if included accidentally
            if "://" in cleaned:
                cleaned = cleaned.split("://")[-1].split("/")[0]

            # Remove port if included
            if ":" in cleaned:
                cleaned = cleaned.split(":")[0]

            if not cleaned or "." not in cleaned:
                logger.debug(f"Skipping invalid domain format: '{domain}'")
                return None

            # IDNA unicode normalization
            try:
                if any(ord(c) > 127 for c in cleaned):
                    cleaned = cleaned.encode("idna").decode("ascii")
            except Exception:
                pass

            return cleaned
        except Exception as exc:
            logger.debug(f"Domain normalization exception for '{domain}': {exc}")
            return None

    @staticmethod
    def normalize_email(email: str) -> Optional[str]:
        """
        Normalizes an email address:
        - Refangs defanged obfuscations ([at], [dot])
        - Lowercases the domain part
        - Preserves the local-part case/characters
        - Trims whitespace

        Args:
            email (str): Input email string.

        Returns:
            Optional[str]: Canonicalized email address, or None if invalid.
        """
        if not email or not isinstance(email, str):
            return None

        try:
            refanged = refang_text(email.strip())
            cleaned = clean_canonical_string(refanged)

            if "@" not in cleaned:
                logger.debug(f"Skipping malformed email missing '@': '{email}'")
                return None

            local_part, domain_part = cleaned.rsplit("@", 1)
            local_part = local_part.strip()
            domain_part = domain_part.strip().lower().rstrip(".")

            if not local_part or not domain_part or "." not in domain_part:
                logger.debug(f"Skipping malformed email structure: '{email}'")
                return None

            return f"{local_part}@{domain_part}"
        except Exception as exc:
            logger.debug(f"Email normalization exception for '{email}': {exc}")
            return None

    @staticmethod
    def normalize_phone(phone: str, default_region: Optional[str] = None) -> Optional[str]:
        """
        Normalizes a phone number to E.164 format via phonenumbers library.

        Args:
            phone (str): Input phone number string.
            default_region (Optional[str]): 2-letter ISO country code fallback (e.g. 'US').

        Returns:
            Optional[str]: E.164 formatted phone number (e.g. '+14155552671'), or None if invalid.
        """
        if not phone or not isinstance(phone, str):
            return None

        try:
            cleaned = clean_canonical_string(phone.strip())
            parsed_number = phonenumbers.parse(cleaned, default_region)

            if not phonenumbers.is_valid_number(parsed_number):
                logger.debug(f"Skipping invalid phone number according to phonenumbers lib: '{phone}'")
                return None

            formatted = phonenumbers.format_number(
                parsed_number, phonenumbers.PhoneNumberFormat.E164
            )
            return formatted
        except Exception as exc:
            logger.debug(f"Phone normalization exception for '{phone}': {exc}")
            return None

    @staticmethod
    def normalize_ipv4(ip: str) -> Optional[str]:
        """
        Normalizes an IPv4 address to canonical string format (removing leading octet zeros).

        Args:
            ip (str): Input IPv4 string.

        Returns:
            Optional[str]: Canonical IPv4 string (e.g. '192.168.1.1'), or None if invalid.
        """
        if not ip or not isinstance(ip, str):
            return None

        try:
            cleaned = clean_canonical_string(ip.strip())
            # Normalize leading zeros in octets e.g. "192.168.001.001" -> "192.168.1.1"
            octets = cleaned.split(".")
            if len(octets) == 4 and all(o.isdigit() for o in octets):
                cleaned = ".".join(str(int(o)) for o in octets)

            ip_obj = ipaddress.IPv4Address(cleaned)
            return str(ip_obj)
        except Exception as exc:
            logger.debug(f"IPv4 normalization exception for '{ip}': {exc}")
            return None

    @staticmethod
    def normalize_ipv6(ip: str) -> Optional[str]:
        """
        Normalizes an IPv6 address to RFC compressed standard string representation.

        Args:
            ip (str): Input IPv6 string.

        Returns:
            Optional[str]: Canonical compressed IPv6 string (e.g. '2001:db8::1'), or None if invalid.
        """
        if not ip or not isinstance(ip, str):
            return None

        try:
            cleaned = clean_canonical_string(ip.strip())
            ip_obj = ipaddress.IPv6Address(cleaned)
            return str(ip_obj.compressed)
        except Exception as exc:
            logger.debug(f"IPv6 normalization exception for '{ip}': {exc}")
            return None

    @classmethod
    def normalize_all(cls, evidence: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """
        Normalizes all categorized artifact lists in an evidence dictionary.

        Args:
            evidence (Dict[str, List[str]]): Extracted evidence dictionary
                with keys 'ipv4', 'ipv6', 'urls', 'domains', 'emails', 'phone_numbers'.

        Returns:
            Dict[str, List[str]]: Normalized, deduplicated, and deterministically sorted evidence dictionary.
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

        initial_count = sum(len(v) for v in evidence.values() if isinstance(v, list))
        logger.info(f"Starting evidence normalization across {initial_count} total artifacts")

        skipped_count = 0

        # 1. Normalize IPv4
        normalized_ipv4: Set[str] = set()
        for raw in evidence.get("ipv4", []):
            norm = cls.normalize_ipv4(raw)
            if norm:
                normalized_ipv4.add(norm)
            else:
                skipped_count += 1

        # 2. Normalize IPv6
        normalized_ipv6: Set[str] = set()
        for raw in evidence.get("ipv6", []):
            norm = cls.normalize_ipv6(raw)
            if norm:
                normalized_ipv6.add(norm)
            else:
                skipped_count += 1

        # 3. Normalize URLs
        normalized_urls: Set[str] = set()
        for raw in evidence.get("urls", []):
            norm = cls.normalize_url(raw)
            if norm:
                normalized_urls.add(norm)
            else:
                skipped_count += 1

        # 4. Normalize Domains
        normalized_domains: Set[str] = set()
        for raw in evidence.get("domains", []):
            norm = cls.normalize_domain(raw)
            if norm:
                normalized_domains.add(norm)
            else:
                skipped_count += 1

        # 5. Normalize Emails
        normalized_emails: Set[str] = set()
        for raw in evidence.get("emails", []):
            norm = cls.normalize_email(raw)
            if norm:
                normalized_emails.add(norm)
            else:
                skipped_count += 1

        # 6. Normalize Phone Numbers
        normalized_phones: Set[str] = set()
        for raw in evidence.get("phone_numbers", []):
            norm = cls.normalize_phone(raw)
            if norm:
                normalized_phones.add(norm)
            else:
                skipped_count += 1

        result = {
            "ipv4": sorted(list(normalized_ipv4)),
            "ipv6": sorted(list(normalized_ipv6)),
            "urls": sorted(list(normalized_urls)),
            "domains": sorted(list(normalized_domains)),
            "emails": sorted(list(normalized_emails)),
            "phone_numbers": sorted(list(normalized_phones)),
        }

        final_count = sum(len(v) for v in result.values())
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        logger.info(
            f"Evidence normalization completed | Initial: {initial_count} -> Final: {final_count} | "
            f"Skipped Invalid: {skipped_count} | Latency: {duration_ms}ms"
        )

        return result
