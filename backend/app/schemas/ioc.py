"""
ReconIQ IOC Schemas

Defines Pydantic models for structured indicator categories:
IPv4, IPv6, URLs, Domains, Email addresses, and Phone numbers.
"""

from typing import List
from pydantic import BaseModel, Field


class IOCSummary(BaseModel):
    """Counts breakdown per indicator category."""
    total_iocs: int = Field(default=0, description="Total count of unique IOCs extracted")
    ipv4_count: int = Field(default=0, description="Count of unique IPv4 addresses")
    ipv6_count: int = Field(default=0, description="Count of unique IPv6 addresses")
    url_count: int = Field(default=0, description="Count of unique URLs")
    domain_count: int = Field(default=0, description="Count of unique domain names")
    email_count: int = Field(default=0, description="Count of unique email addresses")
    phone_count: int = Field(default=0, description="Count of unique phone numbers")
    hash_count: int = Field(default=0, description="Count of unique file hashes")


class IOCResults(BaseModel):
    """Categorized extracted IOC lists."""
    ipv4: List[str] = Field(default_factory=list, description="Extracted IPv4 addresses")
    ipv6: List[str] = Field(default_factory=list, description="Extracted IPv6 addresses")
    urls: List[str] = Field(default_factory=list, description="Extracted URLs")
    domains: List[str] = Field(default_factory=list, description="Extracted domain names")
    emails: List[str] = Field(default_factory=list, description="Extracted email addresses")
    phone_numbers: List[str] = Field(default_factory=list, description="Extracted phone numbers")
    hashes: List[str] = Field(default_factory=list, description="Extracted file hashes (MD5/SHA-1/SHA-256)")
