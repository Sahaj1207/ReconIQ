"""
Threat-intelligence provider registry.

Builds the ThreatIntelManager from settings: key-based providers are registered only when their
key is configured, keyless providers when INTEL_KEYLESS_PROVIDERS is enabled. Unconfigured
providers are reported (not queried), so investigations don't carry noise from missing keys.
"""

from typing import Dict, List

from app.core.config import settings
from app.integrations.manager import ThreatIntelManager
from app.integrations.providers.virustotal import VirusTotalProvider
from app.integrations.providers.abuseipdb import AbuseIPDBProvider
from app.integrations.providers.shodan_internetdb import ShodanInternetDBProvider
from app.integrations.providers.rdap import RDAPProvider
from app.integrations.providers.urlhaus import URLhausProvider
from app.integrations.providers.safe_browsing import SafeBrowsingProvider
from app.integrations.providers.hibp import HIBPProvider

# (display name, setting holding the key or None for keyless, factory, artifact types, signup URL)
PROVIDER_CATALOG = [
    ("VirusTotal", "VIRUSTOTAL_API_KEY", lambda key: VirusTotalProvider(api_key=key, timeout=settings.INTEL_TIMEOUT_SECONDS),
     ["url", "domain", "ip", "hash"], "https://www.virustotal.com/gui/my-apikey"),
    ("AbuseIPDB", "ABUSEIPDB_API_KEY", lambda key: AbuseIPDBProvider(api_key=key, timeout=settings.INTEL_TIMEOUT_SECONDS),
     ["ip"], "https://www.abuseipdb.com/account/api"),
    ("URLhaus", "URLHAUS_AUTH_KEY", lambda key: URLhausProvider(api_key=key, timeout=settings.INTEL_TIMEOUT_SECONDS),
     ["url", "domain", "ip", "hash"], "https://auth.abuse.ch/"),
    ("Google Safe Browsing", "GOOGLE_SAFE_BROWSING_API_KEY",
     lambda key: SafeBrowsingProvider(api_key=key, timeout=settings.INTEL_TIMEOUT_SECONDS),
     ["url", "domain"], "https://developers.google.com/safe-browsing/v4/get-started"),
    ("Have I Been Pwned", "HIBP_API_KEY", lambda key: HIBPProvider(api_key=key, timeout=settings.INTEL_TIMEOUT_SECONDS),
     ["email"], "https://haveibeenpwned.com/API/Key"),
    ("Shodan InternetDB", None, lambda _: ShodanInternetDBProvider(timeout=settings.INTEL_TIMEOUT_SECONDS),
     ["ip"], "https://internetdb.shodan.io/"),
    ("RDAP", None, lambda _: RDAPProvider(timeout=settings.INTEL_TIMEOUT_SECONDS),
     ["domain"], "https://about.rdap.org/"),
]


def _enabled(key_setting) -> bool:
    if key_setting is None:
        return settings.INTEL_KEYLESS_PROVIDERS
    return bool(getattr(settings, key_setting, ""))


def build_default_manager() -> ThreatIntelManager:
    manager = ThreatIntelManager()
    for _, key_setting, factory, _, _ in PROVIDER_CATALOG:
        if _enabled(key_setting):
            manager.register_provider(factory(getattr(settings, key_setting, "") if key_setting else ""))
    return manager


def provider_status() -> List[Dict[str, object]]:
    return [
        {
            "name": name,
            "enabled": _enabled(key_setting),
            "requires_key": key_setting is not None,
            "key_setting": key_setting,
            "artifact_types": types,
            "docs_url": url,
        }
        for name, key_setting, _, types, url in PROVIDER_CATALOG
    ]
