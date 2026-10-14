"""
ReconIQ Deterministic Threat Detection Rule Framework & Rule Library

Purpose:
Framework for defining, registering, and evaluating independent deterministic risk detection rules.

Responsibilities:
- Provide abstract BaseRule contract (id, name, description, weight, severity, enabled, evaluate())
- Provide comprehensive initial rule library covering Validation, Threat Intel, and Evidence rules
- Provide RuleRegistry for dynamic rule enabling/disabling and rule management

IMPORTANT:
Rules are 100% deterministic and explainable. No ML or AI is used.

Future Extension Notes:
- External YAML rule loader for SIGMA/YARA style rule definitions.
"""

from abc import ABC, abstractmethod
import logging
from typing import List, Dict, Any, Tuple, Optional
from app.risk_engine.models import RiskFinding, AppliedRule
from app.risk_engine.weights import RiskWeights

logger = logging.getLogger(__name__)

# Framework context for the original rule library (new rules declare theirs inline).
RULE_METADATA: Dict[str, Dict[str, List[str]]] = {
    "RULE_VAL_001": {"categories": ["suspicious_infrastructure"], "mitre": ["T1036"], "cwe": ["CWE-451"]},
    "RULE_VAL_002": {"categories": ["suspicious_infrastructure"], "mitre": ["T1036", "T1583.001"], "cwe": ["CWE-451"]},
    "RULE_VAL_003": {"categories": ["email_spoofing"], "mitre": ["T1656"], "cwe": ["CWE-290"]},
    "RULE_INT_001": {"categories": ["suspicious_infrastructure"], "mitre": ["T1583.001", "T1071.001"]},
    "RULE_INT_002": {"categories": ["suspicious_infrastructure"], "mitre": ["T1583.001", "T1071.001"]},
    "RULE_EVI_001": {"categories": ["phishing_email"], "mitre": ["T1027"]},
    "RULE_EVI_002": {"categories": ["suspicious_infrastructure"]},
    "RULE_EVI_003": {"categories": ["suspicious_infrastructure"], "mitre": ["T1583.003"]},
}


class BaseRule(ABC):
    """
    Abstract Base Class for all ReconIQ Risk Engine Rules.
    """

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        weight: float,
        severity: str,
        enabled: bool = True,
        categories: Optional[List[str]] = None,
        mitre: Optional[List[str]] = None,
        cwe: Optional[List[str]] = None,
    ) -> None:
        self.id = rule_id
        self.name = name
        self.description = description
        self.weight = weight
        self.severity = severity
        self.enabled = enabled
        meta = RULE_METADATA.get(rule_id, {})
        self.categories: List[str] = categories if categories is not None else meta.get("categories", [])
        self.mitre: List[str] = mitre if mitre is not None else meta.get("mitre", [])
        self.cwe: List[str] = cwe if cwe is not None else meta.get("cwe", [])

    @abstractmethod
    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[RiskFinding], Dict[str, Any]]:
        """
        Evaluates rule condition against risk assessment context dictionary.

        Args:
            context (Dict[str, Any]): Assessment context containing 'evidence',
                'validation_results', 'intel_results', and 'raw_text'.

        Returns:
            Tuple[bool, List[RiskFinding], Dict[str, Any]]:
                - matched (bool): Whether the rule triggered a match.
                - findings (List[RiskFinding]): Generated findings if matched.
                - evidence_context (Dict[str, Any]): Matched evidence context metadata.
        """
        pass


# --- Validation Rules ---

class InvalidURLRule(BaseRule):
    """Triggers when malformed or invalid URLs fail validation."""
    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE_VAL_001",
            name="Invalid URL Detected",
            description="One or more extracted URLs failed structural validation",
            weight=RiskWeights.MEDIUM,
            severity="MEDIUM"
        )

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[RiskFinding], Dict[str, Any]]:
        validation = context.get("validation_results", {})
        invalid_urls = []

        for item in validation.get("urls", []):
            is_valid = getattr(item, "valid", True) if hasattr(item, "valid") else item.get("valid", True)
            if not is_valid:
                art = getattr(item, "artifact", str(item)) if hasattr(item, "artifact") else item.get("artifact", str(item))
                invalid_urls.append(art)

        if invalid_urls:
            finding = RiskFinding(
                finding_id=f"{self.id}_FINDING",
                title="Malformed URL Artifact",
                description=f"Extracted URLs failed structural validation: {', '.join(invalid_urls[:3])}",
                severity=self.severity,
                score_impact=self.weight,
                artifact=invalid_urls[0]
            )
            return True, [finding], {"invalid_urls": invalid_urls}
        return False, [], {}


class InvalidDomainRule(BaseRule):
    """Triggers when invalid domains or IP masquerades are detected."""
    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE_VAL_002",
            name="Invalid Domain or IP Masquerade",
            description="Extracted domain failed validation or IP masquerading as domain",
            weight=RiskWeights.HIGH,
            severity="HIGH"
        )

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[RiskFinding], Dict[str, Any]]:
        validation = context.get("validation_results", {})
        invalid_domains = []

        for item in validation.get("domains", []):
            is_valid = getattr(item, "valid", True) if hasattr(item, "valid") else item.get("valid", True)
            if not is_valid:
                art = getattr(item, "artifact", str(item)) if hasattr(item, "artifact") else item.get("artifact", str(item))
                invalid_domains.append(art)

        if invalid_domains:
            finding = RiskFinding(
                finding_id=f"{self.id}_FINDING",
                title="Invalid Domain / IP Masquerade",
                description=f"Domain failed validation or masqueraded as IP: {', '.join(invalid_domains[:3])}",
                severity=self.severity,
                score_impact=self.weight,
                artifact=invalid_domains[0]
            )
            return True, [finding], {"invalid_domains": invalid_domains}
        return False, [], {}


class InvalidEmailRule(BaseRule):
    """Triggers when malformed emails are detected."""
    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE_VAL_003",
            name="Invalid Email Structure",
            description="Extracted email failed RFC 5322 syntax validation",
            weight=RiskWeights.LOW,
            severity="LOW"
        )

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[RiskFinding], Dict[str, Any]]:
        validation = context.get("validation_results", {})
        invalid_emails = []

        for item in validation.get("emails", []):
            is_valid = getattr(item, "valid", True) if hasattr(item, "valid") else item.get("valid", True)
            if not is_valid:
                art = getattr(item, "artifact", str(item)) if hasattr(item, "artifact") else item.get("artifact", str(item))
                invalid_emails.append(art)

        if invalid_emails:
            finding = RiskFinding(
                finding_id=f"{self.id}_FINDING",
                title="Malformed Email Address",
                description=f"Extracted email failed syntax validation: {', '.join(invalid_emails[:3])}",
                severity=self.severity,
                score_impact=self.weight,
                artifact=invalid_emails[0]
            )
            return True, [finding], {"invalid_emails": invalid_emails}
        return False, [], {}


# --- Threat Intelligence Rules ---

FLAGGING_SEVERITIES = {"MEDIUM", "HIGH", "CRITICAL"}


def is_flagged_malicious(res: Any) -> bool:
    """
    A provider response counts as a malicious verdict only when the lookup succeeded AND it carries
    at least one MEDIUM+ threat indicator. Provider `confidence` describes certainty in the verdict
    (a clean VirusTotal result reports 0.8), so it must never be read as maliciousness on its own.
    """
    get = (lambda k, d=None: res.get(k, d)) if isinstance(res, dict) else (lambda k, d=None: getattr(res, k, d))
    if str(get("status", "")).split(".")[-1] != "SUCCESS":
        return False
    for ind in get("threat_indicators", []) or []:
        sev = ind.get("severity") if isinstance(ind, dict) else getattr(ind, "severity", "")
        if str(sev).upper() in FLAGGING_SEVERITIES:
            return True
    return False

class ProviderMaliciousRule(BaseRule):
    """Triggers when a threat intel provider reports malicious indicators or high confidence threat."""
    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE_INT_001",
            name="Threat Intel Provider Flagged Malicious",
            description="External threat intelligence provider flagged an artifact as malicious",
            weight=RiskWeights.HIGH,
            severity="HIGH"
        )

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[RiskFinding], Dict[str, Any]]:
        intel_data = context.get("intel_results", {})
        flagged_artifacts = []

        for category, items in intel_data.items():
            if not isinstance(items, list):
                continue
            for res in items:
                status = getattr(res, "status", None) or (res.get("status") if isinstance(res, dict) else None)
                conf = getattr(res, "confidence", 0.0) if hasattr(res, "confidence") else (res.get("confidence", 0.0) if isinstance(res, dict) else 0.0)
                indicators = getattr(res, "threat_indicators", []) if hasattr(res, "threat_indicators") else (res.get("threat_indicators", []) if isinstance(res, dict) else [])
                provider = getattr(res, "provider", "intel") if hasattr(res, "provider") else res.get("provider", "intel")
                artifact = getattr(res, "artifact", "target") if hasattr(res, "artifact") else res.get("artifact", "target")

                if is_flagged_malicious(res):
                    flagged_artifacts.append((provider, artifact, conf))

        if flagged_artifacts:
            prov, art, conf = flagged_artifacts[0]
            finding = RiskFinding(
                finding_id=f"{self.id}_FINDING",
                title="Provider Malicious Indicator Match",
                description=f"Provider [{prov}] flagged artifact '{art}' with confidence {conf}",
                severity=self.severity,
                score_impact=self.weight,
                artifact=art
            )
            return True, [finding], {"flagged_count": len(flagged_artifacts), "artifacts": flagged_artifacts}
        return False, [], {}


class ProviderConsensusRule(BaseRule):
    """Triggers when multiple independent providers agree an artifact is malicious."""
    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE_INT_002",
            name="Multi-Provider Threat Consensus",
            description="Multiple independent threat intel providers confirmed malicious verdict",
            weight=RiskWeights.CRITICAL,
            severity="CRITICAL"
        )

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[RiskFinding], Dict[str, Any]]:
        intel_data = context.get("intel_results", {})
        artifact_providers: Dict[str, List[str]] = {}

        for category, items in intel_data.items():
            if not isinstance(items, list):
                continue
            for res in items:
                status = getattr(res, "status", None) or (res.get("status") if isinstance(res, dict) else None)
                conf = getattr(res, "confidence", 0.0) if hasattr(res, "confidence") else (res.get("confidence", 0.0) if isinstance(res, dict) else 0.0)
                provider = getattr(res, "provider", "intel") if hasattr(res, "provider") else res.get("provider", "intel")
                artifact = getattr(res, "artifact", "target") if hasattr(res, "artifact") else res.get("artifact", "target")

                if is_flagged_malicious(res) and provider not in artifact_providers.get(artifact, []):
                    artifact_providers.setdefault(artifact, []).append(provider)

        consensus_artifacts = {art: provs for art, provs in artifact_providers.items() if len(provs) >= 2}

        if consensus_artifacts:
            art, provs = next(iter(consensus_artifacts.items()))
            finding = RiskFinding(
                finding_id=f"{self.id}_FINDING",
                title="Multi-Provider Consensus Flag",
                description=f"Multiple providers ({', '.join(provs)}) confirmed malicious status for '{art}'",
                severity=self.severity,
                score_impact=self.weight,
                artifact=art
            )
            return True, [finding], {"consensus_matches": consensus_artifacts}
        return False, [], {}


class ProviderUnavailableRule(BaseRule):
    """Triggers when a provider returned an error or unavailable status."""
    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE_INT_003",
            name="Threat Intel Provider Failure",
            description="One or more threat intelligence providers were unavailable",
            weight=RiskWeights.INFORMATIONAL,
            severity="INFORMATIONAL"
        )

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[RiskFinding], Dict[str, Any]]:
        intel_data = context.get("intel_results", {})
        failed_providers = []

        for category, items in intel_data.items():
            if not isinstance(items, list):
                continue
            for res in items:
                get = (lambda k, d=None, r=res: r.get(k, d)) if isinstance(res, dict) else (lambda k, d=None, r=res: getattr(r, k, d))
                status = get("status")
                status = str(getattr(status, "value", status))
                if status in ("FAILED", "UNAVAILABLE", "RATE_LIMITED"):
                    failed_providers.append((get("provider", "intel"), status, get("artifact", "target"),
                                             get("error_message")))

        if failed_providers:
            provider, status, artifact, error = failed_providers[0]
            description = f"{provider} lookup {status.lower().replace('_', ' ')} for '{artifact}'"
            if error:
                description += f": {str(error)[:160]}"
            if len(failed_providers) > 1:
                description += f" (+{len(failed_providers) - 1} more)"
            finding = RiskFinding(
                finding_id=f"{self.id}_FINDING",
                title="Intel Provider Degradation Notice",
                description=description,
                severity=self.severity,
                score_impact=self.weight,
                artifact=artifact
            )
            return True, [finding], {"failed_providers": [
                {"provider": p, "status": s, "artifact": a, "error": e} for p, s, a, e in failed_providers]}
        return False, [], {}


# Indicator categories that are detections (as opposed to context such as Tor exit nodes or open CVEs)
DETECTION_CATEGORIES = {"Malicious Detection", "Suspicious Detection", "Phishing", "Known Malware", "C2 / Botnet",
                        "Community Flagged"}


class WeakProviderDetectionRule(BaseRule):
    """A provider reported a detection too weak to be a verdict, e.g. one or two VirusTotal engines."""
    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE_INT_005",
            name="Weak Provider Detection",
            description="A threat intel provider reported an uncorroborated detection (e.g. 1-2 VirusTotal engines)",
            weight=RiskWeights.LOW,
            severity="LOW"
        )

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[RiskFinding], Dict[str, Any]]:
        weak = []
        for items in context.get("intel_results", {}).values():
            if not isinstance(items, list):
                continue
            for res in items:
                get = (lambda k, d=None, r=res: r.get(k, d)) if isinstance(res, dict) else (lambda k, d=None, r=res: getattr(r, k, d))
                if str(get("status", "")).split(".")[-1] != "SUCCESS" or is_flagged_malicious(res):
                    continue
                for ind in get("threat_indicators", []) or []:
                    ind_get = ind.get if isinstance(ind, dict) else (lambda k, d=None, i=ind: getattr(i, k, d))
                    if ind_get("category") in DETECTION_CATEGORIES and str(ind_get("severity", "")).upper() == "LOW":
                        weak.append((get("provider", "intel"), get("artifact", "target"), ind_get("description", "")))
                        break
        if weak:
            provider, artifact, detail = weak[0]
            finding = RiskFinding(
                finding_id=f"{self.id}_FINDING",
                title="Uncorroborated Provider Detection",
                description=f"{provider}: {detail}" + (f" (+{len(weak) - 1} more)" if len(weak) > 1 else ""),
                severity=self.severity,
                score_impact=self.weight,
                artifact=artifact
            )
            return True, [finding], {"weak_detections": [{"provider": p, "artifact": a} for p, a, _ in weak]}
        return False, [], {}


# --- Evidence Rules ---

class DefangedIndicatorDetectedRule(BaseRule):
    """Triggers when defanged/obfuscated indicators (hxxps://, [at], [dot]) were present."""
    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE_EVI_001",
            name="Defanged Indicator Obfuscation Detected",
            description="Input contained defanged threat indicators (hxxp, [at], [dot]) indicating evasion attempts",
            weight=RiskWeights.MEDIUM,
            severity="MEDIUM"
        )

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[RiskFinding], Dict[str, Any]]:
        raw_text = context.get("raw_text", "")
        # Check raw text for defanged patterns
        defanged_patterns = ["hxxp", "hxxps", "[.]", "[dot]", "(dot)", "[at]", "(at)", "meow://"]

        matches = [pat for pat in defanged_patterns if pat in raw_text.lower()]

        if matches:
            finding = RiskFinding(
                finding_id=f"{self.id}_FINDING",
                title="Obfuscated Defanged Indicator",
                description=f"Raw payload contained obfuscated indicator notation: {', '.join(matches)}",
                severity=self.severity,
                score_impact=self.weight,
                artifact=matches[0]
            )
            return True, [finding], {"defanged_matches": matches}
        return False, [], {}


class MultipleSuspiciousArtifactsRule(BaseRule):
    """Triggers when a high volume of suspicious artifacts (>= 5) is identified in payload."""
    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE_EVI_002",
            name="High Artifact Density",
            description="Payload contains a high density of extracted indicators (>= 8)",
            weight=RiskWeights.MEDIUM,
            severity="MEDIUM"
        )

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[RiskFinding], Dict[str, Any]]:
        evidence = context.get("evidence", {})
        total_count = sum(len(v) for v in evidence.values() if isinstance(v, list))

        if total_count >= 8:
            finding = RiskFinding(
                finding_id=f"{self.id}_FINDING",
                title="High Indicator Density Detected",
                description=f"Evidence collection extracted a total of {total_count} indicators",
                severity=self.severity,
                score_impact=self.weight,
                artifact=None
            )
            return True, [finding], {"total_count": total_count}
        return False, [], {}


class PublicIPPresentRule(BaseRule):
    """Triggers when public global IP addresses are present in evidence."""
    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE_EVI_003",
            name="Public IP Address Present",
            description="Evidence payload contains public global IP infrastructure",
            weight=RiskWeights.LOW,
            severity="LOW"
        )

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[RiskFinding], Dict[str, Any]]:
        validation = context.get("validation_results", {})
        public_ips = []

        for category in ("ipv4", "ipv6"):
            for item in validation.get(category, []):
                is_valid = getattr(item, "valid", True) if hasattr(item, "valid") else item.get("valid", True)
                props = getattr(item, "properties", {}) if hasattr(item, "properties") else item.get("properties", {})
                art = getattr(item, "artifact", str(item)) if hasattr(item, "artifact") else item.get("artifact", str(item))

                if is_valid and props.get("is_global") is True:
                    public_ips.append(art)

        if public_ips:
            finding = RiskFinding(
                finding_id=f"{self.id}_FINDING",
                title="Public IP Infrastructure",
                description=f"Public routable IP identified in evidence: {', '.join(public_ips[:3])}",
                severity=self.severity,
                score_impact=self.weight,
                artifact=public_ips[0]
            )
            return True, [finding], {"public_ips": public_ips}
        return False, [], {}


# --- Rule Registry ---

class RuleRegistry:
    """
    Registry for managing and executing threat detection rules.
    """

    def __init__(self) -> None:
        self._rules: Dict[str, BaseRule] = {}
        # Register default initial rule library
        self.register_rule(InvalidURLRule())
        self.register_rule(InvalidDomainRule())
        self.register_rule(InvalidEmailRule())
        self.register_rule(ProviderMaliciousRule())
        self.register_rule(ProviderConsensusRule())
        self.register_rule(ProviderUnavailableRule())
        self.register_rule(WeakProviderDetectionRule())
        self.register_rule(DefangedIndicatorDetectedRule())
        self.register_rule(MultipleSuspiciousArtifactsRule())
        self.register_rule(PublicIPPresentRule())

        # Extended content, email, file and intel rule library
        from app.risk_engine.content_rules import EXTENDED_RULES
        for rule_cls in EXTENDED_RULES:
            self.register_rule(rule_cls())

    def register_rule(self, rule: BaseRule) -> None:
        """Registers a new detection rule."""
        if not isinstance(rule, BaseRule):
            raise TypeError("Rule must subclass BaseRule")
        self._rules[rule.id] = rule
        logger.debug(f"Registered risk rule [{rule.id}: {rule.name}]")

    def unregister_rule(self, rule_id: str) -> bool:
        """Unregisters a rule by ID."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            logger.debug(f"Unregistered risk rule [{rule_id}]")
            return True
        return False

    def enable_rule(self, rule_id: str) -> bool:
        """Enables a rule by ID."""
        rule = self._rules.get(rule_id)
        if rule:
            rule.enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disables a rule by ID."""
        rule = self._rules.get(rule_id)
        if rule:
            rule.enabled = False
            return True
        return False

    def get_enabled_rules(self) -> List[BaseRule]:
        """Returns list of enabled rule instances."""
        return [r for r in self._rules.values() if r.enabled]

    def get_all_rules(self) -> List[BaseRule]:
        """Returns list of all registered rule instances."""
        return list(self._rules.values())
