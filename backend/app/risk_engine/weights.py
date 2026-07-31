"""
ReconIQ Risk Weights Matrix

Purpose:
Defines numeric severity weights and risk impact constants per threat indicator type.

Responsibilities:
- Maintain severity weight maps across indicator categories (IPs, Domains, URLs, Emails)
- Provide configurable multiplier tables based on provider confidence

Future Implementation Notes:
- Dynamic adjustment of weights based on user policy overrides.

TODO:
- [ ] Implement RiskWeights configuration mapping table.
"""

from typing import Dict

# Default Weight Matrix Constants (Placeholder)
DEFAULT_CATEGORY_WEIGHTS: Dict[str, float] = {
    "malicious_url": 35.0,
    "malicious_ip": 25.0,
    "disposable_email": 15.0,
    "high_risk_domain": 20.0,
    "suspicious_phone": 10.0,
}
