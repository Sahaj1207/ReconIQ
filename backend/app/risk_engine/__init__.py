"""
ReconIQ Risk Engine Package

Purpose:
Core decision-making engine that calculates evidence-based risk scores, evaluates
threat rules, applies dynamic severity weights, and computes confidence ratings.

Responsibilities:
- Provide deterministic threat score calculation (0-100 scale)
- Evaluate rule matches against extracted evidence and threat intel responses
- Calculate confidence ratings based on provider consensus

Future Implementation Notes:
- Dynamic rule engine with YARA / SIGMA-style rule parsing capabilities.

TODO:
- [ ] Implement rule loader for external YAML threat rules.
"""
