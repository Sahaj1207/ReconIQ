"""
STIX 2.1 bundle export.

Produces a self-contained bundle: a ReconIQ identity, cyber-observable objects for every
indicator (deterministic UUIDv5 IDs per the STIX spec), indicator SDOs for artifacts implicated
by findings or intel, attack-pattern SDOs for mapped ATT&CK techniques, relationships, and a
report SDO that references all of them.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# STIX 2.1 namespace for deterministic SCO identifiers (spec section 2.9)
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
IDENTITY_ID = "identity--5c2a8f7e-3b8e-4a5f-9b8f-7a1f0c6e2d11"

SCO_TYPES = {"ipv4": "ipv4-addr", "ipv6": "ipv6-addr", "domains": "domain-name", "urls": "url", "emails": "email-addr"}
HASH_NAMES = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


def _ts(value: Optional[str] = None) -> str:
    dt = datetime.fromisoformat(value) if value else datetime.now(timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _sco_id(sco_type: str, contributing: Dict[str, Any]) -> str:
    canonical = json.dumps(contributing, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{sco_type}--{uuid.uuid5(SCO_NAMESPACE, canonical)}"


def _sdo_id(sdo_type: str, *parts: str) -> str:
    """Stable SDO IDs so re-exporting the same investigation yields the same bundle."""
    return f"{sdo_type}--{uuid.uuid5(SCO_NAMESPACE, '|'.join(parts))}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def build_stix_bundle(result: Dict[str, Any]) -> Dict[str, Any]:
    inv_id = result["investigation_id"]
    created = _ts(result.get("timestamp"))
    risk = result.get("risk_assessment") or {}
    evidence = result.get("normalized_evidence") or result.get("evidence") or {}
    intel = result.get("threat_intelligence") or {}

    objects: List[Dict[str, Any]] = [{
        "type": "identity", "spec_version": "2.1", "id": IDENTITY_ID, "created": created, "modified": created,
        "name": "ReconIQ", "identity_class": "system",
    }]
    patterns: Dict[str, str] = {}  # artifact value -> STIX pattern

    for cat, sco_type in SCO_TYPES.items():
        for value in evidence.get(cat, []):
            objects.append({"type": sco_type, "spec_version": "2.1", "id": _sco_id(sco_type, {"value": value}), "value": value})
            patterns[value] = f"[{sco_type}:value = '{_escape(value)}']"
    for digest in evidence.get("hashes", []):
        algo = HASH_NAMES.get(len(digest))
        if not algo:
            continue
        hashes = {algo: digest}
        objects.append({"type": "file", "spec_version": "2.1", "id": _sco_id("file", {"hashes": hashes}), "hashes": hashes})
        patterns[digest] = f"[file:hashes.'{algo}' = '{digest}']"

    # Artifacts implicated by findings or flagged by intel become indicators
    implicated: Dict[str, List[Dict[str, Any]]] = {}
    for finding in risk.get("findings", []):
        art = finding.get("artifact")
        if art in patterns and finding.get("score_impact", 0) > 0:
            implicated.setdefault(art, []).append(finding)
    flagged = {r["artifact"] for items in intel.values() for r in items if r.get("threat_indicators")}
    for art in flagged:
        if art in patterns:
            implicated.setdefault(art, [])

    attack_ids: Dict[str, str] = {}
    for tech in risk.get("mitre_techniques", []):
        ap_id = _sdo_id("attack-pattern", tech["id"])
        attack_ids[tech["id"]] = ap_id
        objects.append({
            "type": "attack-pattern", "spec_version": "2.1", "id": ap_id, "created": created, "modified": created,
            "created_by_ref": IDENTITY_ID, "name": tech["name"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tech["tactic"].lower().replace(" ", "-")}],
            "external_references": [{"source_name": "mitre-attack", "external_id": tech["id"], "url": tech["url"]}],
        })

    for art, findings in implicated.items():
        ind_id = _sdo_id("indicator", inv_id, art)
        malicious = art in flagged or any(f.get("severity") in ("HIGH", "CRITICAL") for f in findings)
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": ind_id, "created": created, "modified": created,
            "created_by_ref": IDENTITY_ID, "name": f"ReconIQ indicator: {art}",
            "description": "; ".join(f["title"] for f in findings) or "Flagged by threat intelligence",
            "indicator_types": ["malicious-activity" if malicious else "anomalous-activity"],
            "pattern": patterns[art], "pattern_type": "stix", "valid_from": created,
            "confidence": int(round((risk.get("confidence") or 0) * 100)),
            "labels": sorted({c for f in findings for c in f.get("categories", [])}),
        })
        for tech_id in sorted({t["id"] for f in findings for t in f.get("mitre_techniques", [])}):
            if tech_id in attack_ids:
                objects.append({
                    "type": "relationship", "spec_version": "2.1", "id": _sdo_id("relationship", ind_id, tech_id),
                    "created": created, "modified": created, "created_by_ref": IDENTITY_ID,
                    "relationship_type": "indicates", "source_ref": ind_id, "target_ref": attack_ids[tech_id],
                })

    summary = (result.get("analyst_report") or {}).get("summary")
    objects.append({
        "type": "report", "spec_version": "2.1", "id": _sdo_id("report", inv_id), "created": created, "modified": created,
        "created_by_ref": IDENTITY_ID, "name": f"ReconIQ investigation {inv_id}",
        "description": summary or f"{risk.get('severity', 'INFORMATIONAL')} risk assessment ({risk.get('total_score', 0)}/100)",
        "report_types": ["threat-report"], "published": created,
        "labels": [risk.get("classification", "no_threat_identified")],
        "object_refs": [o["id"] for o in objects if o["id"] != IDENTITY_ID] or [IDENTITY_ID],
        "x_reconiq_score": risk.get("total_score", 0), "x_reconiq_severity": risk.get("severity"),
        "x_reconiq_investigation_id": inv_id,
    })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
