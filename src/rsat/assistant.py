"""Evidence-scoped assistance: models select validated claims, never control outcomes."""

import hashlib
from datetime import datetime, timezone

from .model import canonical, validate_audit, utcnow

CLAIM_TYPES = {"outcome", "evidence_gap", "recommendation"}


def evidence_index(audit):
    validate_audit(audit)
    return {
        "audit_id": audit["audit_id"],
        "audit_sha256": hashlib.sha256(canonical(audit)).hexdigest(),
        "scope": audit["scope"],
        "claims": [
            {
                "finding_id": finding["id"],
                "status": finding["status"],
                "title": finding["title"],
                "rule_version": finding["rule_version"],
                "severity": finding["severity"],
                "evidence_ids": finding["evidence_ids"],
                "pointer": f"/findings/{index}/status",
                "details": finding["details"],
                "recommendation": finding["remediation"],
            }
            for index, finding in enumerate(audit["findings"])
        ],
    }


def validate_claims(audit, proposal):
    """Only exact typed selections may reach rendering; model prose is not accepted."""
    index = evidence_index(audit)
    if not isinstance(proposal, dict) or set(proposal) != {"audit_sha256", "claims"}:
        raise ValueError(
            "AI claims require exact audit binding and typed claims; prose/citations alone are invalid"
        )
    if proposal["audit_sha256"] != index["audit_sha256"]:
        raise ValueError("AI claims refer to a different or changed audit")
    claims = proposal["claims"]
    if not isinstance(claims, list) or not 1 <= len(claims) <= 100:
        raise ValueError("Expected 1-100 typed AI claims")
    findings = {f["finding_id"]: f for f in index["claims"]}
    checked = []
    for claim in claims:
        if not isinstance(claim, dict) or set(claim) != {"finding_id", "status", "type"}:
            raise ValueError("Unsupported AI claim fields")
        finding = findings.get(claim["finding_id"])
        if finding is None or claim["status"] != finding["status"] or claim["type"] not in CLAIM_TYPES:
            raise ValueError("AI claim contradicts evidence or contains invalid citations")
        if claim["type"] == "evidence_gap" and finding["status"] not in {"UNKNOWN", "ERROR"}:
            raise ValueError("AI evidence-gap claim contradicts the finding")
        checked.append({**claim, "pointer": finding["pointer"], "evidence_ids": finding["evidence_ids"]})
    return checked


def render_claims(audit, claims):
    findings = {f["id"]: f for f in audit["findings"]}
    lines = []
    for claim in claims:
        finding = findings[claim["finding_id"]]
        detail = finding["remediation"] if claim["type"] == "recommendation" else finding["details"]
        lines.append(f"[{finding['id']}] {finding['status']}: {finding['title']}. {detail}")
    return "\n".join(lines)


def answer(audit, question, finding_ids=None):
    """Deterministic retrieval works offline; no claims of general semantic understanding."""
    index = evidence_index(audit)
    if not isinstance(question, str) or not 1 <= len(question) <= 2000:
        raise ValueError("Question must contain 1-2000 characters")
    identifiers = finding_ids or []
    if not isinstance(identifiers, list) or any(not isinstance(x, str) for x in identifiers):
        raise ValueError("Invalid finding selection")
    unknown = set(identifiers) - {f["finding_id"] for f in index["claims"]}
    if unknown:
        raise ValueError("Unknown finding selection")
    terms = {word.lower().strip("?,.:") for word in question.split() if len(word) > 3}
    candidates = [f for f in index["claims"] if f["status"] != "NOT_APPLICABLE"]
    if identifiers:
        selected = [f for f in candidates if f["finding_id"] in identifiers]
    else:
        selected = sorted(
            candidates,
            key=lambda f: (
                -sum(word in (f["title"] + " " + f["finding_id"]).lower() for word in terms),
                {"FAIL": 0, "ERROR": 1, "UNKNOWN": 2, "PASS": 3}[f["status"]],
            ),
        )[:5]
    claims = [{"finding_id": f["finding_id"], "status": f["status"], "type": "outcome"} for f in selected]
    checked = (
        validate_claims(audit, {"audit_sha256": index["audit_sha256"], "claims": claims}) if claims else []
    )
    return {
        "mode": "offline deterministic evidence retrieval",
        "question": question,
        "audit_id": audit["audit_id"],
        "audit_sha256": index["audit_sha256"],
        "scope": index["scope"],
        "claims": checked,
        "text": render_claims(audit, checked),
        "abstained": not checked,
        "generated_at": utcnow(),
        "limitations": "Retrieves matching controls; it does not infer compromise or authorize changes.",
    }


def adaptive_plan(audit, max_checks=5, max_age_hours=24):
    from .recheck import CAPABILITIES

    validate_audit(audit)
    if not 1 <= max_checks <= 20 or not 1 <= max_age_hours <= 8760:
        raise ValueError("Invalid adaptive planning budget")
    missing = {i for f in audit["findings"] if f["status"] in {"UNKNOWN", "ERROR"} for i in f["evidence_ids"]}
    now = datetime.now(timezone.utc)
    for observation in audit["observations"]:
        try:
            timestamp = datetime.fromisoformat(observation.get("collected_at", "").replace("Z", "+00:00"))
            if timestamp.tzinfo is None or (now - timestamp).total_seconds() > max_age_hours * 3600:
                missing.add(observation["id"])
        except ValueError:
            missing.add(observation["id"])
    suggestions = [
        {
            "capability": name,
            "observation_id": capability["observation_id"],
            "reason": "Missing, failed or stale evidence",
            "estimated_cost_seconds": 15,
            "read_only": True,
            "network": False,
        }
        for name, capability in CAPABILITIES.items()
        if capability["platform"] == audit["platform"] and capability["observation_id"] in missing
    ][:max_checks]
    return {
        "audit_id": audit["audit_id"],
        "suggestions": suggestions,
        "execution_authorized": False,
        "limitations": "Prioritizes evidence gaps using fixed capabilities; no model-created commands.",
    }
