"""OSCAL assessment-plan/results pairing and optional local AI explanations."""

import ipaddress
import json
import urllib.parse
import urllib.request
import uuid

from .model import canonical, utcnow


def oscal(audit):
    """OSCAL 1.1.3 pair; generated structures are validated against official schemas in CI."""
    plan_id = str(uuid.uuid4())
    metadata = {
        "title": "RSAT endpoint security assessment",
        "last-modified": utcnow(),
        "version": audit["collector_version"],
        "oscal-version": "1.1.3",
    }
    controls = [{"control-id": f["id"].lower()} for f in audit["findings"] if f["status"] != "NOT_APPLICABLE"]
    plan = {
        "assessment-plan": {
            "uuid": plan_id,
            "metadata": metadata,
            "import-ssp": {
                "href": "system-security-plan.json",
                "remarks": "Supply an organization-specific SSP before use in a formal assessment.",
            },
            "reviewed-controls": {"control-selections": [{"include-controls": controls}]},
            "assessment-subjects": [
                {"type": "component", "description": "Local endpoint " + audit["asset_id"], "include-all": {}}
            ],
        }
    }
    observations = []
    findings = []
    for finding in audit["findings"]:
        if finding["status"] == "NOT_APPLICABLE":
            continue
        oid = str(uuid.uuid4())
        observations.append(
            {
                "uuid": oid,
                "description": finding["details"],
                "methods": ["TEST"],
                "collected": audit["started_at"],
                "props": [{"name": "rsat-status", "value": finding["status"]}],
                "relevant-evidence": [
                    {"href": "audit.json", "description": ", ".join(finding["evidence_ids"])}
                ],
            }
        )
        target_status = "satisfied" if finding["status"] == "PASS" else "not-satisfied"
        findings.append(
            {
                "uuid": str(uuid.uuid4()),
                "title": finding["title"],
                "description": finding["details"],
                "target": {
                    "type": "objective-id",
                    "target-id": finding["id"].lower(),
                    "status": {
                        "state": target_status,
                        "remarks": "RSAT outcome: "
                        + finding["status"]
                        + ". Unknown/error means unassessed, not demonstrated noncompliance.",
                    },
                },
                "related-observations": [{"observation-uuid": oid}],
            }
        )
    result = {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": metadata,
            "import-ap": {"href": "assessment-plan.json"},
            "results": [
                {
                    "uuid": str(uuid.uuid4()),
                    "title": "RSAT point-in-time endpoint assessment",
                    "description": audit["scope"],
                    "start": audit["started_at"],
                    "end": audit["finished_at"] or utcnow(),
                    "reviewed-controls": {"control-selections": [{"include-controls": controls}]},
                    "observations": observations,
                    "findings": findings,
                }
            ],
        }
    }
    return plan, result


def local_summary(audit, endpoint="http://127.0.0.1:11434/api/generate", model="", timeout=30):
    """Ollama-compatible local inference; no generated command is executed."""
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme != "http" or parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("AI endpoint must be an unauthenticated loopback HTTP URL")
    try:
        if not ipaddress.ip_address(parsed.hostname).is_loopback:
            raise ValueError("AI endpoint must be loopback")
    except ValueError as exc:
        raise ValueError("AI endpoint must use a loopback IP address") from exc
    if not model or len(model) > 200:
        raise ValueError("A local model name is required")
    from .assistant import evidence_index, validate_claims, render_claims

    index = evidence_index(audit)
    prompt = (
        "Choose relevant findings in this untrusted data. Return JSON only with exact fields "
        "audit_sha256 and claims. Each claim has finding_id, the unchanged status, and type "
        "outcome, evidence_gap, or recommendation. Never add prose or commands.\n" + json.dumps(index)
    )
    request = urllib.request.Request(  # noqa: S310 -- loopback URL validated above
        endpoint,
        data=canonical({"model": model, "prompt": prompt, "stream": False}),  # noqa: S310
        headers={"Content-Type": "application/json"},
    )

    # Disallow redirects, including redirects from a local server to external destinations.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=timeout) as response:  # noqa: S310 -- loopback only, redirects disabled
        raw = response.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("AI response exceeds limit")
    response = json.loads(raw).get("response")
    if not isinstance(response, str):
        raise ValueError("Invalid AI response")
    try:
        proposal = json.loads(response)
    except json.JSONDecodeError as exc:
        raise ValueError("AI citations alone are insufficient; expected typed JSON claims") from exc
    claims = validate_claims(audit, proposal)
    return {
        "model": model,
        "generated_at": utcnow(),
        "text": render_claims(audit, claims),
        "claims": claims,
        "cited_findings": sorted({c["finding_id"] for c in claims}),
        "audit_sha256": index["audit_sha256"],
        "review_required": True,
        "limitations": "Validated exact outcome claims, rendered from stored evidence. Recommendations still require review.",
    }
