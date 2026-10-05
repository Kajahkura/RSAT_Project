"""Original exports and explicitly trusted external evidence adapters."""

import hashlib
import re
from datetime import datetime, timezone
from urllib.parse import quote

from .model import canonical, validate_audit, utcnow


def sbom(audit):
    validate_audit(audit)
    inventory = next(
        (
            o.get("value")
            for o in audit["observations"]
            if o["id"] == "software.inventory" and o["state"] == "OK"
        ),
        [],
    )
    if not isinstance(inventory, list):
        raise ValueError("Invalid software inventory")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": utcnow(),
            "component": {"type": "device", "name": "RSAT asset " + audit["asset_id"]},
            "properties": [
                {
                    "name": "rsat:scope",
                    "value": "Collected installed package inventory; not binary composition or exhaustive AI provenance",
                }
            ],
        },
        "components": [
            {
                "type": "library",
                "name": p["name"],
                "version": p["version"],
                "purl": p.get("purl")
                or f"pkg:generic/{quote(p['name'], safe='')}@{quote(p['version'], safe='')}",
                "properties": [{"name": "rsat:ecosystem", "value": p.get("ecosystem", "unknown")}],
            }
            for p in inventory
            if isinstance(p, dict) and isinstance(p.get("name"), str) and isinstance(p.get("version"), str)
        ],
    }


def mlbom(manifest):
    if not isinstance(manifest, dict) or set(manifest) != {"models", "datasets"}:
        raise ValueError("ML-BOM requires explicit models and datasets metadata")
    components = []
    for group, kind in [("models", "machine-learning-model"), ("datasets", "data")]:
        if not isinstance(manifest[group], list) or len(manifest[group]) > 1000:
            raise ValueError("Invalid ML-BOM metadata count")
        for item in manifest[group]:
            if not isinstance(item, dict) or set(item) - {"name", "version", "sha256", "license", "source"}:
                raise ValueError("Unsupported ML-BOM metadata fields")
            if not isinstance(item.get("name"), str) or not re.fullmatch(
                "[a-f0-9]{64}", item.get("sha256", "")
            ):
                raise ValueError("ML-BOM needs a name and SHA-256 identity")
            component = {
                "type": kind,
                "name": item["name"],
                "hashes": [{"alg": "SHA-256", "content": item["sha256"]}],
                "properties": [
                    {
                        "name": "rsat:provenance",
                        "value": "Operator-supplied; hash/source not independently verified",
                    }
                ],
            }
            if item.get("version"):
                component["version"] = item["version"]
            if item.get("license"):
                component["licenses"] = [{"license": {"name": item["license"]}}]
            if item.get("source"):
                component["externalReferences"] = [{"type": "distribution", "url": item["source"]}]
            components.append(component)
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}


def ocsf(audit):
    validate_audit(audit)
    epoch = int(datetime.fromisoformat(audit["started_at"].replace("Z", "+00:00")).timestamp() * 1000)
    severities = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    return [
        {
            "class_uid": 2003,
            "category_uid": 2,
            "activity_id": 1,
            "type_uid": 200301,
            "time": epoch,
            "severity_id": severities[f["severity"]],
            "metadata": {
                "version": "1.3.0",
                "product": {"name": "RSAT", "vendor_name": "OFINFIX", "version": audit["collector_version"]},
            },
            "finding_info": {"uid": f["id"], "title": f["title"], "desc": f["details"]},
            "compliance": {
                "status_id": {"PASS": 1, "FAIL": 3}.get(f["status"], 2),
                "status": {"PASS": "Pass", "FAIL": "Fail"}.get(f["status"], "Warning"),
                "requirements": [f["id"]],
                "standards": ["RSAT original endpoint policy " + f["rule_version"]],
            },
            "unmapped": {
                "rsat_outcome": f["status"],
                "rule_version": f["rule_version"],
                "evidence_ids": f["evidence_ids"],
                "scope": audit["scope"],
            },
        }
        for f in audit["findings"]
        if f["status"] != "NOT_APPLICABLE"
    ]


def trusted_vex(vulnerabilities, document, product_ids, max_age_days=30):
    """Call only after pinned-signature verification; keep original evidence and decisions."""
    if not isinstance(document, dict) or not isinstance(document.get("statements"), list):
        raise ValueError("Expected an OpenVEX statements document")
    timestamp = datetime.fromisoformat(document["timestamp"].replace("Z", "+00:00"))
    if (
        timestamp.tzinfo is None
        or not 0 <= (datetime.now(timezone.utc) - timestamp).total_seconds() <= max_age_days * 86400
    ):
        raise ValueError("VEX document is stale or has an invalid timestamp")
    results = []
    for vulnerability in vulnerabilities:
        result = dict(vulnerability)
        decisions = []
        for statement in document["statements"]:
            name = statement.get("vulnerability", {}).get("name")
            ids = [vulnerability["id"], *vulnerability.get("aliases", [])]
            products = {p.get("@id") for p in statement.get("products", []) if isinstance(p, dict)}
            if name not in ids or not products & set(product_ids):
                continue
            status = statement.get("status")
            if status not in {"affected", "not_affected", "fixed", "under_investigation"}:
                raise ValueError("Invalid VEX status")
            if status == "not_affected" and not (
                statement.get("justification") or statement.get("impact_statement")
            ):
                raise ValueError("VEX dismissal requires justification")
            decisions.append(
                {
                    "status": status,
                    "justification": statement.get("justification"),
                    "impact_statement": statement.get("impact_statement"),
                    "product_ids": sorted(products),
                    "publisher_signature_verified": True,
                    "timestamp": document["timestamp"],
                }
            )
        result["vex_decisions"] = decisions
        results.append(result)
    return results


def external_evidence(data):
    """An imported attestation is never promoted to independently verified telemetry."""
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != "1.0"
        or data.get("kind") not in {"identity", "cloud", "mdm", "attestation"}
    ):
        raise ValueError("Invalid external evidence contract")
    required = ["subject_id", "source", "collected_at", "claims"]
    if any(key not in data for key in required) or not isinstance(data["claims"], list):
        raise ValueError("Missing external evidence metadata")
    return {
        **data,
        "import_sha256": hashlib.sha256(canonical(data)).hexdigest(),
        "verification": "unverified import",
        "limitations": "External claims need a trusted connector/verifier and independently associated subject.",
    }


def verify_document(envelope, pinned_key):
    """Verify exact publisher document with an independently pinned Ed25519 key."""
    import base64
    from pathlib import Path
    from .bundle import crypto

    if not isinstance(envelope, dict) or set(envelope) != {"document", "signature"}:
        raise ValueError("Invalid signed publisher envelope")
    document = envelope["document"]
    if not isinstance(document, dict):
        raise ValueError("Invalid publisher document")
    crypto().verify(
        crypto().load_key(Path(pinned_key).read_bytes(), "Ed25519"),
        base64.b64decode(envelope["signature"], validate=True),
        canonical(document),
    )
    return document


def csaf(document):
    """Extract vendor product IDs and status declarations without speculative package matching."""
    if not isinstance(document, dict) or document.get("document", {}).get("csaf_version") != "2.0":
        raise ValueError("Expected CSAF 2.0")
    metadata = document["document"]
    tracking = metadata.get("tracking", {})
    timestamp = tracking.get("current_release_date")
    if not isinstance(timestamp, str):
        raise ValueError("CSAF release timestamp missing")
    when = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if when.tzinfo is None or not 0 <= (datetime.now(timezone.utc) - when).total_seconds() <= 30 * 86400:
        raise ValueError("CSAF release is stale or invalid")
    entries = document.get("vulnerabilities", [])
    if not isinstance(entries, list) or len(entries) > 10000:
        raise ValueError("Invalid CSAF vulnerability list")
    results = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("product_status", {}), dict):
            raise ValueError("Invalid CSAF vulnerability")
        statuses = entry.get("product_status", {})
        if any(
            not isinstance(value, list) or any(not isinstance(x, str) for x in value)
            for value in statuses.values()
        ):
            raise ValueError("Invalid CSAF product IDs")
        results.append(
            {
                "cve": entry.get("cve"),
                "title": entry.get("title"),
                "product_status": statuses,
                "publisher_signature_verified": True,
                "source_release": timestamp,
                "limitations": "Vendor product IDs require an independently verified mapping to collected packages.",
            }
        )
    return {
        "publisher": metadata.get("publisher"),
        "tracking_id": tracking.get("id"),
        "vulnerabilities": results,
    }
