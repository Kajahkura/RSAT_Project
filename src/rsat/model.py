"""Versioned audit data shared by collectors, policies, and reports."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import platform
import uuid

from . import __version__

SCHEMA_VERSION = "2.0"
STATES = {"PASS", "FAIL", "UNKNOWN", "ERROR", "NOT_APPLICABLE"}


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass
class Observation:
    id: str
    value: object = None
    state: str = "OK"
    source: str = "native"
    collected_at: str = field(default_factory=utcnow)
    reason: str = ""
    duration_ms: int = 0


@dataclass
class Finding:
    id: str
    title: str
    status: str
    severity: str
    evidence_ids: list[str]
    details: str
    remediation: str
    rule_version: str
    references: list[str] = field(default_factory=list)
    exception: dict | None = None


def new_audit(asset_salt="", include_hostname=False):
    hostname = platform.node()
    # A salt is required for linking assets across engagements without publishing hostnames.
    asset_id = (
        hmac.new(asset_salt.encode(), hostname.encode(), hashlib.sha256).hexdigest()
        if asset_salt
        else hashlib.sha256(hostname.encode()).hexdigest()
    )[:24]
    return {
        "schema_version": SCHEMA_VERSION,
        "collector_version": __version__,
        "audit_id": str(uuid.uuid4()),
        "asset_id": asset_id,
        "target_fingerprint": hashlib.sha256(hostname.encode("utf-8")).hexdigest(),
        "asset_id_scope": "engagement" if asset_salt else "unsalted-hostname-hash",
        "hostname": hostname if include_hostname else None,
        "platform": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "started_at": utcnow(),
        "finished_at": None,
        "scope": "local endpoint; no external reachability verified",
        "observations": [],
        "findings": [],
        "risks": [],
        "vulnerabilities": [],
        "coverage": {},
    }


def serialize(items):
    return [asdict(x) for x in items]


def validate_audit(data):
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported audit schema version")
    for key in ("audit_id", "asset_id", "platform", "started_at", "collector_version"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise ValueError(f"Invalid audit field: {key}")
    for key in ("findings", "observations", "risks", "vulnerabilities"):
        if not isinstance(data.get(key), list):
            raise ValueError(f"Invalid audit list: {key}")
    ids = set()
    for obs in data["observations"]:
        if not isinstance(obs, dict) or not isinstance(obs.get("id"), str):
            raise ValueError("Invalid observation")
        if obs["id"] in ids or obs.get("state") not in {"OK", "UNKNOWN", "ERROR", "NOT_APPLICABLE"}:
            raise ValueError("Duplicate observation or invalid state")
        ids.add(obs["id"])
    ids = set()
    for finding in data["findings"]:
        if not isinstance(finding, dict) or finding.get("status") not in STATES:
            raise ValueError("Invalid finding status")
        if not isinstance(finding.get("id"), str) or finding["id"] in ids:
            raise ValueError("Duplicate or missing finding ID")
        if not isinstance(finding.get("evidence_ids"), list):
            raise ValueError("Invalid finding evidence")
        for key in ("title", "details", "remediation", "rule_version", "severity"):
            if not isinstance(finding.get(key), str):
                raise ValueError(f"Invalid finding field: {key}")
        ids.add(finding["id"])
    return data
