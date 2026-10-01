"""Constrained declarative rules. Policies cannot run commands or Python code."""

from dataclasses import asdict
from datetime import datetime, timezone
from importlib.resources import files
import json
from pathlib import Path

from .model import Finding

OPERATORS = {"eq", "ne", "ge", "le", "in", "not_in", "nonempty", "empty"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}


def load_policy(path=None):
    raw = Path(path).read_bytes() if path else files("rsat").joinpath("policies/core.json").read_bytes()
    if len(raw) > 1_000_000:
        raise ValueError("Policy too large")
    return validate_policy(json.loads(raw))


def validate_policy(data):
    if not isinstance(data, dict) or data.get("schema_version") != "1.0":
        raise ValueError("Unsupported policy schema")
    if not isinstance(data.get("version"), str) or not isinstance(data.get("rules"), list):
        raise ValueError("Invalid policy metadata")
    seen = set()
    if len(data["rules"]) > 1000:
        raise ValueError("Too many rules")
    for rule in data["rules"]:
        allowed = {
            "id",
            "title",
            "platforms",
            "observation",
            "path",
            "operator",
            "expected",
            "severity",
            "remediation",
            "references",
            "mode",
        }
        if not isinstance(rule, dict) or set(rule) - allowed:
            raise ValueError("Unknown policy field; executable rules are not supported")
        for key in ("id", "title", "observation", "operator", "severity", "remediation"):
            if not isinstance(rule.get(key), str) or not rule[key]:
                raise ValueError(f"Invalid rule field: {key}")
        if rule["id"] in seen or rule["operator"] not in OPERATORS or rule["severity"] not in SEVERITIES:
            raise ValueError("Duplicate ID or unsupported rule operator/severity")
        seen.add(rule["id"])
        if rule.get("mode", "scalar") not in {"scalar", "all", "any"}:
            raise ValueError("Invalid rule mode")
        if not isinstance(rule.get("platforms"), list) or not rule["platforms"]:
            raise ValueError("Rule platforms required")
        if any(p not in {"Windows", "Darwin", "Linux"} for p in rule["platforms"]):
            raise ValueError("Unknown policy platform")
        if not isinstance(rule.get("path", ""), str):
            raise ValueError("Invalid rule path")
        refs = rule.get("references", [])
        if not isinstance(refs, list) or any(
            not isinstance(x, str) or not x.startswith("https://") for x in refs
        ):
            raise ValueError("Rule references must be HTTPS URLs")
    return data


def extract(value, path):
    for part in path.split(".") if path else []:
        if not isinstance(value, dict) or part not in value:
            raise KeyError(path)
        value = value[part]
    if value is None:
        raise KeyError(path)
    return value


def compare(actual, operator, expected):
    if actual is None:
        raise ValueError("Missing value")
    if operator in {"eq", "ne"}:
        if isinstance(expected, bool) and not isinstance(actual, bool):
            raise ValueError("Expected boolean evidence")
        if isinstance(expected, (int, float)) and not isinstance(expected, bool):
            if isinstance(actual, bool) or not isinstance(actual, (int, float)):
                raise ValueError("Expected numeric evidence")
        return (actual == expected) if operator == "eq" else (actual != expected)
    if operator in {"ge", "le"}:
        if isinstance(actual, bool) or not isinstance(actual, (int, float)):
            raise ValueError("Expected numeric evidence")
        return actual >= expected if operator == "ge" else actual <= expected
    if operator == "in":
        return actual in expected
    if operator == "not_in":
        return actual not in expected
    if not isinstance(actual, (list, dict, str)):
        raise ValueError("Expected collection evidence")
    return bool(actual) if operator == "nonempty" else not actual


def evaluate(policy, observations, os_type):
    evidence = {o["id"]: o for o in observations}
    findings = []
    for rule in policy["rules"]:
        obs = evidence.get(rule["observation"])
        status, details = "UNKNOWN", "No evidence collected"
        if os_type not in rule["platforms"]:
            status, details = "NOT_APPLICABLE", "Rule does not apply to this platform"
        elif (
            rule["id"] == "RSAT-REMOTE-001"
            and obs
            and obs.get("state") == "OK"
            and isinstance(obs.get("value"), dict)
            and obs["value"].get("enabled") is False
        ):
            status, details = "NOT_APPLICABLE", "RDP is disabled; NLA requirement does not apply"
        elif obs and obs["state"] != "OK":
            status, details = obs["state"], obs.get("reason") or "Evidence unavailable"
        elif obs:
            try:
                mode = rule.get("mode", "scalar")
                values = obs["value"] if mode != "scalar" else [obs["value"]]
                if not isinstance(values, list) or not values:
                    raise ValueError("No applicable evidence values")
                checks = [
                    compare(extract(v, rule.get("path", "")), rule["operator"], rule.get("expected"))
                    for v in values
                ]
                passed = any(checks) if mode == "any" else all(checks)
                status = "PASS" if passed else "FAIL"
                details = "Evidence satisfies the rule" if passed else "Evidence does not satisfy the rule"
            except (KeyError, ValueError, TypeError):
                details = "Missing or incompatible evidence; no pass can be established"
        findings.append(
            asdict(
                Finding(
                    rule["id"],
                    rule["title"],
                    status,
                    rule["severity"],
                    [rule["observation"]] if obs else [],
                    details,
                    rule["remediation"],
                    policy["version"],
                    rule.get("references", []),
                )
            )
        )
    return findings


def coverage(findings):
    counts = {
        state: sum(f["status"] == state for f in findings)
        for state in ("PASS", "FAIL", "UNKNOWN", "ERROR", "NOT_APPLICABLE")
    }
    applicable = len(findings) - counts["NOT_APPLICABLE"]
    assessed = counts["PASS"] + counts["FAIL"]
    return {
        **counts,
        "applicable": applicable,
        "assessed": assessed,
        "assessed_percent": round(100 * assessed / applicable, 1) if applicable else 0,
    }


def apply_exceptions(findings, exceptions):
    now = datetime.now(timezone.utc)
    if not isinstance(exceptions, list):
        raise ValueError("Exceptions must be a list")
    seen = set()
    for exception in exceptions:
        if not isinstance(exception, dict) or not all(
            isinstance(exception.get(k), str) and exception[k] for k in ("control_id", "reason", "expires_at")
        ):
            raise ValueError("Exception requires control_id, reason, and expires_at")
        if exception["control_id"] in seen:
            raise ValueError("Duplicate exception")
        seen.add(exception["control_id"])
        expiry = datetime.fromisoformat(exception["expires_at"].replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            raise ValueError("Exception expiry must include timezone")
        matching = next((f for f in findings if f["id"] == exception["control_id"]), None)
        if matching is None:
            raise ValueError("Exception refers to an unknown control")
        matching["exception"] = {**exception, "expired": expiry <= now}
    return findings
