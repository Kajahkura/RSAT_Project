import hashlib
import json
from unittest.mock import Mock, patch

import pytest
from rsat.connectors import fetch_context
from rsat.drafts import validate_draft
from rsat.model import canonical
from rsat.policy import load_policy


def draft():
    policy = load_policy()
    rule = next(r for r in policy["rules"] if r["id"] == "RSAT-FW-001")
    policy = {**policy, "rules": [rule]}
    from rsat.policy import evaluate

    fixtures = []
    for state, value in [("OK", [{"enabled": True}]), ("OK", [{"enabled": False}]), ("UNKNOWN", None)]:
        observations = [{"id": rule["observation"], "state": state, "value": value}]
        expected = {f["id"]: f["status"] for f in evaluate(policy, observations, "Windows")}
        fixtures.append({"platform": "Windows", "observations": observations, "expected": expected})
    return {
        "policy": policy,
        "sources": ["https://example.org/reviewed-source"],
        "fixtures": fixtures,
        "review": {
            "reviewer": "independent reviewer",
            "approved": True,
            "policy_sha256": hashlib.sha256(canonical(policy)).hexdigest(),
        },
    }


def test_policy_draft_review_and_negative_unknown_fixtures():
    data = draft()
    assert validate_draft(data)["approved_for_signed_publication"]
    data["review"]["policy_sha256"] = "a" * 64
    assert not validate_draft(data)["approved_for_signed_publication"]
    data["fixtures"] = data["fixtures"][:1]
    with pytest.raises(ValueError):
        validate_draft(data)
    data = draft()
    data["policy"]["rules"][0]["command"] = "evil"
    with pytest.raises(ValueError):
        validate_draft(data)
    data = draft()
    data["fixtures"][0]["expected"] = {"RSAT-FW-001": "FAIL"}
    with pytest.raises(ValueError):
        validate_draft(data)


def test_connector_transport_subject_redirection_and_size():
    payload = {"subject_id": "test", "claims": [{"mfa": "unknown"}]}
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = json.dumps(payload).encode()
    with patch("rsat.connectors.build_opener") as opener:
        opener.return_value.open.return_value = response
        result = fetch_context("https://example.org/context", "test-token", "identity", "test")
        assert "semantic claims unverified" in result["verification"]
        assert "test-token" not in json.dumps(result)
        payload["subject_id"] = "foreign"
        response.read.return_value = json.dumps(payload).encode()
        with pytest.raises(ValueError):
            fetch_context("https://example.org/context", "test-token", "identity", "test")
        response.read.return_value = b"x" * 1_000_001
        with pytest.raises(ValueError):
            fetch_context("https://example.org/context", "test-token", "identity", "test")
    for url in ["http://example.org", "file:///etc/passwd", "https://user:secret@example.org"]:
        with pytest.raises(ValueError):
            fetch_context(url, "token", "identity", "test")
    with pytest.raises(ValueError):
        fetch_context("https://example.org", "token\nsecret", "identity", "test")
