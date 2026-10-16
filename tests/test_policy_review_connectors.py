import hashlib
import json
from unittest.mock import Mock, patch

import pytest
from rsat.connectors import fetch_context
from rsat.cli import main
from rsat.policy_review import validate_policy_review
from rsat.model import canonical
from rsat.policy import load_policy


def policy_submission():
    policy = load_policy()
    rule = next(r for r in policy["rules"] if r["id"] == "RSAT-FW-001")
    policy = {**policy, "rules": [rule]}
    fixtures = []
    for state, value, outcome in [
        ("OK", [{"enabled": True}], "PASS"),
        ("OK", [{"enabled": False}], "FAIL"),
        ("UNKNOWN", None, "UNKNOWN"),
    ]:
        observations = [{"id": rule["observation"], "state": state, "value": value}]
        expected = {"RSAT-FW-001": outcome}
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


def test_policy_review_and_negative_unknown_fixtures():
    data = policy_submission()
    assert validate_policy_review(data)["approved_for_signed_publication"]
    data["review"]["policy_sha256"] = "a" * 64
    assert not validate_policy_review(data)["approved_for_signed_publication"]
    data["fixtures"] = data["fixtures"][:1]
    with pytest.raises(ValueError):
        validate_policy_review(data)
    data = policy_submission()
    data["policy"]["rules"][0]["command"] = "evil"
    with pytest.raises(ValueError):
        validate_policy_review(data)
    data = policy_submission()
    data["fixtures"][0]["expected"] = {"RSAT-FW-001": "FAIL"}
    with pytest.raises(ValueError):
        validate_policy_review(data)


def test_policy_review_cli_approval_and_fixture_rejection(tmp_path, capsys):
    source = tmp_path / "reviewed-policy.json"
    output = tmp_path / "review-result.json"
    data = policy_submission()
    source.write_bytes(canonical(data))
    assert main(["policy-review", str(source), "--output", str(output)]) == 0
    assert json.loads(output.read_text())["approved_for_signed_publication"] is True

    data["fixtures"][0]["expected"] = {"RSAT-FW-001": "FAIL"}
    source.write_bytes(canonical(data))
    rejected_output = tmp_path / "rejected-result.json"
    assert main(["policy-review", str(source), "--output", str(rejected_output)]) == 1
    assert not rejected_output.exists()
    assert "expected fixture outcomes" in capsys.readouterr().err


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
