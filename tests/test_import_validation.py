"""Malformed imported evidence fails cleanly before report processing."""

import json

import pytest

from rsat.cli import main
from rsat.model import validate_audit


@pytest.mark.parametrize(
    "field,value",
    [
        ("references", [123]),
        ("references", "https://example.com"),
        ("evidence_ids", [{}]),
        ("exception", {"expired": "no", "reason": "test", "expires_at": "future"}),
        ("exception", {"expired": False}),
        ("severity", "safe"),
    ],
)
def test_malformed_findings_are_rejected(audit, field, value):
    audit["findings"][0][field] = value
    with pytest.raises(ValueError):
        validate_audit(audit)


@pytest.mark.parametrize("risk", [None, {}, {"id": "test", "factors": "text"}])
def test_malformed_risks_are_rejected(audit, risk):
    audit["risks"] = [risk]
    with pytest.raises(ValueError):
        validate_audit(audit)


@pytest.mark.parametrize("value", ["0.8", float("nan"), True, 1.1, -0.1])
def test_invalid_vulnerability_priority_rejected(audit, value):
    audit["vulnerabilities"] = [{"id": "CVE-2026-10000", "name": "test", "epss": value}]
    with pytest.raises(ValueError):
        validate_audit(audit)


def test_cli_rejects_malformed_import_without_traceback(tmp_path, audit, capsys):
    audit["findings"][0]["references"] = [17]
    source = tmp_path / "audit.json"
    source.write_text(json.dumps(audit))
    output = tmp_path / "report.html"
    assert main(["report", str(source), "--output", str(output)]) == 1
    assert not output.exists()
    error = capsys.readouterr().err
    assert "RSAT: Invalid finding references" in error and "Traceback" not in error
