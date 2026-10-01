import json
from unittest.mock import patch
import pytest

from rsat.cli import main
from rsat.model import canonical


def save(tmp_path, audit):
    path = tmp_path / "audit.json"
    path.write_bytes(canonical(audit))
    return path


def test_cli_report_plan_bundle_verify_workspace(tmp_path, audit):
    source = save(tmp_path, audit)
    for args in (
        ["report", str(source), "--output", str(tmp_path / "report.html")],
        ["plan", str(source), "--output", str(tmp_path / "plan.json")],
        ["bundle", str(source), "--output", str(tmp_path / "audit.zip")],
        ["workspace", str(source), "--output", str(tmp_path / "workspace.html")],
    ):
        assert main(args) == 0
    assert main(["verify", str(tmp_path / "audit.zip")]) == 0
    assert main(["report", str(source), "--output", str(tmp_path / "report.html")]) == 1


def test_cli_diff(tmp_path, audit, capsys):
    source = save(tmp_path, audit)
    assert main(["diff", str(source), str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["changes"] == []


def test_audit_stdout_valid_json(audit, capsys):
    with patch("rsat.cli.Collector") as collector:
        collector.return_value.collect.return_value = audit["observations"]
        assert main(["audit", "--stdout"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["schema_version"] == "2.0" and data["findings"]


@pytest.mark.parametrize(
    "args",
    [
        ["audit", "--deadline", "0"],
        ["audit", "--deadline", "1", "--command-timeout", "2"],
        ["audit", "--stdout", "--bundle"],
        ["audit", "--recipient-key", "key.pem"],
        ["audit", "--policy-key", "key.pem"],
    ],
)
def test_cli_invalid_audit_options(args):
    assert main(args) == 1


def test_missing_input_is_clean_error(tmp_path, capsys):
    assert main(["report", str(tmp_path / "absent"), "--output", str(tmp_path / "out")]) == 1
    assert "RSAT:" in capsys.readouterr().err


def test_complete_output_bundle_roundtrip(tmp_path, audit):
    with patch("rsat.cli.Collector") as collector:
        collector.return_value.collect.return_value = audit["observations"]
        assert main(["audit", "--output", str(tmp_path / "out"), "--bundle", "--oscal"]) == 0
    outputs = list((tmp_path / "out").iterdir())
    assert len(outputs) == 1
    assert {p.name for p in outputs[0].iterdir()} == {
        "audit.json",
        "report.html",
        "remediation-plan.json",
        "evidence.rsat.zip",
        "assessment-plan.json",
        "assessment-results.json",
    }


def test_cli_exit_on_failures(audit):
    audit["observations"][1]["value"][0]["enabled"] = False
    with patch("rsat.cli.Collector") as collector, patch("rsat.cli.platform", create=True):
        collector.return_value.collect.return_value = audit["observations"]
        with patch("rsat.cli.new_audit", return_value=audit):
            assert main(["audit", "--stdout", "--fail-on-findings"]) == 2
