from unittest.mock import Mock, patch
import json
import pytest
from rsat.remediation import apply_action, plan, rollback
from rsat.runner import CommandResult


def planned():
    return {
        "platform": "Windows",
        "plan_id": "test",
        "items": [{"automated_action": "windows-firewall-enable"}],
    }


def test_manual_plan_tracks_findings(audit):
    result = plan(audit)
    assert result["audit_id"] == audit["audit_id"] and result["audit_sha256"]
    assert all(x["status"] != "PASS" for x in result["items"])


def test_dry_run_never_executes(tmp_path):
    with (
        patch("rsat.remediation.platform.system", return_value="Windows"),
        patch("rsat.remediation.native") as native,
    ):
        result = apply_action(planned(), "windows-firewall-enable", tmp_path / "backup", execute=False)
    native.assert_not_called()
    assert result["dry_run"] and not (tmp_path / "backup").exists()


def test_execution_needs_recovery_and_privileges(tmp_path):
    with patch("rsat.remediation.platform.system", return_value="Windows"):
        with pytest.raises(ValueError, match="recovery"):
            apply_action(planned(), "windows-firewall-enable", tmp_path / "backup", execute=True)
        with (
            patch("rsat.remediation.privileged", return_value=False),
            pytest.raises(ValueError, match="administrator"),
        ):
            apply_action(
                planned(), "windows-firewall-enable", tmp_path / "backup", execute=True, recovery_access=True
            )


def test_backup_before_execution_and_verify(tmp_path):
    before = [{"Name": n, "enabled": 0} for n in ("Domain", "Private", "Public")]
    after = [{"Name": n, "enabled": 1} for n in ("Domain", "Private", "Public")]
    backup = tmp_path / "backup.json"

    def run(runner, command):
        if "-PolicyStore PersistentStore" in command:
            return CommandResult(stdout=json.dumps(before))
        if "Set-NetFirewallProfile" in command:
            assert backup.exists()
            return CommandResult(stdout="true")
        return CommandResult(stdout=json.dumps(after))

    with (
        patch("rsat.remediation.platform.system", return_value="Windows"),
        patch("rsat.remediation.privileged", return_value=True),
        patch("rsat.remediation.native", side_effect=run),
    ):
        result = apply_action(planned(), "windows-firewall-enable", backup, True, Mock(), True)
    assert result["verified"] and json.loads(backup.read_text())["before"] == before


def test_modified_backup_cannot_inject_commands(tmp_path):
    backup = tmp_path / "backup.json"
    backup.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "platform": "Windows",
                "action": "windows-firewall-enable",
                "before": [{"Name": "Domain; malicious", "enabled": 0}] * 3,
            }
        )
    )
    with patch("rsat.remediation.platform.system", return_value="Windows"), pytest.raises(ValueError):
        rollback(backup)


def test_action_not_in_plan_rejected(tmp_path):
    with patch("rsat.remediation.platform.system", return_value="Windows"), pytest.raises(ValueError):
        apply_action({"platform": "Windows", "items": []}, "windows-firewall-enable", tmp_path / "backup")
