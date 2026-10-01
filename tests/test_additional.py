import copy
from datetime import datetime, timezone
import json
from unittest.mock import Mock, patch
import pytest

from rsat.analysis import diff_audits, loopback
from rsat.collectors import Collector, parse_backup, parse_enrollment, osquery_observations
from rsat.exports import local_summary
from rsat.intelligence import request_json
from rsat.model import validate_audit
from rsat.policy import compare, validate_policy, load_policy
from rsat.remediation import action_value, rollback, target_fingerprint
from rsat.runner import CommandResult
from rsat.storage import read_json


def test_single_powershell_volume_normalized():
    runner = Mock()
    runner.powershell.return_value = CommandResult(stdout='{"protection":1,"percentage":100}')
    collector = Collector(runner, "Windows")
    assert collector.ps("disk.encryption", "test") == [{"protection": 1, "percentage": 100}]


def test_linux_full_collection_with_mocked_queries():
    runner = Mock()

    def query(argv):
        data = {
            "lsblk": '{"blockdevices":[]}',
            "ss": "",
            "nft": '{"nftables":[]}',
            "mokutil": "SecureBoot enabled",
            "sshd": "permitrootlogin no\npasswordauthentication no",
            "getent": "root:x:0:0:root:/root:/bin/bash",
            "systemctl": "active",
            "dpkg-query": "example\t1.0\n",
        }
        return CommandResult(stdout=data.get(argv[0], "{}"))

    runner.run.side_effect = query
    obs = Collector(runner, "Linux", inventory=True, update_search=True).collect()
    assert any(o["id"] == "software.inventory" and o["state"] == "OK" for o in obs)
    assert next(o for o in obs if o["id"] == "updates.available")["state"] == "UNKNOWN"


def test_mac_backup_enrollment():
    name = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")
    assert parse_backup("/Backups/" + name)["age_days"] == 0
    assert parse_enrollment("MDM enrollment: Yes (User Approved)")["mdm_enrolled"]
    with pytest.raises(ValueError):
        parse_backup("No backups")
    with pytest.raises(ValueError):
        parse_enrollment("no data")


def test_osquery_adapter_requires_explicit_binary(tmp_path):
    path = tmp_path / "osqueryi"
    path.write_text("test")
    runner = Mock()
    runner.run.side_effect = [
        CommandResult(stdout='[{"port":80}]'),
        CommandResult(state="ERROR", reason="failed"),
    ]
    observations = osquery_observations(path, runner)
    assert observations[0]["state"] == "OK" and observations[1]["state"] == "UNKNOWN"
    assert runner.run.call_args.args[0][0] == str(path.resolve())


def test_policy_comparisons():
    assert compare(2, "ge", 1) and compare(2, "le", 3)
    assert compare("x", "in", ["x"]) and compare("x", "not_in", ["y"])
    assert compare([], "empty", None) and compare(["x"], "nonempty", None)
    for actual, op, expected in [(None, "eq", 1), (True, "eq", 1), ("1", "ge", 1), (3, "empty", None)]:
        with pytest.raises(ValueError):
            compare(actual, op, expected)


def test_schema_invalid_metadata(audit):
    for key, value in [("schema_version", "wrong"), ("asset_id", ""), ("observations", {})]:
        bad = copy.deepcopy(audit)
        bad[key] = value
        with pytest.raises(ValueError):
            validate_audit(bad)


def test_expired_exception_diff(audit):
    before = copy.deepcopy(audit)
    audit["findings"][0]["exception"] = {
        "expired": True,
        "reason": "test",
        "expires_at": "2000-01-01T00:00:00Z",
    }
    assert diff_audits(before, audit)["changes"][0]["change"] == "exception_expired"
    assert not loopback("unrecognized") and loopback("::1")


def test_rollback_execution_verifies_saved_profiles(tmp_path):
    profiles = [{"Name": name, "enabled": 0} for name in ("Domain", "Private", "Public")]
    backup = tmp_path / "backup.json"
    backup.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "platform": "Windows",
                "action": "windows-firewall-enable",
                "before": profiles,
                "target_fingerprint": target_fingerprint(),
            }
        )
    )
    runner = Mock()
    runner.powershell.return_value = CommandResult(stdout=json.dumps(profiles))
    with (
        patch("rsat.remediation.platform.system", return_value="Windows"),
        patch("rsat.remediation.privileged", return_value=True),
    ):
        assert rollback(backup)["dry_run"]
        assert rollback(backup, True, runner, True)["verified"]
    assert runner.powershell.call_count == 4


def test_mac_action_values():
    assert action_value("macos-firewall-enable", CommandResult(stdout="State = 1"))["enabled"]
    assert action_value("macos-stealth-enable", CommandResult(stdout="Stealth mode enabled"))["enabled"]
    with pytest.raises(ValueError):
        action_value("macos-stealth-enable", CommandResult(state="ERROR", reason="denied"))


def test_successful_local_ai_cited_output(audit):
    ident = next(f["id"] for f in audit["findings"] if f["status"] == "UNKNOWN")
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = json.dumps({"response": f"Collect evidence for [{ident}]."}).encode()
    opener = Mock()
    opener.open.return_value = response
    with patch("rsat.exports.urllib.request.build_opener", return_value=opener):
        result = local_summary(audit, model="test")
    assert result["review_required"] and result["cited_findings"] == [ident]


def test_bounded_json_read(tmp_path):
    path = tmp_path / "test.json"
    path.write_text('{"test":true}')
    with pytest.raises(ValueError):
        read_json(path, limit=2)


def test_request_json_https_response():
    response = Mock()
    response.url = "https://example.com/"
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = b'{"value":1}'
    with patch("rsat.intelligence.urllib.request.urlopen", return_value=response):
        assert request_json("https://example.com/", {"test": True}) == {"value": 1}


def test_policy_metadata_validation():
    with pytest.raises(ValueError):
        validate_policy({"schema_version": "other"})
    policy = copy.deepcopy(load_policy())
    policy["rules"][0]["platforms"] = ["Other"]
    with pytest.raises(ValueError):
        validate_policy(policy)
