import json
from unittest.mock import Mock
import pytest

from rsat.collectors import (
    Collector,
    parse_alf,
    parse_boolean_number,
    parse_enabled,
    parse_filevault,
    parse_lsof,
    parse_mac_apps,
    parse_mac_updates,
    parse_nft,
    parse_on_off,
    parse_os_release,
    parse_ss,
    parse_sshd,
    parse_uid0,
)
from rsat.runner import CommandResult


@pytest.mark.parametrize("text,enabled", [("FileVault is On.", True), ("FileVault is Off.", False)])
def test_filevault_states(text, enabled):
    assert parse_filevault(text)["enabled"] is enabled


def test_filevault_in_progress_is_not_pass():
    value = parse_filevault("Encryption in progress: Percent completed = 43.2%")
    assert value["enabled"] is None and value["progress"] == 43.2


def test_unknown_filevault_output_rejected():
    with pytest.raises(ValueError):
        parse_filevault("Something unexpected")


@pytest.mark.parametrize("state,enabled", [(0, False), (1, True), (2, True)])
def test_alf(state, enabled):
    assert parse_alf(f"Firewall state (State = {state})")["enabled"] is enabled


def test_mac_feature_parsers():
    assert parse_enabled("System Integrity Protection status: enabled.")["enabled"]
    assert not parse_enabled("assessments disabled")["enabled"]
    assert parse_on_off("Automatic check is on")["enabled"]
    assert not parse_on_off("Remote Login: Off")["enabled"]
    assert parse_boolean_number("1\n")
    with pytest.raises(ValueError):
        parse_boolean_number("yes")


def test_listener_ipv4_ipv6_processes():
    listeners = parse_lsof("p123\ncserver\nn127.0.0.1:80\nn[::]:3389\n")
    assert listeners[0]["address"] == "127.0.0.1"
    assert listeners[1]["address"] == "::" and listeners[1]["pid"] == 123
    listeners = parse_ss('LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=99,fd=3))\n')
    assert (
        listeners[0]["address"] == "::" and listeners[0]["port"] == 22 and listeners[0]["process"] == "sshd"
    )


def test_missing_utilities_do_not_abort():
    runner = Mock()
    runner.run.return_value = CommandResult(state="UNKNOWN", reason="Utility unavailable")
    observations = Collector(runner, "Darwin").collect()
    assert next(o for o in observations if o["id"] == "disk.encryption")["state"] == "UNKNOWN"
    assert len(observations) > 10


def test_permission_failures_do_not_abort():
    runner = Mock()
    runner.powershell.return_value = CommandResult(state="ERROR", reason="Access denied")
    observations = Collector(runner, "Windows").collect()
    assert next(o for o in observations if o["id"] == "disk.encryption")["state"] == "ERROR"
    assert next(o for o in observations if o["id"] == "backup.status")["state"] == "UNKNOWN"


def test_windows_queries_are_structured_and_do_not_export_keys():
    runner = Mock()
    runner.powershell.return_value = CommandResult(stdout="{}", returncode=0)
    Collector(runner, "Windows", inventory=True, update_search=True).collect()
    scripts = [call.args[0] for call in runner.powershell.call_args_list]
    assert all("ConvertTo-Json" in script for script in scripts)
    assert any("[int]$_.ProtectionStatus" in script for script in scripts)
    assert any("-PolicyStore ActiveStore" in script for script in scripts)
    assert all("RecoveryPassword" not in script and "Win32_Product" not in script for script in scripts)


def test_unrecognized_json_is_unknown():
    runner = Mock()
    runner.powershell.return_value = CommandResult(stdout="localized error", returncode=0)
    observations = Collector(runner, "Windows").collect()
    assert next(o for o in observations if o["id"] == "disk.encryption")["state"] == "UNKNOWN"


def test_platform_rejected():
    with pytest.raises(ValueError, match="Unsupported"):
        Collector(Mock(), "Other").collect()


def test_linux_configuration_parsers():
    assert parse_os_release('ID=ubuntu\nPRETTY_NAME="Ubuntu 24.04 LTS"')["id"] == "ubuntu"
    assert parse_uid0("root:x:0:0:a:/root:/bin/bash\nuser:x:1000:1000:b:/home/user:/bin/bash")[
        "accounts"
    ] == ["root"]
    assert parse_sshd("permitrootlogin no\npasswordauthentication no")["permit_root"] == "no"
    assert parse_nft(json.dumps({"nftables": [{"chain": {"hook": "input", "policy": "drop"}}]}))[
        "default_drop"
    ]
    assert not parse_nft('{"nftables":[]}')["default_drop"]


def test_mac_update_search_requires_definitive_data():
    assert parse_mac_updates("No new software available.")["count"] == 0
    assert parse_mac_updates("* Label: update1\n* Label: update2")["count"] == 2
    with pytest.raises(ValueError):
        parse_mac_updates("")


def test_mac_inventory():
    assert (
        parse_mac_apps('{"SPApplicationsDataType":[{"_name":"Example","version":"1.0"}]}')[0]["ecosystem"]
        == "macOS"
    )
