import copy
import pytest

from rsat.policy import apply_exceptions, coverage, evaluate, load_policy, validate_policy


def find(findings, ident):
    return next(f for f in findings if f["id"] == ident)


def test_disabled_profiles_never_pass(audit):
    audit["observations"][1]["value"][1]["enabled"] = False
    audit["observations"][1]["value"][2]["enabled"] = False
    findings = evaluate(load_policy(), audit["observations"], "Windows")
    assert find(findings, "RSAT-FW-001")["status"] == "FAIL"


def test_suspended_fully_encrypted_drive_fails_protection(audit):
    audit["observations"][0]["value"][0]["protection"] = 0
    findings = evaluate(load_policy(), audit["observations"], "Windows")
    assert find(findings, "RSAT-ENC-001")["status"] == "FAIL"
    assert find(findings, "RSAT-ENC-002")["status"] == "PASS"


@pytest.mark.parametrize("value", [None, [], [{}], [{"enabled": None}], [{"enabled": "True"}]])
def test_absent_or_wrong_type_evidence_never_passes(value):
    observations = [{"id": "firewall.profiles", "state": "OK", "value": value}]
    assert find(evaluate(load_policy(), observations, "Windows"), "RSAT-FW-001")["status"] == "UNKNOWN"


def test_missing_macos_update_data_never_passes():
    findings = evaluate(load_policy(), [{"id": "updates.available", "state": "OK", "value": {}}], "Darwin")
    assert find(findings, "RSAT-UPDATE-002")["status"] == "UNKNOWN"


def test_no_reboot_is_not_patch_currency():
    findings = evaluate(
        load_policy(), [{"id": "updates.reboot", "state": "OK", "value": {"required": False}}], "Windows"
    )
    assert find(findings, "RSAT-UPDATE-001")["status"] == "PASS"
    assert find(findings, "RSAT-UPDATE-002")["status"] == "UNKNOWN"


def test_error_and_not_applicable_are_explicit():
    observations = [{"id": "disk.encryption", "state": "ERROR", "reason": "Access denied"}]
    findings = evaluate(load_policy(), observations, "Windows")
    assert find(findings, "RSAT-ENC-001")["status"] == "ERROR"
    assert find(findings, "RSAT-ENC-004")["status"] == "NOT_APPLICABLE"
    assert coverage(findings)["assessed"] == 0


@pytest.mark.parametrize("mutation", ["execute", "duplicate", "bad_operator", "bad_mode", "bad_reference"])
def test_untrusted_policy_is_constrained(mutation):
    policy = copy.deepcopy(load_policy())
    rule = policy["rules"][0]
    if mutation == "execute":
        rule["command"] = "rm -rf /"
    elif mutation == "duplicate":
        policy["rules"].append(copy.deepcopy(rule))
    elif mutation == "bad_operator":
        rule["operator"] = "eval"
    elif mutation == "bad_mode":
        rule["mode"] = "python"
    else:
        rule["references"] = ["javascript:alert(1)"]
    with pytest.raises(ValueError):
        validate_policy(policy)


def test_exceptions_preserve_failure(audit):
    f = audit["findings"][0]
    f["status"] = "FAIL"
    apply_exceptions(
        audit["findings"],
        [{"control_id": f["id"], "reason": "Firmware work", "expires_at": "2000-01-01T00:00:00Z"}],
    )
    assert f["status"] == "FAIL"
    assert f["exception"]["expired"] is True


def test_exceptions_require_timezone(audit):
    with pytest.raises(ValueError):
        apply_exceptions(
            audit["findings"],
            [{"control_id": audit["findings"][0]["id"], "reason": "Test", "expires_at": "2030-01-01"}],
        )
