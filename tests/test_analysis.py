import copy
import pytest
from rsat.analysis import analyze, diff_audits


def test_loopback_never_claimed_exposed(audit):
    assert analyze(audit) == []


def test_sensitive_nonloopback_scenario_keeps_uncertainty(audit):
    audit["observations"][2]["value"][0]["address"] = "::"
    firewall = next(f for f in audit["findings"] if f["id"] == "RSAT-FW-001")
    firewall["status"] = "FAIL"
    risks = analyze(audit)
    assert risks[0]["severity"] == "high"
    assert risks[0]["reachability"] == "not verified"
    assert "do not prove" in risks[0]["limitations"]


def test_version_match_prioritization(audit):
    audit["vulnerabilities"] = [
        {
            "id": "CVE-2026-10000",
            "name": "Example",
            "installed_version": "1.0",
            "known_exploited": True,
            "epss": 0.85,
            "cvss": 9.1,
        }
    ]
    risk = analyze(audit)[0]
    assert risk["severity"] == "high" and any("not endpoint" in x for x in risk["factors"])


def test_diff_resolutions_and_regressions(audit):
    before = copy.deepcopy(audit)
    after = copy.deepcopy(audit)
    before["findings"][0]["status"] = "FAIL"
    after["findings"][0]["status"] = "PASS"
    before["findings"][1]["status"] = "PASS"
    after["findings"][1]["status"] = "FAIL"
    changes = diff_audits(before, after)["changes"]
    assert {x["change"] for x in changes} == {"resolved", "regression"}


def test_policy_changes_not_claimed_fixes(audit):
    before = copy.deepcopy(audit)
    audit["findings"][0].update(status="FAIL", rule_version="3.0")
    assert diff_audits(before, audit)["changes"][0]["change"] == "rule_changed"


def test_different_assets_rejected(audit):
    other = copy.deepcopy(audit)
    other["asset_id"] = "other"
    with pytest.raises(ValueError):
        diff_audits(audit, other)
