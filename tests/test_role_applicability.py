from rsat.policy import evaluate, load_policy


def test_disabled_rdp_nla_not_applicable():
    findings = evaluate(
        load_policy(),
        [{"id": "remote.rdp", "state": "OK", "value": {"enabled": False, "nla": False}}],
        "Windows",
    )
    finding = next(f for f in findings if f["id"] == "RSAT-REMOTE-001")
    assert finding["status"] == "NOT_APPLICABLE"


def test_enabled_rdp_without_nla_fails():
    findings = evaluate(
        load_policy(),
        [{"id": "remote.rdp", "state": "OK", "value": {"enabled": True, "nla": False}}],
        "Windows",
    )
    assert next(f for f in findings if f["id"] == "RSAT-REMOTE-001")["status"] == "FAIL"
