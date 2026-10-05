import json
from unittest.mock import patch

import pytest

from rsat.assistant import answer, evidence_index, validate_claims, adaptive_plan
from rsat.ai_security import collect_ai_metadata, evaluate_ai
from rsat.context import environment_context
from rsat.collectors import parse_dpkg_inventory
from rsat.graph import build_graph, simulate_change
from rsat.intelligence import query_osv, osv_identity
from rsat.recheck import recheck


def test_wsl_and_container_scope():
    wsl = environment_context("Linux", "6.1-Microsoft-WSL2", {}, False)
    assert wsl["kind"] == "wsl" and not wsl["host_controls_assessed"]
    assert "Windows host" in wsl["scope"]
    assert environment_context("Linux", "6.1", {}, True)["kind"] == "container"
    assert environment_context("Windows", "10", {}, False)["kind"] == "native"


def test_distro_identity_preserves_source_epoch_release():
    package = parse_dpkg_inventory(
        "libssl3:amd64\t1:3.0-1ubuntu2\topenssl\t1:3.0-1ubuntu2\tamd64\n",
        {"id": "ubuntu", "version_id": "22.04"},
    )[0]
    assert package["name"] == "libssl3" and package["ecosystem"] == "Ubuntu"
    assert "1%3A3.0" in package["purl"]
    assert osv_identity(package) == {
        "package": {"name": "openssl", "ecosystem": "Ubuntu:22.04"},
        "version": "1:3.0-1ubuntu2",
    }
    assert osv_identity({"name": "openssl", "version": "1", "ecosystem": "ubuntu"}) is None


def test_every_capped_package_accounted_for():
    packages = [{"name": f"p{i}", "version": "1", "ecosystem": "PyPI"} for i in range(571)]
    with patch("rsat.intelligence.request_json", return_value={}) as request:
        matched, skipped = query_osv(packages, budget=600)
    assert not matched and request.call_count == 500 and skipped == [f"p{i}" for i in range(500, 571)]
    _, skipped = query_osv(packages, budget=0)
    assert len(skipped) == 571


def test_failed_osv_query_is_recorded():
    with patch("rsat.intelligence.request_json", side_effect=OSError("offline")):
        assert query_osv([{"name": "test", "version": "1", "ecosystem": "PyPI"}])[1] == ["test"]


def test_ai_claims_reject_valid_id_false_outcome(audit):
    f = audit["findings"][0]
    proposal = {
        "audit_sha256": evidence_index(audit)["audit_sha256"],
        "claims": [
            {"finding_id": f["id"], "status": "FAIL" if f["status"] == "PASS" else "PASS", "type": "outcome"}
        ],
    }
    with pytest.raises(ValueError, match="contradicts"):
        validate_claims(audit, proposal)
    proposal["claims"][0]["status"] = f["status"]
    assert validate_claims(audit, proposal)[0]["pointer"] == "/findings/0/status"
    proposal["claims"][0]["text"] = "All controls pass"
    with pytest.raises(ValueError, match="fields"):
        validate_claims(audit, proposal)


def test_ai_binding_changes_when_evidence_changes(audit):
    proposal = {
        "audit_sha256": evidence_index(audit)["audit_sha256"],
        "claims": [
            {
                "finding_id": audit["findings"][0]["id"],
                "status": audit["findings"][0]["status"],
                "type": "outcome",
            }
        ],
    }
    audit["observations"][0]["value"] = "changed"
    with pytest.raises(ValueError, match="changed"):
        validate_claims(audit, proposal)


def test_offline_assistant_has_exact_evidence(audit):
    result = answer(audit, "Explain firewall")
    assert result["claims"] and "scope" in result and any("FW" in c["finding_id"] for c in result["claims"])
    with pytest.raises(ValueError):
        answer(audit, "test", ["MISSING"])


def test_explicit_ai_config_redacts_credentials(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "private-name": {
                        "url": "http://secret:password@example.com/?token=DO_NOT_RETAIN",
                        "env": {"API_KEY": "DO_NOT_RETAIN"},
                        "permissions": {"filesystem": ["/"], "write": True},
                    }
                }
            }
        )
    )
    observations = collect_ai_metadata([path], [{"port": 11434, "address": "0.0.0.0"}])
    assert "DO_NOT_RETAIN" not in json.dumps(observations) and "private-name" not in json.dumps(observations)
    findings = evaluate_ai(observations)
    assert {f["id"] for f in findings if f["status"] == "FAIL"} == {
        "RSAT-AI-001",
        "RSAT-AI-002",
        "RSAT-AI-003",
        "RSAT-AI-004",
    }
    assert evaluate_ai(collect_ai_metadata([], []))[0]["status"] == "UNKNOWN"


def test_graph_provenance_and_conditional_simulation(audit):
    audit["risks"] = [
        {
            "id": "TEST",
            "title": "test",
            "severity": "high",
            "evidence_ids": audit["findings"][0]["evidence_ids"],
            "factors": ["test"],
            "limitations": "not proof",
        }
    ]
    audit["findings"][0]["status"] = "FAIL"
    graph = build_graph(audit)
    assert all(e["scope"] == audit["scope"] for e in graph["edges"])
    assert simulate_change(audit, [audit["findings"][0]["id"]])["potentially_affected_paths"]
    with pytest.raises(ValueError):
        simulate_change(audit, ["missing"])


def test_recheck_registry_rejects_arbitrary_commands():
    with pytest.raises(ValueError):
        recheck("powershell -Command evil")
    with pytest.raises(ValueError):
        recheck("windows-firewall", system="Linux")


def test_adaptive_plan_only_registered_actions(audit):
    audit["findings"][0]["status"] = "UNKNOWN"
    result = adaptive_plan(audit)
    assert not result["execution_authorized"] and all(x["read_only"] for x in result["suggestions"])


def test_known_ai_failure_not_hidden_by_partial_config(tmp_path):
    good = tmp_path / "bad-settings.json"
    good.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "test": {"url": "http://example.org", "permissions": {"filesystem": ["/"], "write": True}}
                }
            }
        )
    )
    observations = collect_ai_metadata([good, tmp_path / "missing.json"], [])
    findings = {f["id"]: f for f in evaluate_ai(observations)}
    assert findings["RSAT-AI-002"]["status"] == "FAIL"
    assert findings["RSAT-AI-003"]["status"] == "FAIL"


def test_assistant_abstains_without_matching_evidence(audit):
    assert answer(audit, "quantum banana economics")["abstained"]
