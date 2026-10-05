import base64
import copy
import io
import json
import hashlib
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest
from rsat.bundle import crypto, generate_keys
from rsat.model import canonical
from rsat.history import (
    device_init,
    signed_snapshot,
    append_snapshot,
    history_status,
    prune_history,
    verify_snapshot,
)
from rsat.organization import issue_token, operation, enrollment_proof, database
from rsat.interfaces import mcp_stdio, read_capability
from rsat.interoperability import sbom, mlbom, trusted_vex, verify_document, external_evidence
from rsat.cli import main


def test_signed_history_rejects_replay_gap_tamper_and_wrong_key(tmp_path, audit):
    keys = tmp_path / "keys"
    identity = device_init(keys)
    public = (keys / "signing.pub.pem").read_bytes()
    store = tmp_path / "history.db"
    first = signed_snapshot(audit, keys, 1)
    accepted = append_snapshot(store, first, public)
    with pytest.raises(ValueError):
        append_snapshot(store, first, public)
    with pytest.raises(ValueError):
        append_snapshot(store, signed_snapshot(audit, keys, 3, accepted["snapshot_sha256"]), public)
    changed = copy.deepcopy(first)
    changed["payload"]["audit"]["scope"] = "forged"
    with pytest.raises(ValueError):
        verify_snapshot(changed, public)
    other = generate_keys(tmp_path / "other")
    with pytest.raises(ValueError):
        verify_snapshot(first, (other / "signing.pub.pem").read_bytes())
    second = signed_snapshot(audit, keys, 2, accepted["snapshot_sha256"])
    accepted = append_snapshot(store, second, public)
    assert len(prune_history(store, identity["device_id"], 1)["snapshots"]) == 1
    append_snapshot(store, signed_snapshot(audit, keys, 3, accepted["snapshot_sha256"]), public)
    assert history_status(store, identity["device_id"])["snapshots"][-1]["sequence"] == 3


def enroll(store, token, keys):
    challenge = operation(store, token, "challenge", {"public_key": (keys / "signing.pub.pem").read_text()})
    proof = enrollment_proof(challenge, keys / "signing.key.pem")
    result = operation(store, token, "enroll", proof)
    return result["device_id"], proof


def test_tenant_enrollment_scopes_expiry_replay_revocation(tmp_path, audit):
    store = tmp_path / "org.db"
    keys = generate_keys(tmp_path / "keys")
    a = issue_token(store, "alpha", ["enroll", "upload", "read", "revoke"])["token"]
    b = issue_token(store, "beta", ["enroll", "upload", "read", "revoke"])["token"]
    device, proof = enroll(store, a, keys)
    with pytest.raises(ValueError):
        operation(store, a, "enroll", proof)
    with pytest.raises(ValueError):
        operation(store, b, "enroll", proof)
    snapshot = signed_snapshot(audit, keys, 1)
    upload = {"device_id": device, "snapshot": snapshot}
    with pytest.raises(ValueError):
        operation(store, b, "upload", upload)
    operation(store, a, "upload", upload)
    with pytest.raises(ValueError):
        operation(store, a, "upload", upload)
    assert operation(store, a, "history", {"device_id": device})["sequence"] == 1
    read = issue_token(store, "alpha", ["read"])["token"]
    with pytest.raises(ValueError):
        operation(store, read, "revoke", {"device_id": device})
    with database(store) as db:
        db.execute("UPDATE tokens SET expires=0 WHERE digest=?", (hashlib.sha256(read.encode()).hexdigest(),))
    with pytest.raises(ValueError):
        operation(store, read, "history", {"device_id": device})
    operation(store, a, "revoke", {"device_id": device})
    with pytest.raises(ValueError):
        operation(store, a, "upload", upload)


def test_enrollment_challenge_mutation_and_expiry(tmp_path):
    store = tmp_path / "org.db"
    keys = generate_keys(tmp_path / "keys")
    token = issue_token(store, "team", ["enroll"])["token"]
    challenge = operation(store, token, "challenge", {"public_key": (keys / "signing.pub.pem").read_text()})
    altered = dict(challenge, tenant="other")
    with pytest.raises(ValueError):
        operation(store, token, "enroll", enrollment_proof(altered, keys / "signing.key.pem"))
    with database(store) as db:
        db.execute("UPDATE challenges SET expires=0")
    with pytest.raises(ValueError):
        operation(store, token, "enroll", enrollment_proof(challenge, keys / "signing.key.pem"))


def test_mcp_readonly_and_injection_boundary(audit):
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "findings"}},
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "shell", "arguments": {"command": "evil"}},
        },
    ]
    destination = io.StringIO()
    mcp_stdio(audit, io.StringIO("\n".join(json.dumps(x) for x in requests) + "\n"), destination)
    replies = [json.loads(x) for x in destination.getvalue().splitlines()]
    assert all(t["annotations"]["readOnlyHint"] for t in replies[1]["result"]["tools"])
    assert "error" in replies[3]
    with pytest.raises(ValueError):
        read_capability(audit, "graph", {"command": "evil"})


def test_interop_metadata_and_unverified_attestation(audit):
    assert sbom(audit)["specVersion"] == "1.6"
    bom = mlbom({"models": [{"name": "synthetic", "sha256": "a" * 64}], "datasets": []})
    assert bom["components"][0]["type"] == "machine-learning-model"
    with pytest.raises(ValueError):
        mlbom({"models": [{"name": "bad", "sha256": "wrong"}], "datasets": []})
    evidence = external_evidence(
        {
            "schema_version": "1.0",
            "kind": "attestation",
            "subject_id": "test",
            "source": "operator",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "claims": [],
        }
    )
    assert evidence["verification"] == "unverified import"


def test_pinned_vex_keeps_original_findings_and_rejects_staleness(tmp_path):
    keys = generate_keys(tmp_path / "keys")
    doc = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "statements": [
            {
                "vulnerability": {"name": "CVE-2026-1234"},
                "products": [{"@id": "pkg:pypi/test@1"}],
                "status": "not_affected",
                "justification": "vulnerable_code_not_present",
            }
        ],
    }
    key = crypto().load_key((keys / "signing.key.pem").read_bytes(), "Ed25519", private=True)
    envelope = {"document": doc, "signature": base64.b64encode(crypto().sign(key, canonical(doc))).decode()}
    verified = verify_document(envelope, keys / "signing.pub.pem")
    vulns = [{"id": "CVE-2026-1234", "name": "test"}]
    assert not trusted_vex(vulns, verified, ["wrong"])[0]["vex_decisions"]
    result = trusted_vex(vulns, verified, ["pkg:pypi/test@1"])
    assert result[0]["id"] == vulns[0]["id"] and result[0]["vex_decisions"]
    doc["timestamp"] = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
    with pytest.raises(ValueError):
        trusted_vex(vulns, doc, ["pkg:pypi/test@1"])
    with pytest.raises(ValueError):
        verify_document(envelope, keys / "signing.pub.pem")


@pytest.mark.parametrize("command", ["ask", "adaptive", "graph", "simulate", "sbom", "ocsf"])
def test_workspace_cli_is_accessible(tmp_path, audit, capsys, command):
    source = tmp_path / "audit.json"
    source.write_bytes(canonical(audit))
    args = [command, str(source)]
    if command == "ask":
        args.append("firewall")
    if command == "simulate":
        args.append(audit["findings"][0]["id"])
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)


def test_progress_leaves_stdout_machine_readable(audit, capsys):
    with patch("rsat.cli.Collector") as collector:
        collector.return_value.collect.return_value = audit["observations"]
        assert main(["audit", "--stdout", "--progress", "--ai-tools"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["schema_version"] == "2.0"
    assert "runtime ready" in output.err
