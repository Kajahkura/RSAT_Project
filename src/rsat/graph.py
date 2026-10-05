"""Provenance-linked evidence relationships and explicitly conditional change simulation."""

import hashlib
from .model import canonical, validate_audit


def build_graph(audit):
    validate_audit(audit)
    nodes, edges, paths = [], [], []

    def node(ident, kind, label, **properties):
        nodes.append({"id": ident, "kind": kind, "label": label, **properties})

    def edge(source, target, relation, evidence_ids, confidence="observed"):
        edges.append(
            {
                "source": source,
                "target": target,
                "relation": relation,
                "evidence_ids": evidence_ids,
                "confidence": confidence,
                "collected_at": audit["finished_at"] or audit["started_at"],
                "scope": audit["scope"],
            }
        )

    asset = "asset:" + audit["asset_id"]
    node(asset, "asset", audit["asset_id"], scope=audit["scope"])
    obs = {o["id"]: o for o in audit["observations"]}
    for finding in audit["findings"]:
        ident = "control:" + finding["id"]
        node(
            ident,
            "control",
            finding["title"],
            status=finding["status"],
            rule_version=finding["rule_version"],
            severity=finding["severity"],
        )
        edge(asset, ident, "assessed_by", finding["evidence_ids"])
    listeners = obs.get("network.listeners", {})
    if listeners.get("state") == "OK" and isinstance(listeners.get("value"), list):
        for index, listener in enumerate(listeners["value"]):
            if not isinstance(listener, dict):
                continue
            ident = "listener:" + str(index)
            node(
                ident,
                "listener",
                f"{listener.get('address')}:{listener.get('port')}",
                port=listener.get("port"),
            )
            edge(asset, ident, "listens_on", ["network.listeners"])
    for risk in audit["risks"]:
        ident = "risk:" + risk["id"]
        node(ident, "risk", risk["title"], severity=risk["severity"])
        edge(asset, ident, "supported_risk_scenario", risk["evidence_ids"], "rule-derived")
        paths.append(
            {
                "id": risk["id"],
                "title": risk["title"],
                "evidence_ids": risk["evidence_ids"],
                "factors": risk["factors"],
                "limitations": risk["limitations"],
                "reachability": risk.get("reachability", "not verified"),
                "supporting_controls": [
                    f["id"]
                    for f in audit["findings"]
                    if f["status"] == "FAIL" and set(f["evidence_ids"]) & set(risk["evidence_ids"])
                ],
            }
        )
    # Configuration relationships do not prove operational exploitability.
    ai_failures = [f for f in audit["findings"] if f["id"].startswith("RSAT-AI-") and f["status"] == "FAIL"]
    if any(f["id"] == "RSAT-AI-001" for f in ai_failures) and any(
        f["id"] == "RSAT-AI-003" for f in ai_failures
    ):
        paths.append(
            {
                "id": "RSAT-PATH-AI-BOUNDARY",
                "title": "Review combined model network and MCP write boundaries",
                "evidence_ids": sorted({i for f in ai_failures for i in f["evidence_ids"]}),
                "supporting_controls": [f["id"] for f in ai_failures],
                "factors": ["Non-loopback model listener observed", "Broad MCP write scope declared"],
                "reachability": "not verified",
                "limitations": "Configuration co-occurrence does not prove the MCP server is connected to this model or an exploitable path.",
            }
        )
    return {
        "schema_version": "1.0",
        "audit_sha256": hashlib.sha256(canonical(audit)).hexdigest(),
        "nodes": nodes,
        "edges": edges,
        "paths": paths,
        "limitations": "A supported relationship graph, not a proof of exploitability or a complete attack graph.",
    }


def simulate_change(audit, control_ids):
    graph = build_graph(audit)
    findings = {f["id"]: f for f in audit["findings"]}
    if not isinstance(control_ids, list) or not control_ids or any(x not in findings for x in control_ids):
        raise ValueError("Select existing control IDs for simulation")
    affected = [p for p in graph["paths"] if set(p.get("supporting_controls", [])) & set(control_ids)]
    return {
        "audit_sha256": graph["audit_sha256"],
        "assumed_corrected_controls": control_ids,
        "potentially_affected_paths": affected,
        "changes_applied": False,
        "limitations": "Assumes selected controls are corrected. Other path conditions and operational dependencies may remain; re-audit and independent verification are required.",
    }
