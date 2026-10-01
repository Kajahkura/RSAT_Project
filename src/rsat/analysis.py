"""Explainable relationships and audit comparison, without speculative exploit claims."""

import ipaddress


def loopback(address):
    try:
        return ipaddress.ip_address(address.split("%")[0]).is_loopback
    except ValueError:
        return address == "localhost"


def analyze(audit):
    obs = {x["id"]: x["value"] for x in audit["observations"] if x["state"] == "OK"}
    findings = {x["id"]: x for x in audit["findings"]}
    risks = []
    sensitive = {21: "FTP", 23: "Telnet", 139: "NetBIOS", 445: "SMB", 3389: "RDP", 5900: "VNC"}
    listeners = obs.get("network.listeners", [])
    if not isinstance(listeners, list):
        listeners = [listeners]
    for listener in listeners:
        port = listener.get("port")
        if loopback(listener.get("address", "")) or port not in sensitive:
            continue
        support = ["network.listeners"]
        factors = [f"{sensitive[port]} listens on a non-loopback address"]
        severity = "medium"
        for control in ("RSAT-FW-001", "RSAT-FW-004", "RSAT-FW-006"):
            if findings.get(control, {}).get("status") == "FAIL":
                support.extend(findings[control]["evidence_ids"])
                factors.append("The assessed firewall control failed")
                severity = "high"
        if port == 3389 and findings.get("RSAT-REMOTE-001", {}).get("status") == "FAIL":
            factors.append("Network Level Authentication is disabled")
            support.append("remote.rdp")
            severity = "high"
        verified = [
            x for x in obs.get("network.reachability", []) if x.get("reachable") and x.get("port") == port
        ]
        if verified:
            support.append("network.reachability")
            factors.append("A separate probe observed reachability; verify its target matches this endpoint")
        risks.append(
            {
                "id": f"RSAT-RISK-LISTENER-{listener.get('address')}-{port}",
                "title": f"Review {sensitive[port]} access",
                "severity": severity,
                "evidence_ids": sorted(set(support)),
                "factors": factors,
                "reachability": "probe evidence attached; endpoint association requires review"
                if verified
                else "not verified",
                "limitations": "A listener and failed control do not prove external exposure or exploitability.",
            }
        )
    for vulnerability in audit.get("vulnerabilities", []):
        factors = [f"Inventory version matches advisory {vulnerability['id']}"]
        severity = "medium"
        if vulnerability.get("known_exploited"):
            severity = "high"
            factors.append("CISA records exploitation of this CVE in the wild")
        if vulnerability.get("epss") is not None:
            factors.append(
                f"EPSS: {vulnerability['epss']:.3f} (CVE exploitation forecast; not endpoint compromise probability)"
            )
        if vulnerability.get("cvss", 0) >= 9:
            severity = "high"
            factors.append("Advisory technical severity is critical")
        risks.append(
            {
                "id": f"RSAT-RISK-CVE-{vulnerability['id']}-{vulnerability['name']}",
                "title": f"Review {vulnerability['name']} {vulnerability.get('installed_version', '')}",
                "severity": severity,
                "evidence_ids": ["software.inventory"],
                "factors": factors,
                "reachability": "not verified",
                "limitations": vulnerability.get("confidence", "Verify vendor applicability"),
            }
        )
    return risks


def diff_audits(before, after):
    if before["asset_id"] != after["asset_id"]:
        raise ValueError("Audits refer to different asset identifiers")
    old = {x["id"]: x for x in before["findings"]}
    new = {x["id"]: x for x in after["findings"]}
    changes = []
    for ident in sorted(old.keys() | new.keys()):
        a, b = old.get(ident), new.get(ident)
        if a is None:
            kind = "new_control"
        elif b is None:
            kind = "removed_control"
        elif a["rule_version"] != b["rule_version"]:
            kind = "rule_changed"
        elif a["status"] == b["status"] and a.get("exception") == b.get("exception"):
            continue
        elif a["status"] == "FAIL" and b["status"] == "PASS":
            kind = "resolved"
        elif a["status"] == "PASS" and b["status"] == "FAIL":
            kind = "regression"
        elif (b.get("exception") or {}).get("expired"):
            kind = "exception_expired"
        else:
            kind = "state_changed"
        changes.append(
            {
                "id": ident,
                "change": kind,
                "before": a["status"] if a else None,
                "after": b["status"] if b else None,
                "before_rule": a["rule_version"] if a else None,
                "after_rule": b["rule_version"] if b else None,
            }
        )
    return {
        "asset_id": after["asset_id"],
        "before_audit": before["audit_id"],
        "after_audit": after["audit_id"],
        "changes": changes,
    }
