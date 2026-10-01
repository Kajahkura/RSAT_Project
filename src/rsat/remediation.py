"""Auditable manual plans and a small allowlist of reversible native actions."""

import hashlib
import platform
import uuid

from .collectors import privileged
from .model import canonical, utcnow
from .runner import CommandRunner, parse_json
from .storage import read_json, write_new

ACTIONS = {
    "windows-firewall-enable": {
        "platform": "Windows",
        "control_id": "RSAT-FW-001",
        "description": "Enable all Windows firewall profiles. May interrupt inbound remote access.",
        "capture": "@(Get-NetFirewallProfile -PolicyStore PersistentStore | Select-Object Name,"
        "@{n='enabled';e={[int]$_.Enabled}}) | ConvertTo-Json -Compress",
        "apply": "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True; 'true'",
        "verify": "@(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,"
        "@{n='enabled';e={[int]$_.Enabled}}) | ConvertTo-Json -Compress",
    },
    "macos-firewall-enable": {
        "platform": "Darwin",
        "control_id": "RSAT-FW-004",
        "description": "Enable the macOS application firewall. May interrupt inbound services.",
        "capture": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
        "apply": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"],
        "verify": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
    },
    "macos-stealth-enable": {
        "platform": "Darwin",
        "control_id": "RSAT-FW-005",
        "description": "Enable macOS firewall stealth mode.",
        "capture": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
        "apply": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setstealthmode", "on"],
        "verify": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
    },
}


def target_fingerprint():
    return hashlib.sha256(platform.node().encode("utf-8")).hexdigest()


def plan(audit):
    return {
        "schema_version": "1.0",
        "plan_id": str(uuid.uuid4()),
        "created_at": utcnow(),
        "audit_id": audit["audit_id"],
        "asset_id": audit["asset_id"],
        "platform": audit["platform"],
        "audit_sha256": hashlib.sha256(canonical(audit)).hexdigest(),
        "target_fingerprint": audit.get("target_fingerprint"),
        "items": [
            {
                "control_id": f["id"],
                "status": f["status"],
                "severity": f["severity"],
                "instruction": f["remediation"],
                "automated_action": next(
                    (
                        name
                        for name, a in ACTIONS.items()
                        if a["control_id"] == f["id"] and a["platform"] == audit["platform"]
                    ),
                    None,
                ),
                "verification": "Re-audit and compare the same control with the same rule version",
            }
            for f in audit["findings"]
            if f["status"] in {"FAIL", "UNKNOWN", "ERROR"}
        ],
        "limitations": "Manual instructions require role-specific review. Only allowlisted actions are executable. "
        "Central policies may override local changes. Keep console/recovery access for firewall changes.",
    }


def native(runner, command):
    return runner.powershell(command) if isinstance(command, str) else runner.run(command)


def action_value(action, result):
    if result.state != "OK":
        raise ValueError(result.reason)
    if action == "windows-firewall-enable":
        value = parse_json(result)
        if (
            not isinstance(value, list)
            or len(value) != 3
            or {v.get("Name") for v in value} != {"Domain", "Private", "Public"}
        ):
            raise ValueError("Expected three firewall profiles")
        if any(v.get("enabled") not in {0, 1, 2} for v in value):
            raise ValueError("Unknown firewall profile state")
        return value
    from .collectors import parse_alf, parse_enabled

    return (parse_alf if action == "macos-firewall-enable" else parse_enabled)(result.stdout)


def apply_action(plan_data, action, backup_path, execute=False, runner=None, recovery_access=False):
    if action not in ACTIONS:
        raise ValueError("Unsupported automated action")
    definition = ACTIONS[action]
    if definition["platform"] != platform.system() or plan_data.get("platform") != platform.system():
        raise ValueError("Action does not apply to this platform")
    if not any(i.get("automated_action") == action for i in plan_data.get("items", [])):
        raise ValueError("Action is absent from this remediation plan")
    if not execute:
        return {
            "dry_run": True,
            "action": action,
            "description": definition["description"],
            "backup_path": str(backup_path),
            "requires_privilege": True,
            "requires_recovery_access": True,
            "changes_applied": False,
        }
    if not recovery_access:
        raise ValueError("Execution requires --recovery-access to acknowledge console/recovery access")
    if plan_data.get("target_fingerprint") != target_fingerprint():
        raise ValueError("Remediation plan is not bound to this endpoint; generate the plan on the target")
    if not privileged():
        raise ValueError("This explicit remediation command requires administrator privileges")
    runner = runner or CommandRunner(deadline=45)
    before = action_value(action, native(runner, definition["capture"]))
    backup = {
        "schema_version": "1.0",
        "action": action,
        "platform": platform.system(),
        "created_at": utcnow(),
        "plan_id": plan_data.get("plan_id"),
        "before": before,
        "target_fingerprint": target_fingerprint(),
    }
    write_new(backup_path, canonical(backup))
    result = native(runner, definition["apply"])
    if result.state != "OK":
        raise ValueError(f"Action failed; backup preserved at {backup_path}: {result.reason}")
    after = action_value(action, native(runner, definition["verify"]))
    verified = all(v["enabled"] == 1 for v in after) if isinstance(after, list) else after["enabled"] is True
    return {
        "action": action,
        "changes_applied": True,
        "verified": verified,
        "after": after,
        "backup_path": str(backup_path),
        "follow_up": "Run a full audit and compare results",
    }


def rollback(backup_path, execute=False, runner=None, recovery_access=False):
    backup = read_json(backup_path)
    action = backup.get("action")
    if (
        backup.get("schema_version") != "1.0"
        or action not in ACTIONS
        or backup.get("platform") != platform.system()
    ):
        raise ValueError("Invalid rollback backup")
    before = backup.get("before")
    if action == "windows-firewall-enable":
        if not isinstance(before, list) or len(before) != 3:
            raise ValueError("Invalid saved firewall profiles")
        for profile in before:
            if profile.get("Name") not in {"Domain", "Private", "Public"} or profile.get("enabled") not in {
                0,
                1,
                2,
            }:
                raise ValueError("Invalid saved profile")
        commands = [
            f"Set-NetFirewallProfile -Profile {p['Name']} -Enabled {['False', 'True', 'NotConfigured'][p['enabled']]}; 'true'"
            for p in before
        ]
    else:
        if not isinstance(before, dict) or not isinstance(before.get("enabled"), bool):
            raise ValueError("Invalid saved firewall state")
        args = list(ACTIONS[action]["apply"])
        if action == "macos-firewall-enable" and before.get("state") == 2:
            raise ValueError(
                "Block-all mode requires manual restoration; rollback cannot reproduce it safely"
            )
        args[-1] = "on" if before["enabled"] else "off"
        commands = [args]
    if not execute:
        return {"dry_run": True, "action": action, "commands": commands}
    if not recovery_access or not privileged():
        raise ValueError("Rollback execution requires administrator privileges and --recovery-access")
    if backup.get("target_fingerprint") != target_fingerprint():
        raise ValueError("Rollback backup is not bound to this endpoint")
    runner = runner or CommandRunner(deadline=45)
    for command in commands:
        result = native(runner, command)
        if result.state != "OK":
            raise ValueError(f"Rollback failed: {result.reason}")
    restored = action_value(action, native(runner, ACTIONS[action]["capture"]))
    return {"action": action, "rollback_applied": True, "verified": restored == before, "restored": restored}
