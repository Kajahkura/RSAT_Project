"""Explicit read-only capability registry independent of model instructions."""

from .runner import CommandRunner
from .collectors import Collector, parse_ss, parse_nft, parse_alf, parse_filevault

CAPABILITIES = {
    "linux-listeners": {
        "platform": "Linux",
        "observation_id": "network.listeners",
        "argv": ["ss", "-H", "-lntp"],
        "parser": parse_ss,
    },
    "linux-firewall": {
        "platform": "Linux",
        "observation_id": "firewall.rules",
        "argv": ["nft", "-j", "list", "ruleset"],
        "parser": parse_nft,
    },
    "macos-firewall": {
        "platform": "Darwin",
        "observation_id": "firewall.global",
        "argv": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
        "parser": parse_alf,
    },
    "macos-filevault": {
        "platform": "Darwin",
        "observation_id": "disk.encryption",
        "argv": ["fdesetup", "status"],
        "parser": parse_filevault,
    },
    "windows-firewall": {
        "platform": "Windows",
        "observation_id": "firewall.profiles",
        "script": "@(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {[pscustomobject]@{name=$_.Name;enabled=([int]$_.Enabled -eq 1);default_inbound=[string]$_.DefaultInboundAction;log_blocked=([int]$_.LogBlocked -eq 1)}}) | ConvertTo-Json -Compress",
    },
}


def recheck(capability, runner=None, system=None):
    import platform

    definition = CAPABILITIES.get(capability)
    if definition is None or definition["platform"] != (system or platform.system()):
        raise ValueError("Unsupported read-only capability for this platform")
    collector = Collector(runner or CommandRunner(timeout=15, deadline=20))
    if "script" in definition:
        collector.ps(definition["observation_id"], definition["script"])
    else:
        collector.query(definition["observation_id"], definition["argv"], parser=definition["parser"])
    return collector.observations[0]
