"""Native read-only collectors; errors stay local to each observation."""

from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shlex

from .model import Observation
from .runner import CommandRunner, parse_json, rows


def privileged():
    if os.name == "nt":
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


class Collector:
    def __init__(self, runner=None, os_type=None, inventory=False, update_search=False, progress=None):
        self.runner = runner or CommandRunner()
        self.os_type = os_type or platform.system()
        self.inventory = inventory
        self.update_search = update_search
        self.observations = []
        self.progress = progress

    def add(self, ident, value=None, state="OK", source="native", reason="", duration_ms=0):
        self.observations.append(
            asdict(Observation(ident, value, state, source, reason=reason, duration_ms=duration_ms))
        )

    def query(self, ident, argv=None, script=None, parser=None):
        if self.progress:
            self.progress(ident, "starting")
        result = self.runner.powershell(script) if script else self.runner.run(argv)
        if self.progress:
            self.progress(ident, f"{result.state} ({result.duration_ms}ms)")
        source = "PowerShell/CIM" if script else argv[0]
        if result.state != "OK":
            self.add(
                ident, state=result.state, reason=result.reason, source=source, duration_ms=result.duration_ms
            )
            return None
        try:
            value = (parser or (lambda x: x))(result.stdout)
            if value is None:
                raise ValueError("No interpretable evidence")
            self.add(ident, value, source=source, duration_ms=result.duration_ms)
            return value
        except (ValueError, KeyError, TypeError, IndexError, plistlib.InvalidFileException) as exc:
            self.add(
                ident,
                state="UNKNOWN",
                source=source,
                reason=f"Unrecognized native output: {type(exc).__name__}",
                duration_ms=result.duration_ms,
            )
            return None

    def ps(self, ident, script):
        array_ids = {
            "disk.encryption",
            "firewall.profiles",
            "network.profiles",
            "network.listeners",
            "network.udp",
            "updates.installed",
            "identity.admins",
            "identity.guest",
            "software.inventory",
        }

        def decode(text):
            value = json.loads(text)
            return rows(value) if ident in array_ids else value

        return self.query(ident, script=script, parser=decode)

    def collect(self):
        self.add("runtime.privileged", privileged(), source="process token")
        from .context import environment_context

        self.add("runtime.environment", environment_context(system=self.os_type), source="runtime context")
        methods = {"Windows": self.windows, "Darwin": self.macos, "Linux": self.linux}
        if self.os_type not in methods:
            raise ValueError(f"Unsupported platform: {self.os_type}")
        methods[self.os_type]()
        if not self.update_search:
            self.add("updates.available", state="UNKNOWN", reason="Live update search not requested")
        if not self.inventory:
            self.add("software.inventory", state="UNKNOWN", reason="Software inventory not requested")
        return self.observations

    def windows(self):
        self.ps(
            "os.info",
            "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,"
            "@{n='system_drive';e={$_.SystemDrive}},@{n='product_type';e={[int]$_.ProductType}} | ConvertTo-Json -Compress",
        )
        self.ps(
            "disk.encryption",
            "$fixed=@(Get-Volume | Where-Object {$_.DriveType -eq 'Fixed' -and $_.DriveLetter} | ForEach-Object {([string]$_.DriveLetter)+':'});"
            "@(Get-BitLockerVolume | Where-Object {$_.MountPoint -in $fixed} | "
            "ForEach-Object { [pscustomobject]@{mount=$_.MountPoint;protection=[int]$_.ProtectionStatus;"
            "percentage=[int]$_.EncryptionPercentage;conversion=[int]$_.VolumeStatus;"
            "method=[string]$_.EncryptionMethod;protector_types=@($_.KeyProtector | "
            "ForEach-Object {[string]$_.KeyProtectorType})}}) | ConvertTo-Json -Depth 4 -Compress",
        )
        self.ps(
            "firewall.profiles",
            "@(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {"
            "[pscustomobject]@{name=$_.Name;enabled=([int]$_.Enabled -eq 1);"
            "default_inbound=[string]$_.DefaultInboundAction;default_outbound=[string]$_.DefaultOutboundAction;"
            "log_blocked=([int]$_.LogBlocked -eq 1)}}) | ConvertTo-Json -Compress",
        )
        self.ps(
            "network.profiles",
            "@(Get-NetConnectionProfile | Select-Object InterfaceIndex,"
            "@{n='category';e={[string]$_.NetworkCategory}}) | ConvertTo-Json -Compress",
        )
        self.ps(
            "network.listeners",
            "@(Get-NetTCPConnection -State Listen | ForEach-Object {"
            "$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;"
            "[pscustomobject]@{address=$_.LocalAddress;port=[int]$_.LocalPort;pid=[int]$_.OwningProcess;"
            "process=$p.ProcessName;protocol='tcp'}}) | ConvertTo-Json -Compress",
        )
        self.ps(
            "network.udp",
            "@(Get-NetUDPEndpoint | Select-Object @{n='address';e={$_.LocalAddress}},"
            "@{n='port';e={[int]$_.LocalPort}},@{n='pid';e={[int]$_.OwningProcess}}) | ConvertTo-Json -Compress",
        )
        self.ps(
            "updates.reboot",
            "$paths=@('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
            "Component Based Servicing\\RebootPending','HKLM:\\SOFTWARE\\Microsoft\\Windows\\"
            "CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired');"
            "$pending=@($paths | Where-Object {Test-Path $_});"
            "$rename=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' "
            "-Name PendingFileRenameOperations -ErrorAction SilentlyContinue;"
            "[pscustomobject]@{required=($pending.Count -gt 0 -or $null -ne $rename);"
            "scope='CBS, Windows Update and file rename indicators'} | ConvertTo-Json -Compress",
        )
        self.ps(
            "updates.installed",
            "@(Get-HotFix | Select-Object HotFixID,"
            "@{n='installed_at';e={if($_.InstalledOn){$_.InstalledOn.ToUniversalTime().ToString('o')}}}) | ConvertTo-Json -Compress",
        )
        self.ps(
            "defender.status",
            "Get-MpComputerStatus | Select-Object AntivirusEnabled,"
            "RealTimeProtectionEnabled,BehaviorMonitorEnabled,AntivirusSignatureAge,IsTamperProtected | ConvertTo-Json -Compress",
        )
        self.ps(
            "boot.secure",
            "[pscustomobject]@{enabled=[bool](Confirm-SecureBootUEFI)} | ConvertTo-Json -Compress",
        )
        self.ps("boot.tpm", "Get-Tpm | Select-Object TpmPresent,TpmReady | ConvertTo-Json -Compress")
        self.ps(
            "boot.vbs",
            "Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard "
            "-ClassName Win32_DeviceGuard | Select-Object VirtualizationBasedSecurityStatus | ConvertTo-Json -Compress",
        )
        self.ps(
            "remote.rdp",
            "$r=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server';"
            "$n=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp';"
            "[pscustomobject]@{enabled=($r.fDenyTSConnections -eq 0);nla=($n.UserAuthentication -eq 1)} | ConvertTo-Json -Compress",
        )
        self.ps(
            "network.smb",
            "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,"
            "RequireSecuritySignature | ConvertTo-Json -Compress",
        )
        self.ps(
            "identity.admins",
            "$g=Get-LocalGroup -SID 'S-1-5-32-544';"
            "@(Get-LocalGroupMember $g | Select-Object Name,ObjectClass,PrincipalSource) | ConvertTo-Json -Compress",
        )
        self.ps(
            "identity.guest",
            "@(Get-LocalUser | Where-Object {$_.SID.Value -match '-501$'} | "
            "Select-Object @{n='enabled';e={[bool]$_.Enabled}}) | ConvertTo-Json -Compress",
        )
        self.ps(
            "identity.uac",
            "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "| Select-Object EnableLUA,ConsentPromptBehaviorAdmin | ConvertTo-Json -Compress",
        )
        self.query(
            "logging.audit",
            ["auditpol", "/get", "/category:*", "/r"],
            parser=lambda text: {
                "csv": text.strip(),
                "scope": "native audit policy inventory; evaluate language-specific CSV separately",
            },
        )
        self.ps(
            "updates.policy",
            "$r=Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' "
            "-ErrorAction SilentlyContinue; $result=if($null -eq $r){[pscustomobject]@{configured=$false;"
            "disabled=$null}}else{[pscustomobject]@{configured=$true;disabled=($r.NoAutoUpdate -eq 1)}}; $result | ConvertTo-Json -Compress",
        )
        if self.inventory:
            # Registry inventory is read-only; Win32_Product is deliberately avoided (it can initiate MSI repairs).
            self.ps(
                "software.inventory",
                "$paths=@('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
                "@(Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | "
                "Select-Object @{n='name';e={$_.DisplayName}},@{n='version';e={$_.DisplayVersion}},"
                "@{n='vendor';e={$_.Publisher}},@{n='ecosystem';e={'Windows'}}) | ConvertTo-Json -Compress",
            )
        if self.update_search:
            self.ps(
                "updates.available",
                "$s=New-Object -ComObject Microsoft.Update.Session;"
                "$r=$s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0');"
                "[pscustomobject]@{count=$r.Updates.Count;searched_at=[DateTime]::UtcNow.ToString('o');"
                "source='Windows Update API'} | ConvertTo-Json -Compress",
            )
        self.add(
            "backup.status",
            state="UNKNOWN",
            reason="Backup availability and recovery require external evidence",
        )

    def macos(self):
        self.query("os.info", ["sw_vers", "-productVersion"], parser=lambda x: {"version": x.strip()})
        self.query("disk.encryption", ["fdesetup", "status"], parser=parse_filevault)
        self.query(
            "firewall.global",
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            parser=parse_alf,
        )
        self.query(
            "firewall.stealth",
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
            parser=parse_enabled,
        )
        self.query(
            "firewall.block_all",
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getblockall"],
            parser=parse_enabled,
        )
        self.query("network.listeners", ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"], parser=parse_lsof)
        self.query("boot.sip", ["csrutil", "status"], parser=parse_enabled)
        self.query(
            "boot.authenticated_root", ["csrutil", "authenticated-root", "status"], parser=parse_enabled
        )
        self.query("software.gatekeeper", ["spctl", "--status"], parser=parse_enabled)
        self.query("remote.ssh", ["systemsetup", "-getremotelogin"], parser=parse_on_off)
        self.query("updates.policy", ["softwareupdate", "--schedule"], parser=parse_on_off)
        self.query(
            "identity.admins",
            ["dscl", ".", "-read", "/Groups/admin", "GroupMembership"],
            parser=lambda x: {"members": x.split(":", 1)[1].strip().split()},
        )
        self.query(
            "identity.guest",
            ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"],
            parser=lambda x: {"enabled": parse_boolean_number(x)},
        )
        self.query("backup.status", ["tmutil", "latestbackup"], parser=parse_backup)
        # Missing preference keys are not proof of patch currency or endpoint protection.
        self.add(
            "updates.reboot",
            state="UNKNOWN",
            reason="No supported authoritative reboot signal collected on macOS",
        )
        self.query(
            "updates.installed", ["softwareupdate", "--history"], parser=lambda x: {"history": x.strip()}
        )
        self.query(
            "management.status", ["profiles", "status", "-type", "enrollment"], parser=parse_enrollment
        )
        if self.inventory:
            self.query(
                "software.inventory",
                ["system_profiler", "SPApplicationsDataType", "-json"],
                parser=parse_mac_apps,
            )
        if self.update_search:
            self.query("updates.available", ["softwareupdate", "--list"], parser=parse_mac_updates)

    def linux(self):
        try:
            info = parse_os_release(Path("/etc/os-release").read_text())
            self.add("os.info", info, source="/etc/os-release")
        except (OSError, ValueError):
            self.add("os.info", state="UNKNOWN", reason="OS release data unavailable")
        self.query(
            "disk.layout", ["lsblk", "--json", "--output", "NAME,TYPE,FSTYPE,MOUNTPOINTS"], parser=json.loads
        )
        self.query("network.listeners", ["ss", "-H", "-lntp"], parser=parse_ss)
        self.query("firewall.rules", ["nft", "-j", "list", "ruleset"], parser=parse_nft)
        self.query("boot.secure", ["mokutil", "--sb-state"], parser=parse_enabled)
        self.query("remote.ssh", ["sshd", "-T"], parser=parse_sshd)
        self.query("identity.uid0", ["getent", "passwd"], parser=parse_uid0)
        self.query(
            "logging.auditd",
            ["systemctl", "is-active", "auditd"],
            parser=lambda x: {"active": x.strip() == "active"},
        )
        self.query(
            "updates.timers",
            ["systemctl", "list-timers", "--all", "--no-pager"],
            parser=lambda x: {
                "automatic_update_timer": bool(re.search(r"apt-daily-upgrade|dnf-automatic", x))
            },
        )
        reboot = Path("/var/run/reboot-required")
        if self.observation_value("os.info", {}).get("id") in {"ubuntu", "debian"}:
            self.add(
                "updates.reboot",
                {"required": reboot.exists(), "scope": "Debian-family reboot indicator"},
                source=str(reboot),
            )
        else:
            self.add(
                "updates.reboot", state="UNKNOWN", reason="No distribution-specific reboot check available"
            )
        self.add(
            "backup.status",
            state="UNKNOWN",
            reason="Backup availability and recovery require external evidence",
        )
        if self.inventory:
            result = self.runner.run(
                [
                    "dpkg-query",
                    "-W",
                    "-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\n",
                ]
            )
            if result.state == "OK":
                info = self.observation_value("os.info", {})
                self.add("software.inventory", parse_dpkg_inventory(result.stdout, info), source="dpkg-query")
            else:
                self.query(
                    "software.inventory",
                    ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
                    parser=lambda x: [
                        {"name": p[0], "version": p[1], "ecosystem": "RPM"}
                        for line in x.splitlines()
                        if len(p := line.split("\t")) == 2
                    ],
                )
        if self.update_search:
            self.add(
                "updates.available",
                state="UNKNOWN",
                reason="Linux live package refresh is not run in read-only audit mode; supply vendor evidence",
            )

    def observation_value(self, ident, default=None):
        return next(
            (o["value"] for o in self.observations if o["id"] == ident and o["state"] == "OK"), default
        )


def parse_filevault(text):
    if "FileVault is On" in text:
        return {"enabled": True, "progress": None, "state": "on"}
    if "FileVault is Off" in text:
        return {"enabled": False, "progress": None, "state": "off"}
    if re.search(r"Encryption in progress", text, re.I):
        progress = re.search(r"([\d.]+)%", text)
        return {"enabled": None, "progress": float(progress[1]) if progress else None, "state": "encrypting"}
    raise ValueError("Unknown FileVault status")


def parse_alf(text):
    match = re.search(r"State\s*=\s*([012])\b", text)
    if not match:
        raise ValueError("Unknown ALF state")
    return {"enabled": int(match[1]) in (1, 2), "state": int(match[1])}


def parse_enabled(text):
    text = text.lower()
    if re.search(r"\bdisabled\b", text):
        return {"enabled": False}
    if re.search(r"\benabled\b", text):
        return {"enabled": True}
    raise ValueError("No enabled/disabled evidence")


def parse_on_off(text):
    match = re.search(r"(?:\:|\bis)\s*(on|off)\b", text, re.I)
    if not match:
        raise ValueError("Unknown on/off state")
    return {"enabled": match[1].lower() == "on"}


def parse_boolean_number(text):
    text = text.strip()
    if text not in {"0", "1"}:
        raise ValueError("Unknown boolean preference")
    return text == "1"


def split_endpoint(endpoint):
    host, port = endpoint.rsplit(":", 1)
    return host.strip("[]"), int(port)


def parse_lsof(text):
    listeners, pid, process = [], None, None
    for line in text.splitlines():
        if line.startswith("p"):
            pid = int(line[1:])
        elif line.startswith("c"):
            process = line[1:]
        elif line.startswith("n"):
            address, port = split_endpoint(line[1:].split(" ")[0])
            listeners.append(
                {"address": address, "port": port, "pid": pid, "process": process, "protocol": "tcp"}
            )
    return listeners


def parse_ss(text):
    listeners = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 5:
            raise ValueError("Malformed socket row")
        address, port = split_endpoint(cols[3])
        process = re.search(r'\("([^"\n]+)",pid=(\d+)', line)
        listeners.append(
            {
                "address": address,
                "port": port,
                "protocol": "tcp",
                "process": process[1] if process else None,
                "pid": int(process[2]) if process else None,
            }
        )
    return listeners


def parse_nft(text):
    data = json.loads(text)
    chains = [x["chain"] for x in data["nftables"] if "chain" in x and x["chain"].get("hook") == "input"]
    return {
        "input_chains": chains,
        "default_drop": bool(chains) and all(c.get("policy") == "drop" for c in chains),
        "scope": "nftables input chains only; other firewall backends not assessed",
    }


def parse_os_release(text):
    values = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            key, val = line.split("=", 1)
            parts = shlex.split(val)
            values[key.lower()] = parts[0] if parts else ""
    if "id" not in values:
        raise ValueError("Missing OS ID")
    return values


def parse_sshd(text):
    values = dict(line.split(None, 1) for line in text.splitlines() if " " in line)
    return {
        "permit_root": values.get("permitrootlogin"),
        "password_auth": values.get("passwordauthentication"),
        "scope": "effective global sshd configuration; Match blocks may differ",
    }


def parse_uid0(text):
    return {
        "accounts": [
            line.split(":", 1)[0]
            for line in text.splitlines()
            if len(line.split(":")) >= 3 and line.split(":")[2] == "0"
        ]
    }


def parse_backup(text):
    match = re.search(r"(\d{4}-\d{2}-\d{2}-\d{6})", text)
    if not match:
        raise ValueError("No dated backup evidence")
    date = datetime.strptime(match[1], "%Y-%m-%d-%H%M%S").replace(tzinfo=timezone.utc)
    return {
        "latest_backup": match[1],
        "age_days": max(0, (datetime.now(timezone.utc) - date).days),
        "restore_tested": None,
        "timestamp_assumption": "UTC; backup name has no timezone",
    }


def parse_enrollment(text):
    match = re.search(r"MDM enrollment:\s*(Yes|No)", text, re.I)
    if not match:
        raise ValueError("Unknown enrollment state")
    return {"mdm_enrolled": match[1].lower() == "yes"}


def parse_mac_apps(text):
    data = json.loads(text)
    return [
        {"name": app.get("_name"), "version": app.get("version"), "ecosystem": "macOS"}
        for app in data["SPApplicationsDataType"]
        if app.get("_name")
    ]


def parse_mac_updates(text):
    if "No new software available" in text:
        count = 0
    elif "Label:" in text:
        count = len(re.findall(r"Label:", text))
    else:
        raise ValueError("Update search did not produce a definitive result")
    return {
        "count": count,
        "searched_at": datetime.now(timezone.utc).isoformat(),
        "source": "softwareupdate --list",
    }


def osquery_observations(executable, runner):
    """Optional explicit binary adapter, with typed native data kept separate."""
    path = Path(executable).resolve(strict=True)
    observations = []
    for ident, sql in {
        "osquery.listeners": "SELECT lp.address,lp.port,lp.protocol,lp.pid,p.name AS process FROM listening_ports lp LEFT JOIN processes p USING(pid);",
        "osquery.os": "SELECT name,version,build,platform FROM os_version;",
    }.items():
        result = runner.run([str(path), "--json", sql])
        try:
            value = parse_json(result)
            observations.append(
                asdict(Observation(ident, rows(value), source="osqueryi", duration_ms=result.duration_ms))
            )
        except ValueError as exc:
            observations.append(
                asdict(Observation(ident, state="UNKNOWN", source="osqueryi", reason=str(exc)))
            )
    return observations


def parse_dpkg_inventory(text, info):
    from urllib.parse import quote

    distribution = info.get("id", "Linux")
    release = info.get("version_id", "")
    ecosystem = {"ubuntu": "Ubuntu", "debian": "Debian"}.get(distribution, distribution)
    packages = []
    for line in text.splitlines():
        columns = line.split("\t")
        if len(columns) < 2:
            continue
        binary, version = columns[:2]
        name = binary.split(":")[0]
        source = columns[2] if len(columns) > 2 and columns[2] else name
        source_version = columns[3] if len(columns) > 3 and columns[3] else version
        architecture = columns[4] if len(columns) > 4 else ""
        packages.append(
            {
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
                "distribution": distribution,
                "distribution_release": release,
                "source_name": source,
                "source_version": source_version,
                "architecture": architecture,
                "purl": f"pkg:deb/{quote(distribution, safe='')}/{quote(name, safe='')}@{quote(version, safe='')}"
                + (
                    f"?arch={quote(architecture, safe='')}&distro={quote(distribution + '-' + release, safe='')}"
                    if architecture
                    else ""
                ),
            }
        )
    return packages
