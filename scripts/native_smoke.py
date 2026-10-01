"""Read-only native CI smoke: compare collected evidence with independent queries."""

from pathlib import Path
import platform
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rsat.collectors import Collector, parse_alf  # noqa: E402
from rsat.policy import evaluate, load_policy  # noqa: E402
from rsat.runner import CommandRunner, parse_json  # noqa: E402


def main():
    runner = CommandRunner(timeout=30, deadline=180)
    collector = Collector(runner)
    observations = collector.collect()
    facts = {o["id"]: o for o in observations}
    findings = evaluate(load_policy(), observations, platform.system())
    assert observations and findings
    if platform.system() == "Windows":
        query = runner.powershell(
            "@(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,"
            "@{n='enabled';e={[int]$_.Enabled}}) | ConvertTo-Json -Compress"
        )
        if query.state == "OK":
            expected = {p["Name"]: p["enabled"] == 1 for p in parse_json(query)}
            if facts["firewall.profiles"]["state"] != "OK":
                collector.ps(
                    "firewall.profiles.retry",
                    "@(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {[pscustomobject]@{name=$_.Name;enabled=([int]$_.Enabled -eq 1)}}) | ConvertTo-Json -Compress",
                )
                retry = collector.observations[-1]
                assert retry["state"] == "OK", retry
                facts["firewall.profiles"] = retry
            actual = {p["name"]: p["enabled"] for p in facts["firewall.profiles"]["value"]}
            assert actual == expected

        # Parse every generated PowerShell command independently, even if a cmdlet is unavailable.
        class SyntaxRunner(CommandRunner):
            def powershell(self, script):
                import base64

                encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
                check = (
                    "$text=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + "'));"
                )
                check += "$tokens=$null;$errors=$null;[void][System.Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors);if($errors.Count){throw ($errors|Out-String)};'true'"
                result = super().powershell(check)
                assert result.state == "OK", (script, result.stderr)
                return result

        Collector(SyntaxRunner(timeout=30, deadline=300), inventory=True, update_search=True).collect()
    elif platform.system() == "Darwin":
        result = runner.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        if result.state == "OK":
            assert facts["firewall.global"]["state"] == "OK"
            assert facts["firewall.global"]["value"] == parse_alf(result.stdout)
        assert facts["os.info"]["state"] == "OK"
    else:
        assert facts["os.info"]["state"] == "OK"
        assert facts["network.listeners"]["state"] == "OK", facts["network.listeners"]
    print(
        f"Native read-only smoke passed on {platform.system()} {platform.machine()}: {len(observations)} observations"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Preserve actionable native failures as GitHub annotations, as well as log output.
        message = str(exc).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error::{type(exc).__name__}: {message}", flush=True)
        raise
