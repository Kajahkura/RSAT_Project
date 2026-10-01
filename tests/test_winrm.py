from unittest.mock import Mock
import pytest
from rsat.model import canonical
from rsat.runner import CommandResult
from rsat.transport import winrm_audit


def test_winrm_authenticated_https_and_encoded_path(audit):
    runner = Mock()
    runner.powershell.return_value = CommandResult(stdout=canonical(audit).decode())
    assert (
        winrm_audit("host.example", r"C:\Program Files\RSAT\rsat.exe", runner)["audit_id"]
        == audit["audit_id"]
    )
    script = runner.powershell.call_args.args[0]
    assert "-UseSSL" in script and "FromBase64String" in script
    assert "SkipCACheck" not in script and "Credential" not in script


@pytest.mark.parametrize("host", ["host';run-command", "-option", "host@user", "host$(cmd)"])
def test_winrm_rejects_injection(host):
    with pytest.raises(ValueError):
        winrm_audit(host, "rsat.exe")
