import socket
from unittest.mock import Mock
import pytest
from rsat.model import canonical
from rsat.runner import CommandResult
from rsat.transport import probe, remote_audit


def test_explicit_probe_loopback():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        results = probe("127.0.0.1", [server.getsockname()[1]], 0.2)
    assert results[0]["reachable"] and "from this probe host only" in results[0]["scope"]


@pytest.mark.parametrize("target", ["--option", "user@host;touch /tmp/x", "user@host$(cmd)", "host"])
def test_ssh_target_injection_rejected(target):
    with pytest.raises(ValueError):
        remote_audit(target)


def test_ssh_preserves_host_key_checks(audit):
    runner = Mock()
    runner.run.return_value = CommandResult(stdout=canonical(audit).decode())
    assert remote_audit("user@host", runner=runner)["audit_id"] == audit["audit_id"]
    argv = runner.run.call_args.args[0]
    assert "StrictHostKeyChecking=yes" in argv and "BatchMode=yes" in argv
    assert "--stdout" in argv[-1]
