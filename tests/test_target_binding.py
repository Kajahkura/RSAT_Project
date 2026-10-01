from unittest.mock import patch
import pytest
from rsat.remediation import apply_action


def test_plan_from_other_endpoint_cannot_execute(tmp_path):
    data = {
        "platform": "Windows",
        "target_fingerprint": "other-endpoint",
        "items": [{"automated_action": "windows-firewall-enable"}],
    }
    with (
        patch("rsat.remediation.platform.system", return_value="Windows"),
        patch("rsat.remediation.native") as run,
    ):
        with pytest.raises(ValueError, match="not bound"):
            apply_action(
                data, "windows-firewall-enable", tmp_path / "backup", execute=True, recovery_access=True
            )
    run.assert_not_called()
