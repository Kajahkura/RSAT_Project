from datetime import datetime, timezone
import pytest

from rsat.model import new_audit
from rsat.policy import coverage, evaluate, load_policy


@pytest.fixture
def audit():
    result = new_audit("test-engagement-salt")
    result.update(platform="Windows", os_release="11", architecture="AMD64")
    result["observations"] = [
        {
            "id": "disk.encryption",
            "state": "OK",
            "value": [{"mount": "C:", "protection": 1, "percentage": 100, "protector_types": ["Tpm"]}],
        },
        {
            "id": "firewall.profiles",
            "state": "OK",
            "value": [
                {"name": name, "enabled": True, "default_inbound": "Block", "log_blocked": True}
                for name in ("Domain", "Private", "Public")
            ],
        },
        {
            "id": "network.listeners",
            "state": "OK",
            "value": [{"address": "127.0.0.1", "port": 3389, "process": "test"}],
        },
    ]
    result["findings"] = evaluate(load_policy(), result["observations"], "Windows")
    result["coverage"] = coverage(result["findings"])
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    return result
