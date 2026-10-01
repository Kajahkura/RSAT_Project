"""Publish file hashes and the actual installed build dependency inventory."""

import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import uuid

from datetime import datetime, timezone

dist = Path("dist")
files = sorted(
    p
    for p in dist.iterdir()
    if p.is_file() and p.name not in {"SHA256SUMS.txt", "build-environment.cdx.json"}
)
checksums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files)
(dist / "SHA256SUMS.txt").write_text(checksums, encoding="utf-8")
components = [
    {
        "type": "library",
        "name": d.metadata["Name"],
        "version": d.version,
        "purl": f"pkg:pypi/{d.metadata['Name'].lower()}@{d.version}",
    }
    for d in importlib.metadata.distributions()
]
sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
    "version": 1,
    "metadata": {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "component": {"type": "application", "name": "RSAT", "version": "2.0.0"},
        "properties": [
            {"name": "rsat:scope", "value": "build-environment inventory; not a binary composition claim"},
            {"name": "rsat:platform", "value": platform.platform()},
        ],
    },
    "components": components,
}
(dist / "build-environment.cdx.json").write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
