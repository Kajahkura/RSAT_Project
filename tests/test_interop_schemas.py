import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from rsat.interoperability import sbom, mlbom


def test_cyclonedx_exports_against_official_schema(audit):
    folder = Path(__file__).parent / "schemas"
    schemas = {
        name: json.loads((folder / name).read_text())
        for name in ("cyclonedx-1.6.json", "jsf-0.82.schema.json", "spdx.schema.json")
    }
    registry = Registry()
    for name, schema in schemas.items():
        registry = registry.with_resource(
            "http://cyclonedx.org/schema/"
            + ("bom-1.6.schema.json" if name == "cyclonedx-1.6.json" else name),
            Resource.from_contents(schema),
        )
    validator = Draft7Validator(schemas["cyclonedx-1.6.json"], registry=registry)
    documents = [
        sbom(audit),
        mlbom(
            {
                "models": [
                    {
                        "name": "synthetic-model",
                        "sha256": "a" * 64,
                        "source": "https://example.org/model",
                        "license": "MIT",
                    }
                ],
                "datasets": [{"name": "synthetic-dataset", "sha256": "b" * 64}],
            }
        ),
    ]
    for document in documents:
        validator.validate(document)
    with pytest.raises(Exception):
        validator.validate({**documents[0], "bomFormat": "invalid"})
