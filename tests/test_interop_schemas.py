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


def test_csaf_publisher_document_schema_and_expiry():
    from datetime import datetime, timezone, timedelta
    from jsonschema import Draft202012Validator, FormatChecker
    from rsat.interoperability import csaf

    now = datetime.now(timezone.utc).isoformat()
    document = {
        "document": {
            "category": "csaf_security_advisory",
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Synthetic vendor",
                "namespace": "https://example.org",
            },
            "title": "Synthetic advisory",
            "tracking": {
                "current_release_date": now,
                "initial_release_date": now,
                "id": "TEST-2026-1",
                "revision_history": [{"date": now, "number": "1", "summary": "Initial release"}],
                "status": "final",
                "version": "1",
            },
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2026-1234",
                "title": "Synthetic vulnerability",
                "product_status": {"known_affected": ["vendor-product-1"]},
            }
        ],
    }
    schema = json.loads((Path(__file__).parent / "schemas/csaf-2.0.json").read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
    assert csaf(document)["vulnerabilities"][0]["product_status"]["known_affected"] == ["vendor-product-1"]
    document["document"]["tracking"]["current_release_date"] = (
        datetime.now(timezone.utc) - timedelta(days=31)
    ).isoformat()
    with pytest.raises(ValueError):
        csaf(document)
