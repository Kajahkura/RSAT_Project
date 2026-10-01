import json
from unittest.mock import Mock, patch
import pytest
from rsat.exports import local_summary, oscal


def test_official_oscal_schemas(audit):
    from pathlib import Path
    import jsonschema
    import regex
    from jsonschema.validators import extend

    # NIST's schemas use Unicode categories (\p{...}); stdlib re cannot parse them.
    def unicode_pattern(validator, pattern, instance, schema):
        if isinstance(instance, str) and not regex.search(pattern, instance):
            yield jsonschema.ValidationError("OSCAL Unicode pattern mismatch")

    validator = extend(jsonschema.Draft7Validator, {"pattern": unicode_pattern})
    for name, data in zip(("assessment-plan", "assessment-results"), oscal(audit)):
        schema = json.loads((Path(__file__).parent / "schemas" / (name + ".json")).read_text())
        validator(schema).validate(data)


def test_oscal_pair_associated(audit):
    plan, results = oscal(audit)
    assert results["assessment-results"]["import-ap"]["href"] == "assessment-plan.json"
    assert plan["assessment-plan"]["import-ssp"]["href"] == "system-security-plan.json"
    observations = results["assessment-results"]["results"][0]["observations"]
    assert all(o["collected"] == audit["started_at"] for o in observations)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://example.com/",
        "http://example.com/",
        "http://localhost/",
        "file:///etc/passwd",
        "http://127.0.0.1@evil/",
    ],
)
def test_ai_external_endpoints_rejected(audit, endpoint):
    with pytest.raises(ValueError):
        local_summary(audit, endpoint, "test-model")


def test_ai_citations_required(audit):
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = json.dumps({"response": "Everything is fine without evidence."}).encode()
    opener = Mock()
    opener.open.return_value = response
    with (
        patch("rsat.exports.urllib.request.build_opener", return_value=opener),
        pytest.raises(ValueError, match="citations"),
    ):
        local_summary(audit, model="test")
