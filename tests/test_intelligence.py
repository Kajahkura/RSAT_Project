import json
from unittest.mock import patch
import pytest
from rsat.intelligence import load_pack, match_inventory, query_osv, refresh_enrichment, request_json


def pack():
    return {
        "schema_version": "1.0",
        "generated_at": "2026-01-01T00:00:00Z",
        "advisories": [
            {
                "id": "CVE-2026-10000",
                "name": "Example",
                "ecosystem": "Windows",
                "affected_versions": ["1.0"],
                "cvss": 9,
                "epss": 0.5,
                "known_exploited": True,
            }
        ],
    }


def test_exact_match_and_no_fuzzy_claims():
    packages = [
        {"name": "Example", "version": "1.0", "ecosystem": "Windows"},
        {"name": "Example", "version": "1.0.1", "ecosystem": "Windows"},
        {"name": "Example", "version": "1.0", "ecosystem": "macOS"},
    ]
    results = match_inventory(packages, pack())
    assert len(results) == 1 and results[0]["match"] == "exact-version"


def test_pack_freshness_and_validation(tmp_path):
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(pack()))
    _, metadata = load_pack(path)
    assert metadata["stale"] and metadata["sha256"]
    value = pack()
    value["advisories"][0]["affected_versions"] = []
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        load_pack(path)


def test_https_required():
    with pytest.raises(ValueError):
        request_json("file:///etc/passwd")


def test_osv_supported_ecosystems_only():
    packages = [
        {"name": "Example", "version": "1.0", "ecosystem": "Windows"},
        {"name": "example", "version": "1.0", "ecosystem": "PyPI"},
    ]
    with patch("rsat.intelligence.request_json", return_value={"vulns": [{"id": "GHSA-example"}]}) as fetch:
        results, skipped = query_osv(packages)
    assert len(results) == 1 and skipped == ["Example"] and fetch.call_count == 1


def test_refresh_matches_cve_identifiers():
    with patch(
        "rsat.intelligence.request_json",
        side_effect=[
            {"vulnerabilities": [{"cveID": "CVE-2026-10000"}], "catalogVersion": "test"},
            {"data": [{"cve": "CVE-2026-10000", "epss": ".8", "date": "2026-01-01"}]},
        ],
    ):
        result = refresh_enrichment(["CVE-2026-10000"])
    assert result["cves"]["CVE-2026-10000"]["known_exploited"]
    assert result["cves"]["CVE-2026-10000"]["epss"] == 0.8


def test_refresh_rejects_malformed_ids():
    with pytest.raises(ValueError):
        refresh_enrichment(["CVE-test&url=evil"])
