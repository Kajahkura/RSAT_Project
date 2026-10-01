import json
from unittest.mock import patch
import pytest
from rsat.bundle import generate_keys
from rsat.cli import main
from rsat.intelligence import enrich


def test_signed_policy_whitespace_preserved(tmp_path, audit):
    from rsat.policy import load_policy

    source = tmp_path / "policy.json"
    source.write_text(json.dumps(load_policy(), indent=2))
    keys = generate_keys(tmp_path / "keys")
    bundle = tmp_path / "policy.zip"
    assert (
        main(
            [
                "bundle",
                str(source),
                "--policy",
                "--output",
                str(bundle),
                "--signing-key",
                str(keys / "signing.key.pem"),
            ]
        )
        == 0
    )
    with patch("rsat.cli.Collector") as collector:
        collector.return_value.collect.return_value = audit["observations"]
        assert (
            main(
                [
                    "audit",
                    "--stdout",
                    "--policy",
                    str(source),
                    "--policy-bundle",
                    str(bundle),
                    "--policy-key",
                    str(keys / "signing.pub.pem"),
                ]
            )
            == 0
        )


def test_signed_intelligence_cli(tmp_path, audit):
    source = tmp_path / "pack.json"
    source.write_text(
        json.dumps({"schema_version": "1.0", "generated_at": "2026-10-01T00:00:00Z", "advisories": []})
    )
    keys = generate_keys(tmp_path / "keys")
    bundle = tmp_path / "intel.zip"
    assert (
        main(
            [
                "bundle",
                str(source),
                "--intelligence",
                "--output",
                str(bundle),
                "--signing-key",
                str(keys / "signing.key.pem"),
            ]
        )
        == 0
    )
    with patch("rsat.cli.Collector") as collector:
        collector.return_value.collect.return_value = audit["observations"]
        assert (
            main(
                [
                    "audit",
                    "--stdout",
                    "--intel-pack",
                    str(source),
                    "--intel-bundle",
                    str(bundle),
                    "--intel-key",
                    str(keys / "signing.pub.pem"),
                ]
            )
            == 0
        )
    source.write_text(source.read_text() + " ")
    assert (
        main(
            [
                "audit",
                "--stdout",
                "--intel-pack",
                str(source),
                "--intel-bundle",
                str(bundle),
                "--intel-key",
                str(keys / "signing.pub.pem"),
            ]
        )
        == 1
    )


def test_cve_alias_enrichment():
    results, meta = enrich(
        [{"id": "GHSA-example", "aliases": ["CVE-2026-10000"], "name": "Example"}],
        {
            "generated_at": "2026-10-01T00:00:00Z",
            "cves": {"CVE-2026-10000": {"known_exploited": True, "epss": 0.8}},
        },
    )
    assert results[0]["known_exploited"] and results[0]["epss"] == 0.8 and "stale" in meta
    with pytest.raises(ValueError):
        enrich([], {"generated_at": "2026-10-01", "cves": {}})
