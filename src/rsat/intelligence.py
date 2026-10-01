"""Offline exact-version advisories plus explicit online OSV/KEV/EPSS enrichment."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request

from .model import canonical, utcnow

MAX_DOWNLOAD = 20_000_000


def request_json(url, payload=None, timeout=10):
    if not url.startswith("https://"):
        raise ValueError("Intelligence sources must use HTTPS")
    headers = {"User-Agent": "RSAT/2.0", "Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(  # noqa: S310 -- HTTPS URL validated above
        url,
        data=canonical(payload) if payload is not None else None,  # noqa: S310
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 -- HTTPS validated above
        if not response.url.startswith("https://"):
            raise ValueError("Source redirected outside HTTPS")
        raw = response.read(MAX_DOWNLOAD + 1)
    if len(raw) > MAX_DOWNLOAD:
        raise ValueError("Intelligence response exceeds limit")
    return json.loads(raw)


def load_pack(path):
    raw = Path(path).read_bytes()
    if len(raw) > MAX_DOWNLOAD:
        raise ValueError("Intelligence pack exceeds limit")
    data = json.loads(raw)
    if data.get("schema_version") != "1.0" or not isinstance(data.get("advisories"), list):
        raise ValueError("Unsupported intelligence pack")
    generated = datetime.fromisoformat(data["generated_at"].replace("Z", "+00:00"))
    if generated.tzinfo is None:
        raise ValueError("Pack timestamp must include timezone")
    for advisory in data["advisories"]:
        if not isinstance(advisory, dict):
            raise ValueError("Invalid advisory")
        for field in ("id", "name", "ecosystem"):
            if not isinstance(advisory.get(field), str) or not advisory[field]:
                raise ValueError(f"Missing advisory {field}")
        versions = advisory.get("affected_versions")
        if not isinstance(versions, list) or not versions or any(not isinstance(x, str) for x in versions):
            raise ValueError(
                "Advisories require explicit affected_versions; fuzzy version matching is unsupported"
            )
        if advisory.get("cvss") is not None and (
            not isinstance(advisory["cvss"], (int, float)) or not 0 <= advisory["cvss"] <= 10
        ):
            raise ValueError("Invalid CVSS")
        if advisory.get("epss") is not None and (
            not isinstance(advisory["epss"], (int, float)) or not 0 <= advisory["epss"] <= 1
        ):
            raise ValueError("Invalid EPSS")
        if not isinstance(advisory.get("known_exploited", False), bool):
            raise ValueError("Invalid exploitation flag")
    age = (datetime.now(timezone.utc) - generated).total_seconds() / 86400
    if age < -1:
        raise ValueError("Intelligence pack has a future timestamp")
    return data, {
        "generated_at": data["generated_at"],
        "age_days": round(max(0, age), 1),
        "stale": age > 7,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "integrity": "hash recorded; publisher signature requires separate verification",
    }


def match_inventory(inventory, pack):
    results = []
    for package in inventory:
        for advisory in pack["advisories"]:
            if package.get("name") != advisory["name"] or package.get("ecosystem") != advisory["ecosystem"]:
                continue
            if package.get("version") not in advisory["affected_versions"]:
                continue
            results.append(
                {
                    **advisory,
                    "installed_version": package["version"],
                    "match": "exact-version",
                    "confidence": "inventory-based; verify vendor/platform applicability",
                }
            )
    return results


def refresh_enrichment(cves):
    """Download public CVE metadata only, never endpoint identifiers."""
    cves = sorted(set(cves))
    if len(cves) > 1000 or any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve) for cve in cves):
        raise ValueError("Expected at most 1000 valid CVE identifiers")
    kev = request_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    known = {entry["cveID"] for entry in kev["vulnerabilities"]}
    values = {cve: {"known_exploited": cve in known} for cve in cves}
    for offset in range(0, len(cves), 100):
        response = request_json(
            "https://api.first.org/data/v1/epss?"
            + urllib.parse.urlencode({"cve": ",".join(cves[offset : offset + 100])})
        )
        for item in response.get("data", []):
            if item["cve"] in values:
                values[item["cve"]].update(epss=float(item["epss"]), epss_date=item["date"])
    return {"generated_at": utcnow(), "kev_catalog_version": kev.get("catalogVersion"), "cves": values}


def query_osv(packages, budget=30):
    """Explicit opt-in: package names, versions and ecosystems leave the endpoint."""
    supported = {"PyPI", "npm", "Go", "Maven", "crates.io", "NuGet", "Debian", "Ubuntu", "Alpine"}
    results, skipped = [], []
    deadline = time.monotonic() + budget
    for package in packages[:500]:
        if time.monotonic() >= deadline:
            skipped.extend(p.get("name") for p in packages[packages.index(package) :])
            break
        if package.get("ecosystem") not in supported or not package.get("version"):
            skipped.append(package.get("name"))
            continue
        response = request_json(
            "https://api.osv.dev/v1/query",
            {
                "package": {"name": package["name"], "ecosystem": package["ecosystem"]},
                "version": package["version"],
            },
            timeout=min(10, max(0.1, deadline - time.monotonic())),
        )
        for vulnerability in response.get("vulns", []):
            if vulnerability.get("withdrawn"):
                continue
            results.append(
                {
                    "id": vulnerability["id"],
                    "aliases": vulnerability.get("aliases", []),
                    "name": package["name"],
                    "ecosystem": package["ecosystem"],
                    "installed_version": package["version"],
                    "match": "OSV ecosystem-version query",
                    "references": [r["url"] for r in vulnerability.get("references", [])],
                    "summary": vulnerability.get("summary", ""),
                    "confidence": "OSV match; verify platform applicability",
                }
            )
    return results, skipped
