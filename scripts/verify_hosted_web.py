"""Verify live static files against the pinned, independently attested 2.1.0 release."""

import hashlib
import html
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
import zipfile

BASE = "https://rsat-workspace.blinkhost.website"
ARCHIVE_URL = "https://github.com/Kajahkura/RSAT_Project/releases/download/v2.1.0/RSAT-web-workspace.zip"
ARCHIVE_SHA256 = "1c8f1a2361f291b2e7d3543291d90497d1861f4725a097abe28edd97206a7a03"


def fetch(url):
    request = Request(  # noqa: S310 -- caller uses only fixed release and hosted HTTPS URLs
        url, headers={"User-Agent": "RSAT-hosted-verification/2.1", "Accept-Encoding": "identity"}
    )
    with urlopen(request, timeout=45) as response:  # noqa: S310 -- fixed HTTPS URLs; no user input
        body = response.read(1_000_001)
        if response.status != 200 or len(body) > 1_000_000:
            raise ValueError("Unsupported static response")
        if url.startswith(BASE) and response.geturl() != url:
            raise ValueError("Unexpected hosted redirect")
        return body, response.headers


def strip_reviewed_metadata(document):
    """Allow only BlinkHost's reviewed, inert search metadata additions."""
    def canonical(match):
        if html.unescape(match[1]) != BASE + "/":
            raise ValueError("Unexpected canonical URL")
        return ""

    def structured_data(match):
        expected = {
            "@context": "https://schema.org",
            "@type": "WebSite",
            "description": (
                "Open-source endpoint and AI tooling security. "
                "Review evidence locally, verify signed bundles, and track improvements."
            ),
            "name": "RSAT — Evidence Workspace",
        }
        if json.loads(match[1]) != expected:
            raise ValueError("Unexpected structured metadata")
        return ""

    document = re.sub(r'<link rel="canonical" href="([^"]+)">', canonical, document, count=1)
    document = document.replace('<meta property="og:type" content="website">', "", 1)
    document = document.replace('<meta name="twitter:card" content="summary_large_image">', "", 1)
    return re.sub(
        r'<script type="application/ld\+json">(.*?)</script>', structured_data, document, count=1, flags=re.S
    )


def main():
    archive, _ = fetch(ARCHIVE_URL)
    if hashlib.sha256(archive).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("Pinned release archive checksum mismatch")
    results = []
    with zipfile.ZipFile(io.BytesIO(archive)) as release:
        for name in release.namelist():
            url = BASE + ("/" if name == "index.html" else "/" + name)
            actual, headers = fetch(url)
            expected = release.read(name)
            matches = actual == expected
            if name == "index.html":
                if headers.get("X-Content-Type-Options") != "nosniff":
                    raise ValueError("Missing MIME protection")
                if not headers.get("Strict-Transport-Security"):
                    raise ValueError("Missing HTTPS transport policy")
                if strip_reviewed_metadata(actual.decode()) != expected.decode():
                    raise ValueError("Hosted HTML differs beyond reviewed search metadata")
            elif not matches:
                raise ValueError(f"Hosted release file mismatch: {name}")
            results.append(
                {
                    "path": name,
                    "sha256": hashlib.sha256(actual).hexdigest(),
                    "release_sha256": hashlib.sha256(expected).hexdigest(),
                    "byte_identical": matches,
                    "reviewed_metadata_only": name == "index.html" and not matches,
                    "deployment_id": headers.get("X-Blinkhost-Deployment-Id"),
                    "artifact_sha256": headers.get("X-Blinkhost-Artifact-Sha256"),
                }
            )
    Path("hosted-web-verification.json").write_text(
        json.dumps(
            {
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "url": BASE,
                "release": "v2.1.0",
                "release_archive_sha256": ARCHIVE_SHA256,
                "files": results,
            },
            indent=2,
        ) + "\n"
    )
    print("Hosted HTTPS files match release 2.1.0; HTML has only reviewed, inert search metadata additions.")


if __name__ == "__main__":
    main()
