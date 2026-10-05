"""Opt-in bounded HTTPS JSON reads; credentials stay in caller-selected files."""

from datetime import datetime, timezone
import json
from urllib.parse import urlsplit
from urllib.request import Request, build_opener
from urllib.request import HTTPRedirectHandler


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise ValueError("Connector redirects are not allowed")


from .interoperability import external_evidence


def fetch_context(url, token, kind, subject_id, timeout=15):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("Connector requires HTTPS and no embedded credentials")
    if kind not in {"identity", "cloud", "mdm"} or not isinstance(subject_id, str) or not subject_id:
        raise ValueError("Invalid connector kind/subject")
    if not isinstance(token, str) or not token or "\r" in token or "\n" in token:
        raise ValueError("Invalid connector credential")
    request = Request(url, headers={"Authorization": "Bearer " + token, "Accept": "application/json"})  # noqa: S310 -- HTTPS validated above
    with build_opener(NoRedirect).open(request, timeout=timeout) as response:
        raw = response.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("Connector response exceeds limit")
    document = json.loads(raw)
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("claims"), list)
        or document.get("subject_id") != subject_id
    ):
        raise ValueError("Connector contract/subject mismatch")
    data = external_evidence(
        {
            "schema_version": "1.0",
            "kind": kind,
            "subject_id": subject_id,
            "source": parsed.hostname,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "claims": document["claims"],
        }
    )
    data["verification"] = (
        "TLS-authenticated configured source; subject mapping and semantic claims unverified"
    )
    return data
