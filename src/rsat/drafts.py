"""Constrained policy drafts: review metadata and outcome fixtures, never executable collectors."""

from .policy import validate_policy, evaluate
from .model import canonical
import hashlib


def validate_draft(draft):
    if not isinstance(draft, dict) or set(draft) != {"policy", "sources", "fixtures", "review"}:
        raise ValueError("Require policy, sources, fixtures and explicit review metadata")
    policy = validate_policy(draft["policy"])
    if (
        not isinstance(draft["sources"], list)
        or not draft["sources"]
        or any(not isinstance(x, str) or not x.startswith("https://") for x in draft["sources"])
    ):
        raise ValueError("Policy drafts need cited HTTPS sources")
    if not isinstance(draft["fixtures"], list) or not draft["fixtures"]:
        raise ValueError("Policy drafts need independently reviewed fixtures")
    covered = set()
    for fixture in draft["fixtures"]:
        if (
            not isinstance(fixture, dict)
            or set(fixture) != {"platform", "observations", "expected"}
            or not isinstance(fixture["expected"], dict)
        ):
            raise ValueError("Invalid policy fixture")
        actual = {
            f["id"]: f["status"] for f in evaluate(policy, fixture["observations"], fixture["platform"])
        }
        if actual != fixture["expected"]:
            raise ValueError("Policy draft disagrees with expected fixture outcomes")
        covered.update((ident, status) for ident, status in actual.items())
    for rule in policy["rules"]:
        if any((rule["id"], status) not in covered for status in ("PASS", "FAIL", "UNKNOWN")):
            raise ValueError("Each draft rule needs PASS, FAIL and UNKNOWN fixtures")
    review = draft["review"]
    if not isinstance(review, dict) or set(review) != {"reviewer", "approved", "policy_sha256"}:
        raise ValueError("Invalid draft review")
    digest = hashlib.sha256(canonical(policy)).hexdigest()
    approved = (
        review["approved"] is True
        and isinstance(review["reviewer"], str)
        and bool(review["reviewer"].strip())
        and review["policy_sha256"] == digest
    )
    return {
        "policy_sha256": digest,
        "fixtures_passed": len(draft["fixtures"]),
        "approved_for_signed_publication": bool(approved),
        "limitations": "Reviewer declaration; independent source correctness and golden-device validation remain reviewer responsibilities.",
    }
