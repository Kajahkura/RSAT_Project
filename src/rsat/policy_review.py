"""Constrained policy review: verify citations, approval metadata and expected rule outcomes."""

from .policy import validate_policy, evaluate
from .model import canonical
import hashlib


def validate_policy_review(submission):
    if not isinstance(submission, dict) or set(submission) != {"policy", "sources", "fixtures", "review"}:
        raise ValueError("Require policy, sources, fixtures and explicit review metadata")
    policy = validate_policy(submission["policy"])
    if (
        not isinstance(submission["sources"], list)
        or not submission["sources"]
        or any(not isinstance(x, str) or not x.startswith("https://") for x in submission["sources"])
    ):
        raise ValueError("Policy review requires cited HTTPS sources")
    if not isinstance(submission["fixtures"], list) or not submission["fixtures"]:
        raise ValueError("Policy review requires independently reviewed fixtures")
    covered = set()
    for fixture in submission["fixtures"]:
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
            raise ValueError("Policy disagrees with expected fixture outcomes")
        covered.update((ident, status) for ident, status in actual.items())
    for rule in policy["rules"]:
        if any((rule["id"], status) not in covered for status in ("PASS", "FAIL", "UNKNOWN")):
            raise ValueError("Each policy rule needs PASS, FAIL and UNKNOWN fixtures")
    review = submission["review"]
    if not isinstance(review, dict) or set(review) != {"reviewer", "approved", "policy_sha256"}:
        raise ValueError("Invalid policy review")
    digest = hashlib.sha256(canonical(policy)).hexdigest()
    approved = (
        review["approved"] is True
        and isinstance(review["reviewer"], str)
        and bool(review["reviewer"].strip())
        and review["policy_sha256"] == digest
    )
    return {
        "policy_sha256": digest,
        "fixtures_passed": len(submission["fixtures"]),
        "approved_for_signed_publication": bool(approved),
        "limitations": "Reviewer declaration; independent source correctness and golden-device validation remain reviewer responsibilities.",
    }
