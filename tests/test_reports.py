import copy
import pytest
from rsat.model import validate_audit
from rsat.report import dashboard, render


def test_endpoint_html_escaped(audit):
    audit["findings"][0]["details"] = '<img src=x onerror="alert(1)">'
    audit["observations"][0]["value"][0]["mount"] = "<script>alert(1)</script>"
    html = render(audit)
    assert "<img src=x" not in html and "&lt;img" in html
    assert "<script>alert" not in html and "&lt;script&gt;" in html
    assert "connect-src" in html and "UNKNOWN" in html


def test_report_has_evidence_coverage_and_filters(audit):
    html = render(audit)
    assert "Evidence &amp; recommended action" in html
    assert "not an overall security score" in html
    assert 'id="search"' in html and 'id="state"' in html
    assert "https://cdn" not in html


def test_dashboard_latest_per_asset(audit):
    before = copy.deepcopy(audit)
    before["started_at"] = "2000-01-01T00:00:00Z"
    html = dashboard([audit, before])
    assert '<div class="metric">1</div>' in html
    assert '<div class="metric">2</div>' in html
    assert "2000-01-01" not in html


def test_schema_rejects_bad_states_and_duplicates(audit):
    audit["findings"][0]["status"] = "SECURE"
    with pytest.raises(ValueError):
        validate_audit(audit)
    audit["findings"][0]["status"] = "PASS"
    audit["observations"].append(audit["observations"][0])
    with pytest.raises(ValueError):
        validate_audit(audit)
