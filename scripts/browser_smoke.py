"""Validate report interactions and mobile layout using synthetic evidence."""

import json
from pathlib import Path
import tempfile

from playwright.sync_api import sync_playwright

from rsat.report import render

root = Path(__file__).resolve().parents[1]
audit = json.loads((root / "examples/sample-audit.json").read_text())
with tempfile.TemporaryDirectory() as tmp, sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1280, "height": 1000})
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.set_content(render(audit), wait_until="domcontentloaded")
    total = page.locator("tbody tr:visible").count()
    page.locator("#state").select_option("FAIL")
    assert 0 < page.locator("tbody tr:visible").count() < total
    page.locator("#search").fill("BitLocker")
    assert page.locator("tbody tr:visible").count() == 1
    page.locator("#search").fill("no-such-control")
    assert page.locator("tbody tr:visible").count() == 0
    page.locator("#search").fill("")
    page.locator("#state").select_option("")
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    page.screenshot(path=str(Path(tmp) / "mobile.png"))
    assert not errors, errors
    browser.close()
print("Browser interaction and mobile layout checks passed")
