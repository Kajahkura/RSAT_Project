"""Browser checks for local import, trust, encrypted history, injection and responsive onboarding."""

import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading

from playwright.sync_api import sync_playwright
from rsat.bundle import generate_keys, create_bundle
from rsat.model import canonical

root = Path(__file__).resolve().parents[1]


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Quiet, directory=str(root / "web/dist")))
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
base = f"http://127.0.0.1:{server.server_port}"
try:
    with tempfile.TemporaryDirectory() as temporary, sync_playwright() as p:
        tmp = Path(temporary)
        browser = p.chromium.launch(headless=True, args=["--disable-gpu", "--no-zygote", "--single-process"])
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        errors = []
        evidence_requests = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on(
            "request",
            lambda r: (
                evidence_requests.append(r.url) if r.method != "GET" or not r.url.startswith(base) else None
            ),
        )
        page.goto(base, wait_until="networkidle", timeout=60000)
        for name, command in [
            ("Windows", "RSAT_Windows_x86_64.exe"),
            ("Linux", "RSAT_Linux_x86_64"),
            ("macOS", "RSAT_macOS_arm64"),
            ("macOSIntel", "RSAT_macOS_x86_64"),
        ]:
            page.locator("#platform").select_option(name)
            assert command in page.locator(".command").inner_text()
        page.get_by_label("Software inventory", exact=True).check()
        assert "--inventory" in page.locator(".command").inner_text()
        page.get_by_role("button", name="Explore a synthetic demo").click()
        page.locator(".metric-grid").wait_for(timeout=30000)
        assert "Synthetic Windows" in page.locator(".scope-note").inner_text()
        page.get_by_role("button", name="Findings", exact=False).first.click()
        page.get_by_label("Filter outcome").select_option("FAIL")
        assert page.locator("tbody tr").count() > 0
        page.get_by_label("Search findings").fill("no-such-control")
        assert page.locator("tbody tr").count() == 0
        page.get_by_role("button", name="Assistant", exact=True).click()
        page.get_by_label("Your question").fill("firewall")
        page.get_by_role("button", name="Find evidence").click()
        assert page.locator(".answer-list article").count() > 0
        audit = json.loads((root / "web/public/demo-audit.json").read_text())
        audit["findings"][0]["title"] = '<img src=x onerror="window.RSAT_INJECTED=true">'
        hostile = tmp / "hostile.json"
        hostile.write_bytes(canonical(audit))
        page.locator("input[type=file]").set_input_files(hostile)
        page.get_by_role("status").filter(has_text="Evidence opened locally").wait_for()
        page.get_by_role("button", name="Findings", exact=False).first.click()
        page.get_by_label("Filter outcome").select_option("")
        page.get_by_label("Search findings").fill("onerror")
        assert page.get_by_text(audit["findings"][0]["title"], exact=True).count() == 1
        assert page.evaluate("window.RSAT_INJECTED") is None
        invalid = tmp / "bad.json"
        invalid.write_text('{"schema_version":"2.0"}')
        page.locator("input[type=file]").set_input_files(invalid)
        page.get_by_role("status").filter(has_text="Invalid audit").wait_for()
        keys = generate_keys(tmp / "keys")
        bundle = create_bundle(
            {"audit.json": canonical(audit)}, tmp / "signed.rsat.zip", keys / "signing.key.pem"
        )
        page.locator(".trust-settings summary").click()
        page.locator("#pinned").fill((keys / "signing.pub.pem").read_text())
        page.locator("input[type=file]").set_input_files(bundle)
        page.get_by_text("Verified signature · independently pinned key", exact=True).wait_for(timeout=30000)
        other = generate_keys(tmp / "other")
        page.locator("#pinned").fill((other / "signing.pub.pem").read_text())
        page.locator("input[type=file]").set_input_files(bundle)
        page.get_by_role("status").filter(has_text="Pinned signer verification failed").wait_for()
        page.get_by_role("button", name="Local history", exact=True).click()
        page.get_by_label("History passphrase").fill("synthetic-passphrase-123")
        page.get_by_role("button", name="Save encrypted snapshot").click()
        page.locator(".history-row").wait_for(timeout=60000)
        raw = page.evaluate(
            """async()=>{const db=await new Promise(resolve=>{const r=indexedDB.open('rsat-encrypted-history',1);r.onsuccess=()=>resolve(r.result)});const rows=await new Promise(resolve=>{const r=db.transaction('snapshots').objectStore('snapshots').getAll();r.onsuccess=()=>resolve(r.result)});db.close();return rows.map(r=>({keys:Object.keys(r),plaintext:new TextDecoder().decode(r.ciphertext)}))}"""
        )
        assert "audit" not in raw[0]["keys"] and "synthetic-demo-endpoint" not in raw[0]["plaintext"]
        page.get_by_label("History passphrase").fill("wrong-passphrase-123")
        page.get_by_role("button", name="Unlock", exact=True).click()
        page.get_by_role("status").filter(has_text="Unable to unlock").wait_for(timeout=60000)
        page.get_by_role("button", name="Delete local history").click()
        page.get_by_role("status").filter(has_text="All local encrypted snapshots deleted").wait_for()
        assert page.locator(".history-row").count() == 0
        page.get_by_role("button", name="Overview", exact=True).click()
        page.screenshot(path=str(root / "docs/assets/workspace-desktop.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.screenshot(path=str(root / "docs/assets/workspace-mobile.png"), full_page=True)
        assert not errors, errors
        assert not evidence_requests, evidence_requests
        browser.close()
finally:
    server.shutdown()
    server.server_close()
print(
    "Web browser checks passed: local import, pinned trust, injection, encrypted storage, offline retrieval, responsive layout, no evidence uploads"
)
