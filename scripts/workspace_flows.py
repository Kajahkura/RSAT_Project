"""Exercise reassessment and reporting through the public browser interface."""

import json

from playwright.sync_api import expect
from rsat.model import canonical


def verify_workspace(page, root, tmp):
    audit = json.loads((root / "web/public/demo-audit.json").read_text())
    original = tmp / "workflow-original.json"
    original.write_bytes(canonical(audit))
    page.locator("#pinned").fill("")
    page.locator("#audit-file").set_input_files(original)
    expect(page.get_by_role("status")).to_contain_text("Evidence opened locally", timeout=30000)
    expect(page.locator(".scope-note")).to_contain_text("Synthetic Windows")
    page.get_by_role("button", name="Findings", exact=False).first.click()
    page.get_by_label("Search findings").fill("")
    page.get_by_label("Filter outcome").select_option("")
    first = audit["findings"][0]
    page.get_by_role("button", name=first["title"], exact=False).click()
    page.get_by_label("Responsible person or team").fill("PRIVATE-OWNER")
    page.get_by_label("Decision notes").fill("PRIVATE-NOTE")
    page.get_by_role("button", name="Local history", exact=True).click()
    expect(page.get_by_role("status")).to_contain_text("before leaving its editor")
    expect(page.get_by_label("Decision notes")).to_have_value("PRIVATE-NOTE")

    after = json.loads(canonical(audit))
    after["audit_id"] = "second-assessment"
    after["started_at"] = "2026-10-02T10:00:00Z"
    after["finished_at"] = "2026-10-02T10:00:30Z"
    after["findings"][0]["status"] = "PASS"
    after["findings"][1]["status"] = "FAIL"
    after["findings"][2]["status"] = "UNKNOWN"
    incoming = tmp / "workflow-current.json"
    incoming.write_bytes(canonical(after))
    page.locator("#audit-file").set_input_files(incoming)
    page.get_by_role("dialog", name="Unsaved assessment notes").wait_for()
    page.get_by_role("button", name="Keep current assessment", exact=True).click()
    expect(page.get_by_label("Decision notes")).to_have_value("PRIVATE-NOTE")
    page.get_by_label("Decision status").select_option("ready_for_recheck")
    page.get_by_label("Review date").fill("2026-12-01")
    page.get_by_role("button", name="Record decision", exact=True).click()
    expect(page.locator(".evidence-detail > .badge")).to_have_text("FAIL")

    page.get_by_label("Select " + first["id"], exact=True).check()
    page.get_by_label("Select " + audit["findings"][1]["id"], exact=True).check()
    page.get_by_label("Search findings").fill("no-such-control")
    expect(page.locator(".export-tools")).to_contain_text("2 selected findings")
    page.get_by_label("Search findings").fill("")
    exports = {}
    for button, name in [
        ("Export selected JSON", "selected.json"),
        ("Export selected CSV", "selected.csv"),
        ("Create redacted report", "redacted.html"),
    ]:
        with page.expect_download() as captured:
            page.get_by_role("button", name=button, exact=True).click()
        target = tmp / name
        captured.value.save_as(target)
        exports[name] = target.read_text(encoding="utf-8-sig")
    selected = json.loads(exports["selected.json"])
    assert len(selected["findings"]) == 2
    assert selected["findings"][0]["remediation_decision"]["note"] == "PRIVATE-NOTE"
    assert "unsigned" in selected["export_verification"]
    assert "PRIVATE-NOTE" in exports["selected.csv"]
    report = exports["redacted.html"]
    for value in ["PRIVATE-NOTE", "PRIVATE-OWNER", audit["asset_id"], audit["started_at"], first["details"]]:
        assert value not in report
    report_page = page.context.new_page()
    report_requests = []
    report_page.on("request", lambda request: report_requests.append(request.url))
    report_page.goto((tmp / "redacted.html").as_uri())
    expect(report_page.get_by_role("heading", name="Redacted assessment excerpt")).to_be_visible()
    assert report_page.locator("tbody tr").count() == 2
    assert not [url for url in report_requests if url.startswith(("http:", "https:"))]
    report_page.close()

    page.get_by_role("button", name="Local history", exact=True).click()
    page.get_by_label("Device label for this assessment").fill("PRIVATE-DEVICE-LABEL")
    page.get_by_label("History passphrase").fill("workflow-passphrase-123")
    page.get_by_role("button", name="Save encrypted snapshot", exact=True).click()
    expect(page.locator(".history-row")).to_have_count(1, timeout=60000)
    expect(page.get_by_label("History passphrase")).to_have_value("")
    raw = page.evaluate("""async()=>{
      const db=await new Promise(resolve=>{const r=indexedDB.open('rsat-encrypted-history',1);r.onsuccess=()=>resolve(r.result)});
      const rows=await new Promise(resolve=>{const r=db.transaction('snapshots').objectStore('snapshots').getAll();r.onsuccess=()=>resolve(r.result)});
      db.close();return rows.map(r=>({keys:Object.keys(r).sort(),plain:new TextDecoder().decode(r.ciphertext)}));
    }""")
    assert raw[0]["keys"] == ["ciphertext", "created", "id", "iv", "salt"]
    for value in ["PRIVATE-NOTE", "PRIVATE-OWNER", "PRIVATE-DEVICE-LABEL", audit["asset_id"]]:
        assert value not in raw[0]["plain"]

    page.reload(wait_until="networkidle")
    page.get_by_role("button", name="Explore a synthetic demo").click()
    page.locator(".metric-grid").wait_for(timeout=30000)
    page.get_by_role("button", name="Local history", exact=True).click()
    page.get_by_label("History passphrase").fill("workflow-passphrase-123")
    page.get_by_role("button", name="Unlock", exact=True).click()
    expect(page.get_by_text("Decrypted browser history · signer trust not retained", exact=True)).to_be_visible(timeout=60000)
    page.get_by_role("button", name="Findings", exact=False).first.click()
    expect(page.locator("tbody tr").first).to_contain_text("Ready for recheck")
    page.get_by_role("button", name=first["title"], exact=False).click()
    expect(page.get_by_label("Decision notes")).to_have_value("PRIVATE-NOTE")

    page.locator("#audit-file").set_input_files(incoming)
    expect(page.locator(".metric-grid")).to_be_visible()
    expect(page.get_by_text("Evidence opened locally. No evidence was uploaded.", exact=True)).to_be_visible()
    page.get_by_role("button", name="Local history", exact=True).click()
    page.get_by_label("History passphrase").fill("workflow-passphrase-123")
    page.get_by_role("button", name="Compare to current", exact=True).click()
    expect(page.locator(".comparison")).to_contain_text("1 regressions", timeout=60000)
    expect(page.locator(".comparison")).to_contain_text("1 improvements")
    expect(page.locator(".comparison")).to_contain_text("1 evidence gaps")

    other = json.loads(canonical(after))
    other["asset_id"] = "unrelated-device"
    other["audit_id"] = "third-assessment"
    other_file = tmp / "workflow-other.json"
    other_file.write_bytes(canonical(other))
    page.locator("#audit-file").set_input_files(other_file)
    expect(page.locator(".asset-strip")).to_contain_text("unrelated-de")
    page.get_by_role("button", name="Local history", exact=True).click()
    page.get_by_label("History passphrase").fill("workflow-passphrase-123")
    page.get_by_role("button", name="Compare to current", exact=True).click()
    expect(page.get_by_role("status")).to_contain_text("same device", timeout=60000)
    page.get_by_label("History passphrase").fill("workflow-passphrase-123")
    page.get_by_role("button", name="Save encrypted snapshot", exact=True).click()
    expect(page.locator(".history-row")).to_have_count(2, timeout=60000)
    page.get_by_label("History passphrase").fill("workflow-passphrase-123")
    page.get_by_role("button", name="Unlock device groups", exact=True).click()
    expect(page.locator(".device-group")).to_have_count(2, timeout=60000)
    expect(page.locator(".device-group").filter(has_text="PRIVATE-DEVICE-LABEL").get_by_role("button", name="Compare to current")).to_be_disabled()
    page.get_by_label("Freshness review window").select_option("720")
    expect(page.locator(".device-groups")).to_contain_text("Review window: 720 hours")
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.set_viewport_size({"width": 1440, "height": 1000})
    page.get_by_role("button", name="Hide unlocked groups", exact=True).click()
    expect(page.locator(".device-group")).to_have_count(0)
    expect(page.locator(".history-panel")).not_to_contain_text("PRIVATE-DEVICE-LABEL")
    page.get_by_role("button", name="Delete local history", exact=True).click()
    expect(page.locator(".history-row")).to_have_count(0)

    # Produce an actual pre-2.2 encrypted row, without importing test-only application code.
    def insert_snapshot(payload):
        page.evaluate("""async payload=>{
          const id=crypto.randomUUID(),salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
          const material=await crypto.subtle.importKey('raw',new TextEncoder().encode('legacy-passphrase-123'),'PBKDF2',false,['deriveKey']);
          const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt']);
          const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:new TextEncoder().encode(id)},key,new TextEncoder().encode(JSON.stringify(payload)));
          const db=await new Promise(resolve=>{const r=indexedDB.open('rsat-encrypted-history',1);r.onsuccess=()=>resolve(r.result)});
          await new Promise((resolve,reject)=>{const tx=db.transaction('snapshots','readwrite');tx.objectStore('snapshots').put({id,created:Date.now(),salt:[...salt],iv:[...iv],ciphertext});tx.oncomplete=resolve;tx.onabort=reject});db.close();
        }""", payload)
        page.reload(wait_until="networkidle")
        page.get_by_role("button", name="Explore a synthetic demo").click()
        page.locator(".metric-grid").wait_for(timeout=30000)
        page.get_by_role("button", name="Local history", exact=True).click()

    insert_snapshot(audit)
    page.get_by_label("History passphrase").fill("legacy-passphrase-123")
    page.get_by_role("button", name="Unlock", exact=True).click()
    expect(page.get_by_text("Decrypted browser history · signer trust not retained", exact=True)).to_be_visible(timeout=60000)
    page.get_by_role("button", name="Local history", exact=True).click()
    expect(page.get_by_label("Device label for this assessment")).to_have_value("")
    page.get_by_role("button", name="Delete local history", exact=True).click()
    expect(page.locator(".history-row")).to_have_count(0)
    insert_snapshot({"format": "rsat.workspace.snapshot/1", "audit": audit, "deviceLabel": "", "decisions": [{"controlId": first["id"], "state": "planned", "auditHash": "foreign-audit"}]})
    page.get_by_label("History passphrase").fill("legacy-passphrase-123")
    page.get_by_role("button", name="Unlock", exact=True).click()
    expect(page.get_by_role("status")).to_contain_text("Unable to unlock", timeout=60000)
    expect(page.locator(".asset-strip")).to_contain_text(audit["asset_id"][:12])
    page.get_by_role("button", name="Delete local history", exact=True).click()
    expect(page.locator(".history-row")).to_have_count(0)
    print("Reassessment/reporting browser flows passed: note preservation, encrypted decisions, grouped identities, redacted downloads, legacy history and foreign binding rejection")
