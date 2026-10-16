# RSAT evidence workspace

A responsive React/TypeScript application for local onboarding and audit review. MIT licensed, with no required account or hosted API.

```sh
npm ci
npm run build
npm run dev
```

Import RSAT 2.x audit JSON or `.rsat.zip` bundles (20 MB input cap, 50 MB expanded bundle cap, 100 entries). Parsing and bundle verification run in a bounded Web Worker. Plain JSON remains unverified. Bundle hashes establish integrity; signature trust requires an independently supplied Ed25519 public PEM key. Verification uses WebCrypto and fails closed if the browser lacks Ed25519 support. No imported HTML is executed.

The assistant retrieves matching stored findings using keywords. It does not run model inference. The graph shows supported relationships and conditional simulations. Evidence is never uploaded by this app. The synthetic demo is clearly labeled.

Local history is explicitly saved to IndexedDB using AES-256-GCM and PBKDF2-SHA256 (600,000 iterations, fresh 128-bit salt and 96-bit nonce). Passphrases remain in memory and are cleared after save/unlock. Retention is bounded to 1–100 snapshots. Deletion clears local snapshots. Browser compromise can access unlocked evidence; encryption protects retained bytes, not an active compromised session. No recovery service exists. Trust is not silently carried across history restoration.

Deploy `web/` as the application root. `blinkhost.yaml` declares the frontend only, with no database or inference requirement. The native collector stays on the user's endpoint. Other static hosts and self-hosted Vite builds work too.

## Collect, reassess and report

Follow the OS-specific download, checksum and execution steps. Obtain the audit owner's Ed25519 public key through a trusted channel and independently confirm its SHA-256 DER fingerprint before importing a signed bundle. Import failures show next steps and preserve the loaded audit. Collection happens on the endpoint; the browser does not inspect OS settings.

In Findings, select controls for JSON/CSV export or a redacted HTML client report. Selections survive filtering within the Findings view. JSON and CSV include selected finding text and recorded decision notes; they are sensitive, unsigned exports. CSV neutralizes formula-leading cells. Redacted reports use public RSAT control labels and report-local labels for custom controls. They omit device identifiers, names, timestamps, raw observations, imported prose, rule versions and free-text decision fields. Open the downloaded HTML and use Print to save a PDF. Outcomes themselves can still be sensitive.

Inspect a finding to record a planned, in-progress, ready-for-recheck or accepted-risk decision. Decisions bind to the exact audit hash and rule version; they never turn an observed FAIL into PASS. Record or remove edits before leaving the editor. Incoming assessments offer a choice when notes or device labels have unsaved changes.

In Local history, save an encrypted snapshot with an optional device label and recorded decisions. Unlock device groups with the appropriate passphrase; grouping metadata remains encrypted at rest and is only held in memory while this view is open. Hide unlocked groups to clear it. Legacy encrypted audit-only snapshots remain readable. History restoration clears signer trust.

Compare an older audit to the current assessment of the same recorded device, identity scope, platform and host/guest context. Use the same engagement salt for repeat collection. Rule and policy changes, scope changes, new or removed controls and evidence gaps are separate from recorded PASS-to-FAIL regressions and FAIL-to-PASS improvements. Collector changes have an explicit compatibility caveat. Evidence freshness is point-in-time age, with 24-hour, 7-day or 30-day review windows in device groups; it is not continuous monitoring.

The CI workflow runs module tests and browser workflows against the production build before packaging it. No backend is required for these workflows, and no cloud synchronization or remediation execution is added to the browser.
