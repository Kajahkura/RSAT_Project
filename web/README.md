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
