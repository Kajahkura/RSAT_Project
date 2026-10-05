# Deploy the browser workspace

The hosted application is the browser workspace. Native collection runs on the user's endpoint. Hosted files contain synthetic demo evidence only. The app does not require databases, outbound inference, customer accounts or audit uploads.

For a repository connection, the root `blinkhost.yaml` selects `web/`. For a frontend-only VFS project, upload the files inside `web/` and use its manifest. Both select the same pinned dependency lock and `npm ci` / `npm run build` flow. Python native collectors and their crypto extensions are not BlinkHost WASI modules.

A verified static ZIP and SHA-256 file are included with tagged GitHub releases. Any static host can serve that ZIP. Serve over HTTPS so standard browser cryptography is available. Preserve the app's Content Security Policy, use `X-Content-Type-Options: nosniff`, and disable third-party analytics or injected scripts if claiming local evidence processing.

BlinkHost 2.5.2 supports remote resource commands:

```sh
blinkhost projects get PROJECT_ID --json
blinkhost builds create --data @reviewed-build.json --json
blinkhost builds wait BUILD_ID --json
blinkhost previews get PREVIEW_ID --json
blinkhost deployments action DEPLOYMENT_ID activate --data @reviewed-publication.json --idempotency-key SAVED_REQUEST_KEY --json
```

Payloads must use the effective account's current resource contract. Select exact reviewed source, inspect the immutable verified artifact and preview, then publish that artifact. Save a unique publication key before submission. If the response is uncertain, use `deployments publication-lookup --idempotency-key SAVED_REQUEST_KEY`; do not replace it with a new request. Verify release routing and the public response before marking publication complete.

GitHub-hosted CLI automation can use an exact-subject BlinkHost workload identity and GitHub OIDC, avoiding long-lived repository secrets. Registration requires an authenticated BlinkHost account and appropriate scopes. No workload identity or production deployment has been provisioned by this repository.

The current task's publication attempt was stopped at authentication: this PC's native PowerShell startup and Password Vault reads time out before authenticated API calls. The user prohibited Node execution on the PC, so the CLI will run only in a separately authorized remote environment. No project, preview or public RSAT URL is claimed until the authenticated publication completes.
