# Deploy the browser workspace

The public [RSAT Evidence Workspace](https://rsat-workspace.blinkhost.website) is live on BlinkHost. Production release `291` was activated on 16 October 2026 for project `1e3b948b-e02b-412f-98d5-a6a2f2b4639a`. It serves the verified 2.1.0 frontend. Onboarding and the synthetic demo need no sign-in.

The hosted application is the browser workspace. Native collection runs on the user's endpoint. Hosted files contain synthetic demo evidence only. The app does not require databases, outbound inference, customer accounts or audit uploads.

For a repository connection, the root `blinkhost.yaml` selects `web/`. For a frontend-only VFS project, upload the files inside `web/` and use its manifest. Both select the same pinned dependency lock and `npm ci` / `npm run build` flow. Python native collectors and their crypto extensions are not BlinkHost WASI modules.

A verified static ZIP and SHA-256 file are included with tagged GitHub releases. [Version 2.1.0](https://github.com/Kajahkura/RSAT_Project/releases/tag/v2.1.0) is published; its public static ZIP checksum and build provenance were independently verified. Extract the archive and serve `index.html` and `assets/` at the site root. Any static host can serve that ZIP. Serve over HTTPS so standard browser cryptography is available. Preserve the app's Content Security Policy, use `X-Content-Type-Options: nosniff`, and disable third-party analytics or injected scripts if claiming local evidence processing.

For this frontend-only deployment, BlinkHost's dashboard contract accepts a prebuilt ZIP with `POST /api/deployments/upload/` using multipart fields `project_id`, `environment_name=Production` and `file=deployment.zip`. The CLI's authenticated API client was used through a task-local multipart adapter because its generic `api` command accepts JSON. No local web build was run. Follow the returned `/api/deployment-requests/REQUEST_ID/` until completion, inspect the resulting deployment and confirm current public routing. This upload flow published directly; a separate activation was unnecessary.

The exact tagged frontend source and MIT license were uploaded into the project VFS and all 14 files were read back and compared by SHA-256. The published ZIP came from [release run 38075110752](https://github.com/Kajahkura/RSAT_Project/actions/runs/38075110752), tag `v2.1.0`, source `53316e839cc9957c7f5e67df0a1942c08de47e18`. Its SHA-256 is `1c8f1a2361f291b2e7d3543291d90497d1861f4725a097abe28edd97206a7a03`. BlinkHost normalizes the archive, so its artifact digest is different (`45199bec48ca695ceddb325fb2dd3b7c7782ef5529bdd8c5a90cb61fb62fddeb`). All six non-HTML public files match the release exactly. The public HTML retains the release's CSP, referrer policy and executable scripts; only canonical, Open Graph, Twitter and inert JSON-LD search metadata are added. HTTPS, HSTS and `nosniff` were verified.

BlinkHost 2.5.2 also supports Git-connected resource commands:

```sh
blinkhost projects get PROJECT_ID --json
blinkhost builds create --data @reviewed-build.json --json
blinkhost builds wait BUILD_ID --json
blinkhost previews get PREVIEW_ID --json
blinkhost deployments action DEPLOYMENT_ID activate --data @reviewed-publication.json --idempotency-key SAVED_REQUEST_KEY --json
```

Payloads must use the effective account's current resource contract. Select exact reviewed source, inspect the immutable verified artifact and preview, then publish that artifact. Save a unique publication key before submission. If the response is uncertain, use `deployments publication-lookup --idempotency-key SAVED_REQUEST_KEY`; do not replace it with a new request. Verify release routing and the public response before marking publication complete.

GitHub-hosted CLI automation can use an exact-subject BlinkHost workload identity and GitHub OIDC, avoiding long-lived repository secrets. Registration requires an authenticated BlinkHost account and appropriate scopes. No workload identity has been provisioned; publication currently uses an authenticated CLI session.

The user subsequently authorized the installed BlinkHost CLI, a narrow exception to the earlier prohibition on local Node execution. Node ran only the published CLI and its transport adapter. Web builds and browser checks continue to run in GitHub CI. Linux authentication used an isolated encrypted Secret Service; a loopback-only relay forwarded requests to the official HTTPS API with TLS verification. Credentials were kept out of the repository and source uploads.

The [hosted validation workflow](../.github/workflows/hosted-web.yml) checks the live files against the pinned public release, then exercises onboarding, imports, signature trust, injection resistance, encrypted history, offline retrieval and responsive layouts on the real HTTPS origin. It can be rerun manually from GitHub Actions without BlinkHost credentials. When publishing a new frontend release, update the pinned archive checksum in `scripts/verify_hosted_web.py` after independent release verification.
