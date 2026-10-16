# Host the browser workspace

Open the [RSAT Evidence Workspace](https://rsat-workspace.blinkhost.website) to use operating-system onboarding, explore the synthetic demo, or import your own evidence locally. No account is required.

The hosted application is a static React/TypeScript frontend. Native collection runs on the endpoint. Audit files are processed in the browser; encrypted history is saved locally in IndexedDB. Hosting does not require a database, an inference service or an evidence-upload API.

## Deploy a release archive

Download `RSAT-web-workspace.zip` and its SHA-256 manifest from the [latest release](https://github.com/Kajahkura/RSAT_Project/releases/latest). Verify the checksum and [GitHub build provenance](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations) before deployment.

Extract the archive and serve its contents at the site root:

```text
index.html
assets/
demo-audit.json
LICENSE
README.md
```

Use HTTPS so browser cryptography is available. Preserve the HTML Content Security Policy and referrer policy, set `X-Content-Type-Options: nosniff`, and avoid injecting analytics or executable third-party scripts. The demo contains synthetic evidence only. Keep the MIT license with redistributed copies.

## Build from source

The frontend uses the pinned dependency lock in `web/`:

```sh
cd web
npm ci
npm run build
```

Serve the generated `web/dist/` files over HTTPS. The [build workflow](../.github/workflows/build.yml) runs the frontend build and browser security checks before packaging release archives.

## BlinkHost

Create a frontend project and publish the verified static archive. For a repository connection, the root `blinkhost.yaml` selects `web/`. For a frontend-only VFS project, use the files inside `web/` and its manifest. Both specify the pinned dependency lock, `npm ci`, `npm run build` and `dist` output. Python native collectors and their crypto extensions run on endpoints rather than as BlinkHost WASI modules.

BlinkHost's deployment-upload API accepts `POST /api/deployments/upload/` with multipart fields `project_id`, `environment_name` and `file`. Use the current authenticated API contract for your account. Follow the returned deployment-request status URL, inspect the resulting deployment and confirm that public routing serves the reviewed artifact. The CLI's generic `api` command accepts JSON; binary uploads require the dashboard or a multipart-capable authenticated client.

For Git-connected deployments, BlinkHost also provides build, preview and publication resource commands. Save a publication idempotency key before activation. Recover an uncertain request with `deployments publication-lookup --idempotency-key SAVED_REQUEST_KEY`; replacing the key can create a second operation. Verify the active release and public files after publication.

GitHub Actions automation can use an exact-subject BlinkHost workload identity and GitHub OIDC. Configure scopes for the intended project and environment, and keep credentials out of repository files.

## Verify a hosted deployment

The [hosted validation workflow](../.github/workflows/hosted-web.yml) checks the public RSAT site against a pinned release archive, then tests onboarding, local imports, signature verification, injection resistance, encrypted history, offline assistance and desktop/mobile layouts on the HTTPS origin. It can be rerun from GitHub Actions without BlinkHost credentials.

When publishing a different release, update the archive URL and checksum in `scripts/verify_hosted_web.py` after verifying its release provenance. Host-added search metadata must remain within the reviewed verifier allowlist; executable script changes fail verification.
