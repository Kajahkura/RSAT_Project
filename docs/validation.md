# Validation

RSAT validates evidence interpretation, cryptographic boundaries, native execution and browser behavior. Passing tests establish the tested behavior and platform scope; they do not certify the health or compliance of an endpoint.

## Published validation

| Scope | Verified result | Evidence |
|---|---|---|
| Release 2.2.0 | Eight platform/Python jobs, 13 workspace module tests, both browser suites, four native builds and publication passed | [Release run 38980473315](https://github.com/Kajahkura/RSAT_Project/actions/runs/38980473315) |
| Release 2.1.0 | Eight platform/Python jobs, both browser jobs, four native builds and publication passed | [Release run 38075110752](https://github.com/Kajahkura/RSAT_Project/actions/runs/38075110752) |
| Source revision `ac3d64f` | Eight platform/Python jobs, both browser jobs and four native builds passed | [Run 38968086839](https://github.com/Kajahkura/RSAT_Project/actions/runs/38968086839) |
| Hosted browser workspace | Public release files and live HTTPS security flows passed | [Run 38968086856](https://github.com/Kajahkura/RSAT_Project/actions/runs/38968086856) |

The release test matrix covers Python 3.11 and 3.13 on Linux x86_64, Windows x86_64, macOS Apple Silicon and macOS Intel. Statement coverage is enforced at 80%. The 2.1.0 Python suite contains 187 tests; Intel macOS explicitly skips one optional interoperability test because current `cryptography` releases do not support that architecture. All bundled crypto tests still run there.

The current source suite passes 188 tests on Linux with Python 3.13 and 86.13% statement coverage, including policy-review CLI approval and inconsistent-fixture rejection.

## Evidence and cryptography

Regression checks cover false firewall and encryption passes, malformed or missing evidence, policy applicability, expired exceptions, changed rule versions, input/output limits, command injection, collection deadlines and process-exit races. Remediation checks cover target binding, preconditions, dry-run, backup, verification and rollback.

Cryptographic verification includes RFC 8032 Ed25519, RFC 7748 X25519 and NIST AES-256-GCM vectors, wrong-key and tamper rejection, low-order recipient rejection, key-type boundaries and envelope interoperability. Signing trust requires an independently pinned key.

Platform tests also cover signed history, replay/expiry/revocation boundaries, subject-bound connectors, trusted VEX/CSAF, official OSCAL and CycloneDX schemas, and TUF metadata tamper, expiry and rollback protection. Upstream schema fixtures retain their original identifiers and notices.

## Native artifacts

Every standalone build is launched for version, audit, signed/encrypted evidence, decryption, pinned-key verification, wrong-key rejection, signed snapshots and graph/SBOM exports. Native collection smoke checks independently compare available Windows and macOS firewall observations. Windows CI parses generated PowerShell queries with the native language parser.

The Linux executable is built on Ubuntu 22.04 for a glibc 2.35 baseline. Older glibc, musl-based distributions and other Linux architectures require source installation or compatible native builds. Public release binaries and the static web archive were independently checked against published SHA-256 values and Sigstore provenance bound to the repository workflow, release tag and source revision.

Build provenance is distinct from Windows Authenticode and macOS notarization. The repository does not configure OS signing certificates. Hosted runners do not provide complete physical-device validation of BitLocker, TPM, Secure Boot, MDM, FileVault or successful backup restoration. WSL/container observations apply to the guest scope.

## Browser workspace

Workspace module tests cover same-device comparisons, policy/scope changes, observation freshness, strict decision bindings and dates, selected exports, CSV formula protection, public-key fingerprints and redaction against hostile imported prose. Browser workflows also verify note preservation, encrypted decision/label storage, device grouping, downloadable report rendering and legacy snapshot restoration.

Browser checks exercise operating-system onboarding, bounded local JSON/ZIP imports, malformed input rejection, independently pinned Ed25519 signatures, wrong-key rejection, HTML injection resistance, encrypted IndexedDB storage, wrong-passphrase rejection, successful restoration with signer trust cleared, local deletion, assistance while the browser network is offline, desktop/mobile layouts and no evidence uploads.

The [live workspace](https://rsat-workspace.blinkhost.website) serves the verified 2.1.0 frontend. Its JavaScript, worker, stylesheet, synthetic demo, license and hosting README match the release bytes. HTML changes are limited to reviewed inert search metadata; the CSP, referrer policy and executable scripts remain intact. HTTPS, HSTS and `nosniff` were verified. Desktop/mobile screenshots from the hosted checks were inspected.

## Reproduce the source checks

```sh
python -m pip install -r requirements-dev.txt -e .
python -m ruff check src tests scripts
python -m pytest --cov=rsat --cov-fail-under=80
python scripts/native_smoke.py
```

Run native checks on the platform being evaluated. The [build workflow](../.github/workflows/build.yml) includes browser and packaged-artifact verification; the [hosted workflow](../.github/workflows/hosted-web.yml) checks the public HTTPS site. CI logs and artifacts provide the result for each source revision.
