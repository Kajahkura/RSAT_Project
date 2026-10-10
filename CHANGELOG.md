# Changelog

## 2.1.0 — 2026-10-10

- Added an MIT-licensed React/TypeScript browser workspace with platform onboarding, bounded local imports, independently pinned bundle verification, offline assistance and encrypted local history.
- Added five AI tooling rules for selected MCP declarations and model listeners, preserving unknowns and excluding configuration secrets.
- Bound model-assisted selections to exact audit hashes and typed evidence claims; added read-only adaptive rechecks and an MCP interface.
- Added scoped evidence graphs, conditional change simulations and explicit host/guest collection boundaries.
- Added signed device snapshots, hash-linked history, scoped organization tokens and replay-resistant enrollment/upload workflows.
- Added CycloneDX SBOM/ML-BOM, OCSF, pinned VEX/CSAF, bounded external connectors, TUF downloads and reviewed policy drafts.
- Corrected distro/source package advisory identity, skipped-inventory accounting, partial AI-config failures and subprocess cleanup races.
- Extended native, cryptographic, interoperability and browser security verification. See the [validation record](docs/validation.md) for measured results and platform limits.
- Packaged the static workspace with checksums and documented BlinkHost publication. Authenticated BlinkHost deployment remains pending; hardware attestation and managed fleet/cloud integrations remain external work.

## 2.0.1 — 2026-10-01

- Build the Linux executable on Ubuntu 22.04 for the glibc 2.35 baseline. The initial 2.0.0 Linux build required GLIBC_2.38 and could not launch on Ubuntu 22.04.
- Keep release inventories tied to the actual installed RSAT version.

## 2.0.0 — 2026-10-01

- Replaced monolithic checks with collectors, normalized evidence, and constrained versioned policies.
- Corrected firewall, suspended BitLocker, missing update evidence, and localhost exposure interpretations.
- Added 42 original controls across Windows, macOS, and Linux; explicit unknown/error/applicability outcomes.
- Added bounded native execution, structured PowerShell data, software inventory, and optional osquery collection.
- Added contextual risk scenarios, offline exact-version intelligence, and explicit OSV/KEV/EPSS workflows.
- Added responsive standalone reports, local engagement dashboards, comparisons, and expiring exceptions.
- Added signed manifests, pinned-key verification, X25519/AES-GCM recipient encryption, and OSCAL exports.
- Added remediation plans, explicit allowlisted actions, verification, saved state, and rollback.
- Added existing SSH/HTTPS WinRM remote collection, explicit TCP probes, and optional cited local model summaries.
- Added 151 tests, cryptographic interoperability and published vectors, native CI, supported Python builds, Intel/Apple Silicon artifacts, release checksums and build inventory.
- Added MIT LICENSE, architecture and usage documentation, contributor/security guidance, and illustrated repository presentation.

Native CI and test results are recorded in the release validation document. OS signing/notarization requires maintainer certificates; a bundle signature is a separate mechanism.

## 1.0.0 — 2025-12-18

Initial portable Windows/macOS executable and HTML report.
