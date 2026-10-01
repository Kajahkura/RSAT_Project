# Validation record

Validation is performed against the source revision, with platform and scope stated explicitly. A passing test suite is not proof that every endpoint configuration is covered.

The local development environment is Linux x86_64. The expanded suite passed 121 tests on Python 3.13.13 with 85.94% statement coverage; a preceding Python 3.11.15 run passed 119 tests with 85.92% coverage before the two RDP applicability cases were added. Coverage is enforced at 80% in CI. Linux read-only native smoke and standalone executable audit/key-generation checks passed. A CLI signing/encryption/decryption/pinned-key verification round trip passed.

Checks include the original firewall/BitLocker/update regressions, malformed and missing evidence, native failure isolation, subprocess deadlines, command argument boundaries, report escaping, policy constraints, exception expiry, comparison semantics, exact-version intelligence, SSH injection prevention, loopback probes, signing trust, wrong keys, tampered data/header, encryption round trips, exclusive output creation, and remediation dry-run/preconditions/backup/verification/rollback.

`scripts/native_smoke.py` runs read-only collections on native runners and independently compares Windows/macOS firewall observations. Windows CI additionally parses every generated PowerShell query with PowerShell's language parser. A native smoke pass is not a complete physical device laboratory: runner hardware may not provide BitLocker, TPM, Secure Boot, MDM, FileVault, or backups.

The build matrix targets Linux x86_64, Windows x86_64, macOS Apple Silicon, and macOS Intel. Every standalone artifact is launched for version and audit smoke checks. Python 3.11 and 3.13 run the test matrix. Signing and crypto are included in portable builds.

Release checksums and a CycloneDX inventory record the build environment. GitHub artifact attestations are separate from OS Authenticode signing and macOS notarization. No certificates are configured in this repository; published executables must not claim those OS signing properties.

The synthetic generated report passed Chromium checks at 1280px desktop and 390px mobile widths, including filtering and no document-level horizontal overflow. Screenshots are in `docs/assets/`. Official OSCAL 1.1.3 schemas are used for paired export validation. Imported customer evidence and external advisories are not evaluated against production client environments during development.

The first native CI run passed Linux and both macOS architectures on Python 3.11/3.13. Windows native smoke caught an update-policy PowerShell pipeline syntax error and a CIM startup timeout; both were corrected and rerun. Consult the linked GitHub workflow for the final revision's native results.
