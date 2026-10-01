# Validation record

Validation is performed against the source revision, with platform and scope stated explicitly. A passing test suite is not proof that every endpoint configuration is covered.

The local development environment is Linux x86_64. The expanded suite passed 151 tests on Python 3.11.15 and 3.13.13 with 86.72% statement coverage. Coverage is enforced at 80% in CI. Linux read-only native smoke and standalone executable audit/key-generation checks passed. A CLI signing/encryption/decryption/pinned-key verification round trip passed.

Cryptographic checks include RFC 8032 Ed25519 and RFC 7748 X25519 vectors, a NIST AES-256-GCM vector, low-order recipient rejection, key-type boundaries, and interoperability with the prior backend's PEM keys and encrypted envelopes. PyCryptodome supplies the primitives on every supported architecture. Interoperability with current `cryptography` runs where upstream supports that package; only that optional cross-library test is skipped on Intel macOS.

Checks include malformed imported references, exception/risk structures and vulnerability priority fields, plus the original firewall/BitLocker/update regressions, malformed and missing evidence, native failure isolation, subprocess deadlines, command argument boundaries, report escaping, policy constraints, exception expiry, comparison semantics, exact-version intelligence, SSH injection prevention, loopback probes, signing trust, wrong keys, tampered data/header, encryption round trips, exclusive output creation, and remediation dry-run/preconditions/backup/verification/rollback.

`scripts/native_smoke.py` runs read-only collections on native runners and independently compares Windows/macOS firewall observations. Windows CI additionally parses every generated PowerShell query with PowerShell's language parser. A native smoke pass is not a complete physical device laboratory: runner hardware may not provide BitLocker, TPM, Secure Boot, MDM, FileVault, or backups.

The build matrix targets Linux x86_64, Windows x86_64, macOS Apple Silicon, and macOS Intel. Every standalone artifact is launched for version, audit, signed/encrypted evidence, decryption, pinned-key verification, and wrong-key rejection smoke checks. Python 3.11 and 3.13 run the test matrix. Signing and crypto are included in portable builds.

Release checksums and a CycloneDX inventory record the build environment. GitHub artifact attestations are separate from OS Authenticode signing and macOS notarization. No certificates are configured in this repository; published executables must not claim those OS signing properties.

The synthetic generated report passed Chromium checks at 1280px desktop and 390px mobile widths, including filtering and no document-level horizontal overflow. Screenshots are in `docs/assets/`. Official OSCAL 1.1.3 schemas are used for paired export validation. Imported customer evidence and external advisories are not evaluated against production client environments during development.

Native CI exposed an update-policy PowerShell syntax error and a Windows CIM startup timeout; both were corrected. The subsequent eight-job Python matrix, browser job, and four native builds passed. The crypto backend was then replaced to avoid an advisory-affected older Intel Mac dependency. Consult the [GitHub workflow](https://github.com/Kajahkura/RSAT_Project/actions/workflows/build.yml) for the final revision's native results.
