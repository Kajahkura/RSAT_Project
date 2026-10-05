# Third-party notices

RSAT code, original controls, and repository-native artwork are MIT licensed. No CIS benchmark text, commercial Fleet code, or copied Lynis/Velociraptor implementation is bundled.

The runtime core uses Python's standard library. Optional signing/encryption uses `pycryptodomex` (PyCryptodome), distributed under BSD-2-Clause and public-domain terms. PyInstaller and its hooks are build dependencies with their own license and bundling exceptions. Release environment inventories list exact installed versions; inspect component notices when redistributing binaries.

PyCryptodome 3.23.0 provides maintained wheels for all supported architectures, including Intel macOS. An OSV query on 1 October 2026 returned no advisories for that version; this is a time-limited database check, not a guarantee. Dependency advisories and availability must be monitored. The current `cryptography` package is used only for interoperability tests on platforms it supports; it is not a bundled runtime dependency. Older Intel-compatible `cryptography` releases are not used because of upstream advisories.

Optional osquery is operator-provided and separately licensed (Apache-2.0 OR GPL-2.0-only). RSAT invokes a supplied binary and does not bundle its code. Public OSV, CISA KEV, and FIRST EPSS data have source-specific terms and provenance; preserve those when redistributing intelligence packs.

OSCAL schemas used for validation come from the NIST OSCAL v1.1.3 release and retain their public-domain/documentation notices. They are validation resources, not a claim of NIST endorsement or certification. The optional local model is operator-provided and subject to its own license.

The optional web workspace uses React/React DOM (MIT), fflate (MIT), Vite (MIT), TypeScript (Apache-2.0), and their transitive build dependencies. `web/package-lock.json` records exact versions and integrity values; upstream dependency license files remain authoritative. CycloneDX schema fixtures and CSAF schema fixtures retain their upstream terms described in `tests/schemas/README.md`. These are separate from the MIT grant for RSAT code. The optional TUF client uses python-tuf and securesystemslib under their upstream MIT/Apache-2.0 terms.
