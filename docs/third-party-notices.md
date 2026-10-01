# Third-party notices

RSAT code, original controls, and repository-native artwork are MIT licensed. No CIS benchmark text, commercial Fleet code, or copied Lynis/Velociraptor implementation is bundled.

The runtime core uses Python's standard library. Optional signing/encryption uses `cryptography`, distributed under Apache-2.0 or BSD-3-Clause terms with its own native dependency notices. PyInstaller and its hooks are build dependencies with their own license and bundling exceptions. Release environment inventories list exact installed versions; inspect component notices when redistributing binaries.

Intel macOS uses `cryptography` 48.0.1 because newer releases stopped publishing Intel macOS wheels; other platforms use 50.0.2. OSV reported no advisories for 48.0.1 at implementation time. Dependency advisories and availability must still be monitored over time.

Optional osquery is operator-provided and separately licensed (Apache-2.0 OR GPL-2.0-only). RSAT invokes a supplied binary and does not bundle its code. Public OSV, CISA KEV, and FIRST EPSS data have source-specific terms and provenance; preserve those when redistributing intelligence packs.

OSCAL schemas used for validation come from the NIST OSCAL v1.1.3 release and retain their public-domain/documentation notices. They are validation resources, not a claim of NIST endorsement or certification. The optional local model is operator-provided and subject to its own license.
