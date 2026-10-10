# RSAT next platform implementation

Authorized scope: implement the advanced roadmap, verify it, push GitHub changes, and publish a BlinkHost web application. Maintain MIT licensing and a self-hosted/local workflow.

- [x] Collection correctness: host/guest scope, distro package identity, full skipped coverage, diagnostics.
- [x] Grounded assistant: typed claims, deterministic validation, scoped questions and adaptive read-only rechecks.
- [x] AI tooling audits: model listeners, explicit MCP configuration metadata, permissions and provenance.
- [x] Evidence graph, supported relationships, counterfactual changes and re-audit comparison.
- [x] Continuous assessment (self-hosted signed plaintext store): device keys, signed histories, replay-resistant enrollment/synchronization and retention.
- [x] Intelligence/interoperability: SBOM/ML-BOM, trusted VEX/CSAF, OCSF and external identity evidence.
- [x] Read-only MCP interface, constrained companion API and self-hosted organization workspace.
- [x] Secure TUF download client, explicit unverified attestation boundary and reviewed policy drafts.
- [x] Web app: onboarding, local import, signature verification, encrypted history, graph/copilot workspace.
- [x] Native, security, interoperability and browser validation.
- [ ] GitHub 2.1.0 release publication and public-download verification.
- [ ] BlinkHost compatibility/build/preview/publication and public URL verification.

All proposed or incomplete capabilities must be labeled as such; no production evidence or credentials belong in the repository.

Verified checkpoint: final Python 3.13.13 suite passed 187 tests at 85.96% coverage; Ruff passed. Source `5fdac9a` passed all eight platform/Python jobs, both browser/web jobs and four native builds in run 37330491072. The downloaded static ZIP matched its checksum, and clean synthetic desktop/mobile previews were inspected. BlinkHost secure credential access remains unavailable: the 10 October PowerShell startup diagnostic timed out before any credential/API operation. No Node will run on the PC per user instruction.

Final release gate: implementation matrix passed after the process-cleanup fix; the 2.1.0 tag repeats the full matrix before publishing native and static-web assets with checksums/provenance. Verify public downloads after publication. Hosted encrypted synchronization, TPM verifier, provider-specific connectors and managed fleet installation remain external/future work, explicitly labeled in docs/platform.md.
