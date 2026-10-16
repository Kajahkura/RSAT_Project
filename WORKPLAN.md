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
- [x] GitHub 2.1.0 release publication and public-download verification.
- [x] BlinkHost publication of the verified release ZIP, source readback and public HTTPS file verification.
- [x] Live HTTPS browser security validation through GitHub CI.

All proposed or incomplete capabilities must be labeled as such; no production evidence or credentials belong in the repository.

Verified checkpoint: final Python 3.13.13 suite passed 187 tests at 85.96% coverage; Ruff passed. Source `5fdac9a` passed all eight platform/Python jobs, both browser/web jobs and four native builds in run 37330491072. The downloaded static ZIP matched its checksum, and clean synthetic desktop/mobile previews were inspected. The initial Windows credential path timed out; the later authorized BlinkHost CLI login succeeded through an isolated encrypted Linux credential service. Local Node use is limited to the BlinkHost CLI; builds and browser checks run in GitHub CI.

Release complete: [v2.1.0](https://github.com/Kajahkura/RSAT_Project/releases/tag/v2.1.0), source `53316e8`, passed every required job and publication in run 38075110752. All four public native binaries and the static workspace matched published checksums and verified build provenance against the exact tag, source digest and repository workflow. The public Linux binary passed eleven local smoke steps, including signed snapshots, graph/SBOM exports and wrong-key rejection. BlinkHost release `291` is active and current at [rsat-workspace.blinkhost.website](https://rsat-workspace.blinkhost.website). Public files match the tagged release, with reviewed inert search metadata added to HTML. Hosted encrypted synchronization, TPM verifier, provider-specific connectors and managed fleet installation remain external/future work, explicitly labeled in docs/platform.md.

Hosted validation complete: [run 38968086856](https://github.com/Kajahkura/RSAT_Project/actions/runs/38968086856), source `ac3d64f`, passed both public release-file verification and the browser security flows on the real HTTPS origin. Its downloaded verification artifact confirms all seven public files and deployment `291`; desktop/mobile screenshots were inspected.

Final source validation: [run 38968086839](https://github.com/Kajahkura/RSAT_Project/actions/runs/38968086839), source `ac3d64f`, passed all eight platform/Python jobs, both browser jobs and all four native builds. The temporary deployment CLI session was logged out; the public production release remains active.
