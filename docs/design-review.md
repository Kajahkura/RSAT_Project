# RSAT review and development options

Research date: 1 October 2026. Project: [Kajahkura/RSAT_Project](https://github.com/Kajahkura/RSAT_Project).

## Assessment

RSAT has a useful product idea: send a client a small executable, run a short endpoint audit, and return a readable local report without deploying a persistent agent. The existing implementation is an early prototype. It is not yet reliable enough to support a consultant's conclusion that an endpoint is secure, correctly patched, or externally protected.

The most valuable next step is to make its conclusions dependable, then expand into contextual risk analysis and evidence-backed remediation. Adding hundreds of checks before fixing the interpretation of the existing checks would make the reports less trustworthy.

The source reviewed is `/root/RSAT_Project/src/audit_tool.py`, at local commit `29235be`. Its contents match public `main`, verified by direct download. Source SHA-256: `c318288390dbace74914827385a34e11ce66a3221a26395d6f1815300f20c73c`.

The repository was created on 17 December 2025; the latest source push reported by GitHub was 18 December 2025. The public v1.0.0 release contains Windows and macOS executables, approximately 7.4 MB and 6.5 MB respectively. That demonstrates a working distribution pipeline, not operational accuracy. GitHub reported two stars, zero forks, and two downloads for each executable at review time. Those numbers are too small to infer real adoption or customer satisfaction.

| Dimension | Assessment | Reason |
|---|---|---|
| Workflow | Useful foundation | Portable execution and a self-contained HTML report suit short consulting engagements. |
| Maintainability | Understandable prototype | About 315 lines, standard-library runtime, few moving parts; collectors, policy decisions, and presentation are coupled. |
| Accuracy | Needs correction before professional reliance | Firewall and encryption checks can produce false passes. |
| Coverage | Narrow | Encryption, firewall, 11 localhost TCP ports, and two update-related heuristics. |
| Remote operation | Not implemented | The tool executes locally; it has no SSH/WinRM transport, fleet orchestration, or result collection service. |
| Release assurance | Basic | Native builds exist, but the workflow contains no tests, explicit architecture matrix, signing, or provenance steps. |
| Open-source readiness | Partly established | Full MIT text exists in README; no standalone LICENSE, contributor guide, tests, or versioned rule format. |

The dependency claim should be expressed as “no separately installed Python required.” PyInstaller bundles Python, and collection still depends on OS utilities, their availability, privileges, and behavior.

## Verified defects and gaps

The following probes imported the module and supplied mocked OS responses on Linux. They did not change host security settings or run the audit against a client endpoint. The defects concern how the code interprets those inputs. Native Windows/macOS integration testing is still required.

### 1. Windows firewall: one enabled profile makes the whole check pass

Source: `src/audit_tool.py:175–184`.

The code tests whether `True` appears anywhere in the output. With Domain enabled and Private/Public disabled, it returns PASS and says “Active Profile Enabled.” It does not establish the current connection's profile. Microsoft documents that the default query reads the persistent policy store; effective policy should be inspected explicitly, including `ActiveStore` where applicable.

Fix: return structured JSON from PowerShell, evaluate each profile separately, collect active network categories, and record relevant inbound defaults and policy sources. Apply the selected baseline without reducing all profiles to a substring match.

### 2. BitLocker: full encryption is mistaken for active protection

Source: `src/audit_tool.py:133–152`.

The fallback passes a drive when output contains `Percentage Encrypted: 100%`, even when `Protection Status` is off. The mock probe reproduced that false pass. Microsoft explains that suspension leaves data encrypted while making the encryption key available in the clear.

The preferred query searches for `1`, while Microsoft's documented output renders ProtectionStatus as `On` or `Off`. A probe using `On` showed that it falls through to the weaker fallback. English text parsing is also vulnerable to spacing and localization differences. Only `C:` is inspected.

Fix: collect all applicable volumes with distinct numeric or explicitly serialized values for encryption percentage, conversion state, protection status, encryption method, and protector types. Detect the actual system volume. Report temporary suspension accurately and keep operational exceptions separate from observed protection state. Do not collect recovery passwords or other secrets.

### 3. Local listening ports do not demonstrate external exposure

Source: `src/audit_tool.py:198–220`.

The tool connects only to `127.0.0.1`, on 11 TCP ports, and labels a successful connection “Exposed.” It cannot establish LAN or internet reachability. It can miss services bound to a particular interface and IPv6 listeners. A legitimate SSH or web service is not automatically a vulnerability.

Fix: enumerate all listeners and their bind addresses, protocol, owning process, and relevant firewall controls. Classify loopback-only services separately. Add an optional second-host probe for explicit evidence of network reachability; record where the probe ran and when. Keep configured exposure, observed reachability, and service vulnerability as separate findings.

### 4. Update checks establish very little about patch posture

Source: `src/audit_tool.py:229–264`.

Windows checks only two reboot indicators. “No Pending Reboots” is a valid narrow observation; it says nothing about missing updates, OS support, or installed security fixes. On macOS an existing empty update plist produces PASS and “System appears up to date.” The probe reproduced this outcome without any update-state evidence.

Fix: independently report reboot status, OS release/build, support status, installed security updates, update policy, and update-search freshness. Missing or stale data must be UNKNOWN. Avoid treating a cached preference as an authoritative assessment of all available updates.

### 5. Failure handling and privileged execution need hardening

Native subprocess calls have no timeout. Many exceptions are suppressed, losing the reason for failure. A missing `fdesetup` executable escapes the FileVault handler and can abort the audit. Windows elevation joins arguments without proper Windows quoting and ignores the launch result. Unsupported Linux execution can leave encryption and patch sections empty while printing that the run is elevated.

Fix: a common command runner with time limits, controlled executable resolution, return-code/error capture, and bounded output. Isolate collection failures by check. Detect supported OS/version before execution. Preserve arguments correctly across elevation, handle cancellation, and run unprivileged checks without requiring elevation of the whole program.

### 6. Report and documentation correctness

Report strings are inserted without HTML escaping. A probe confirmed that markup in a finding is written unchanged. Current finding strings are mostly fixed; this becomes more consequential when future collectors include service names or other endpoint-controlled text. Reports use a predictable filename in the working directory and overwrite earlier audits. Privileged output creation should use a controlled path and safe creation semantics rather than follow unexpected existing files or links.

README claims include macOS stealth-mode and encryption-progress auditing, which are absent from the implementation. The clone command also contains Markdown link syntax inside a shell code block.

Fix: escape all endpoint data, use UTF-8 and UTC timestamps, create uniquely identified audit files, provide a configurable output directory, preserve prior results, and make documentation match implemented and tested behavior.

### 7. Build maintenance

The workflow bundles Python 3.10. The Python Developer's Guide lists its end of life as 1 October 2026. Upgrade the build interpreter to a supported version after checking PyInstaller and supported OS compatibility. Pin build dependencies and action revisions, test on pull requests, and publish separate verified Intel/Apple Silicon macOS and supported Windows architecture artifacts. The current workflow does not establish that its one macOS binary supports both architectures.

## What current tools suggest

These comparisons are based on current project documentation and license files, not a performance shootout. They show where RSAT overlaps existing work and where it could offer a more focused experience.

| Tool/project | Relevant capability | Implication for RSAT |
|---|---|---|
| [osquery](https://github.com/osquery/osquery) | Cross-platform structured endpoint inventory through SQL; standalone `osqueryi`; process/listener joins and detailed BitLocker fields. | An optional collection adapter could save substantial implementation effort. Keep a lightweight native mode for users who prioritize a small download. |
| [HardeningKitty](https://github.com/scipag/HardeningKitty) | Windows baseline auditing, configurable finding lists, CSV reports, and hardening operations. | A handful of additional registry checks will not create a strong advantage. Reliable interpretation and client workflow matter more. |
| [NIST macOS Security Compliance Project](https://github.com/usnistgov/macos_security) | Versioned Apple security rules, mappings, configuration profiles, and compliance scripts. | Use maintained, appropriately licensed baseline sources and preserve version/attribution metadata. |
| [Lynis](https://github.com/CISOfy/lynis) | Deep local UNIX security auditing with installation optional. | Portability alone is established elsewhere; Windows/macOS consistency and consultant reporting are a more specific opportunity. |
| [Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html) | YAML configuration assessment, remediation advice, and inventory-based vulnerability correlation in an agent/server platform. | Learn from declarative policies and inventory models. Fleet monitoring would introduce a much larger operational scope. |
| [Velociraptor](https://docs.velociraptor.app/docs/deployment/offline_collections/) | Cross-platform endpoint collection, custom offline binaries, and encrypted collection output. | Portable evidence collection is already available in a mature tool. RSAT must add focused posture interpretation and a simpler client-facing workflow. |
| [Fleet](https://github.com/fleetdm/fleet) | Device management built around structured endpoint visibility. | Useful architecture reference, but its repository separates MIT code from subscription-licensed enterprise code. Do not assume all visible source is reusable open source. |

Recommended positioning: **an open-source portable endpoint audit tool for consultants and small IT teams, producing traceable findings, prioritized remediation, and proof of improvement.** This is a product hypothesis, not demonstrated market demand. Validate it with actual consultants before building a server platform.

## Advanced improvements worth pursuing

### A. An evidence model that separates observation from judgment

Store every observation as structured data. Evaluate rules against that data; render HTML from the results. A finding should include a stable control ID, status, severity, evidence, collection method, timestamp, rule version, applicability, uncertainty reason, and recommended action.

Use PASS, FAIL, UNKNOWN, ERROR, and NOT_APPLICABLE as outcome states. Keep severity and operational exceptions separate. Show assessed coverage alongside results so ten successful checks do not imply full security coverage.

Versioned declarative JSON/YAML rules would let contributors add policies without editing collection code. Use schema validation and a constrained evaluator; a downloaded policy should not silently become arbitrary privileged code. Signed official packs and separately identified user packs can coexist.

Value: a reviewer can understand and reproduce why a result occurred. Native OS output is evidence from that endpoint; it is not independent proof that a compromised endpoint is telling the truth.

### B. Contextual risk analysis across multiple findings

Build relationships between services, processes, installed software, interfaces, firewall rules, privileges, and controls. Correlate facts rather than flagging every open port.

For example, prioritize a confirmed reachable remote-access service with a verified vulnerable version and weak authentication controls. A loopback-only development service should get a different assessment. Show the observed supporting facts and any unverified assumptions for each scenario.

This is potentially the strongest differentiator, but begin with a few explicitly defined risk scenarios. Do not label a relationship graph as proof that an attacker can exploit a machine.

### C. Vulnerability prioritization with current, locally usable intelligence

Add software inventory and match precise products, versions, platforms, and vendor patch rules. Use OSV where its ecosystems apply, and vendor advisories/platform-specific data for OS and proprietary applications. OSV is not a complete database of every Windows or macOS application.

Enrich confirmed CVEs with [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), [FIRST EPSS](https://www.first.org/epss/), technical severity, observed exposure, and asset context. EPSS predicts exploitation of a CVE in the wild over the next 30 days; it is not the probability this particular endpoint will be compromised.

Provide offline intelligence packs with recorded source dates, integrity verification, and stale-data indicators. Explain prioritization factors rather than displaying an arbitrary security score. Software-identification ambiguity should lower confidence, not generate certain vulnerability claims.

### D. Evidence bundles and verifiable audit history

Export readable HTML plus a documented JSON schema and a manifest of collected evidence. Hash the bundle contents and optionally sign the manifest with a consultant-controlled key. Encrypt sensitive evidence for a designated recipient when needed. Keep signing and encryption separate.

Include collector/rule versions, scope, UTC timestamps, and an audit ID. A verification command should detect changes to a signed bundle. A signature proves that a signer signed those bytes; it does not prove endpoint health, truthful collection, or trustworthy local time.

Later add [OSCAL assessment-results](https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/) export. Proper export includes the associated assessment plan and model validation; merely renaming JSON fields is insufficient.

### E. Remediation plans that can be checked before and after execution

Start with precise manual instructions and generated plans. Later support selected reversible actions with preconditions, a dry run, backup of relevant original values, explicit execution, rollback where technically possible, and a follow-up audit.

Account for centrally managed policies: a local edit may be reverted by MDM or Group Policy. Changes to remote access, firewall rules, encryption, or identity require different recovery procedures. Some actions cannot be reliably rolled back; label that limitation in the plan.

Value: users can distinguish “a fix was attempted” from “the targeted condition was corrected.”

### F. Comparison across time and across a small engagement

Compare prior and current findings using stable control IDs and privacy-preserving asset identifiers. Show new issues, resolved issues, regressions, expired exceptions, and changes caused by rule updates. Store both rule versions so policy changes are not confused with endpoint drift.

A local workspace that imports audit bundles from multiple machines could provide a consultant dashboard without requiring cloud upload or a persistent endpoint agent. Remote execution through existing SSH/WinRM channels can follow once transport authentication, credential handling, and bounded execution are designed.

### G. Optional local AI for explanation

AI could draft client summaries, explain evidence, and help navigate remediation plans. Deterministic rules should decide whether controls pass or fail. Generated text should cite the actual finding IDs and evidence; validate suggested actions against supported procedures before offering execution.

A local model is an option, not a requirement. Open weights do not automatically mean unrestricted open-source licensing; evaluate the model license separately. Treat collected text as untrusted input so endpoint-controlled strings cannot instruct an assistant to change policy or execute commands.

This feature has less early value than trustworthy collection and rules. No model or provider selection is necessary for the first improved release.

## Implementation direction

Recommended first architecture:

`OS collectors → normalized observations → versioned policy evaluation → contextual findings → HTML / JSON / evidence bundle`

Use an optional adapter boundary for osquery and future transports. Keep a tightly scoped privileged collection helper separate from policy processing and report writing where feasible. Enforce per-check budgets and an overall audit deadline; retain partial results when a collector fails.

Keep Python for the first redesign. The current defects are interpretation and architecture problems, not demonstrated language-performance problems. A Go or Rust executable could later simplify some packaging or improve startup/resource behavior, but rewriting native integration creates its own validation burden. Measure deployment friction before deciding.

## Keeping the entire project open source

1. Add a standalone LICENSE containing the existing MIT grant and copyright, plus clear dependency notices and contribution instructions. GitHub currently reports no recognized repository license because the grant is only embedded in README.
2. MIT remains a valid open-source choice. It permits proprietary forks. GPLv3 offers source-sharing obligations for covered distributed derivatives; AGPLv3 adds obligations for covered modified software offered over a network. If preserving openness of derivatives matters, discuss those tradeoffs before choosing a license for future work. A later license choice cannot withdraw permissions already granted for released MIT code.
3. Keep the collector, rules, reports, advanced analysis, and any dashboard available under the chosen open-source license. Revenue can come from hosting, support, training, and audits without reserving essential features for proprietary code.
4. Check the license of every reused component and rule pack. osquery is offered under Apache-2.0 OR GPL-2.0-only; HardeningKitty uses MIT; Lynis uses GPLv3; Velociraptor uses AGPLv3; mSCP identifies CC BY 4.0 for its content. These are different reuse obligations, not interchangeable “free code.”
5. Do not copy CIS benchmark text into an unrestricted MIT pack simply because it can be downloaded. The [CIS non-member terms](https://www.cisecurity.org/terms-of-use-for-non-member-cis-products) specify noncommercial/content restrictions. Use original rules, suitable publicly reusable guidance, or content for which redistribution rights are established. A control mapping is not a compliance certification.
6. Pin and review build dependencies, generate an SBOM, and publish checksums and provenance. Sigstore can support artifact verification; Windows Authenticode and macOS signing/notarization address separate OS trust and distribution concerns. Open-source licensing does not eliminate certificate or distribution costs.

## Staged roadmap and success criteria

These are sequencing recommendations, not delivery-date estimates.

| Stage | Deliverable | Evidence required before advancing |
|---|---|---|
| Corrected maintenance release | Fix existing false passes, structured native output, timeouts, accurate documentation, safe reporting, supported build runtime, LICENSE. | Regression fixtures for reproduced defects; actual Windows/macOS checks for enabled, disabled, suspended, missing-data, non-English, and permission-denied cases. |
| Dependable audit core | Modular collectors, normalized schema, versioned rules, CLI options, HTML/JSON, explicit coverage. | No absent evidence silently passes; documented supported OS/architecture matrix; partial results survive failures. |
| Useful baseline depth | Start with roughly 30–50 high-value controls selected for supported platforms, including endpoint protection, boot protections, remote access, identities, update posture, and backup evidence. | Known-good and intentionally misconfigured lab cases agree with independent native inspection; unsupported controls remain explicit. |
| Consultant workflow | Risk scenarios, vulnerability enrichment, signed bundles, audit comparison, multiple-machine imports, remediation plans. | Findings can be traced to evidence; changed bundles fail verification; repeat audits distinguish fixes from rule changes. |
| Extended platform | Optional transport, self-hosted dashboard, broader integrations, selective automation, AI explanations. | Pilot users demonstrate a need; collection and credentials remain bounded and observable; open-source reuse obligations are documented. |

Benchmark accuracy per control, especially false-pass rates. Measure audit coverage, collector error rate, startup/runtime, peak memory, and output size on explicitly named OS/architecture combinations. A proposed initial target is a core audit within 60 seconds on supported test machines; update-search and deep inventory operations should have separate budgets. This target has not been measured in the existing tool.

Ask pilot consultants to complete a real workflow: launch on a client endpoint, understand unknown results, identify the first action, produce a client report, and verify a fix. Compare that task with their current process. More checks or a more attractive dashboard alone do not establish product value.

My recommended first commitment is the corrected release and evidence/rule architecture, followed by contextual risk and audit comparison. Those changes preserve the portable idea while addressing the main reason the present tool cannot yet support professional assurance.

## Selected primary sources

- [RSAT repository](https://github.com/Kajahkura/RSAT_Project) and [v1.0.0 release](https://github.com/Kajahkura/RSAT_Project/releases/tag/v1.0.0).
- [Get-BitLockerVolume](https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume?view=windowsserver2025-ps) and [Suspend-BitLocker](https://learn.microsoft.com/en-us/powershell/module/bitlocker/suspend-bitlocker?view=windowsserver2025-ps).
- [Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile?view=windowsserver2025-ps).
- [Apple FileVault security documentation](https://support.apple.com/guide/security/volume-encryption-with-filevault-sec4c6dc1b6e/web).
- [Python supported versions](https://devguide.python.org/versions/).
- [osquery standalone shell](https://osquery.readthedocs.io/en/stable/introduction/using-osqueryi/) and [license](https://github.com/osquery/osquery/blob/master/LICENSE).
- [Wazuh vulnerability detection](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html).
- [OSV-Scanner, including offline mode](https://github.com/google/osv-scanner).
- [Fleet root license](https://github.com/fleetdm/fleet/blob/main/LICENSE) and [enterprise license](https://github.com/fleetdm/fleet/blob/main/ee/LICENSE).
- [Sigstore Cosign](https://github.com/sigstore/cosign) and [SLSA assurance levels](https://slsa.dev/spec/v1.1/levels).
- [Microsoft RSAT naming](https://learn.microsoft.com/en-us/windows-server/administration/install-remote-server-administration-tools): the acronym already commonly denotes Remote Server Administration Tools. A more distinctive project name may improve discoverability; this is secondary to audit correctness.

Scope limits: no live Windows/macOS endpoint was available for native verification; release binaries were not executed or reverse-engineered; no timing, antivirus acceptance, exploitability, or market-demand claims were measured. Repository source and settings were not changed during this review.
