# Usage guide

## Local assessment

```bash
rsat audit --output audit-output
rsat audit --inventory --update-search --deadline 120 --command-timeout 20
rsat audit --stdout > audit.json
rsat report audit.json --output report.html
```

Run without elevation to collect available evidence. Re-run as administrator/root for privileged native queries when appropriate. RSAT does not automatically relaunch itself or change security settings. A query denied by the OS remains ERROR; a missing utility, missing value, unsupported parser, or exhausted budget is explicit.

Statuses: PASS means the collected evidence satisfied the chosen rule; FAIL means it did not; UNKNOWN means a conclusion could not be established; ERROR means collection failed; NOT_APPLICABLE means the rule does not target the platform. Exceptions record reason and expiry without changing the outcome.

For pseudonymous comparison, create a private engagement salt of at least 16 characters and use the same salt file for the same engagement:

```bash
rsat audit --asset-salt-file engagement-salt.txt
rsat diff before/audit.json after/audit.json --output changes.json
rsat workspace machine-a/audit.json machine-b/audit.json --output engagement.html
rsat serve engagement.html --port 8765 --duration 300
```

Without a salt, asset IDs are hostname hashes and should not be described as strong anonymization. Hostname changes also change asset identity. Use `--include-hostname` only when a report needs it.

## Policies and exceptions

```bash
rsat audit --policy my-original-policy.json --exceptions exceptions.json
rsat bundle my-original-policy.json --policy --output policy.zip --signing-key keys/signing.key.pem
rsat audit --policy my-original-policy.json --policy-bundle policy.zip --policy-key keys/signing.pub.pem
```

JSON rules cannot contain executable code. Supported operators are `eq`, `ne`, `ge`, `le`, `in`, `not_in`, `empty`, and `nonempty`; list evaluation supports `all` or `any`. Empty evidence cannot pass an all/any rule. Field types are validated during evaluation.

An exception file is a list of records containing `control_id`, `reason`, and an ISO 8601 `expires_at` with timezone. Expired exceptions remain visible.

## Inventory and vulnerability intelligence

```bash
rsat audit --inventory --intel-pack advisories.json
rsat intel-refresh CVE-2026-10000 --output enrichment.json
rsat audit --intel-pack advisories.json --enrichment enrichment.json
rsat bundle advisories.json --intelligence --output intelligence.zip --signing-key keys/signing.key.pem
rsat audit --intel-pack advisories.json --intel-bundle intelligence.zip --intel-key keys/signing.pub.pem
rsat audit --inventory --online-osv
```

Offline pack examples are in `examples/`. The matching contract requires exact package name, ecosystem, and an explicit affected version. It deliberately does not guess version ranges. Verify vendor/platform applicability. Public KEV/EPSS enrichment is downloaded separately and can be attached to validated advisory records; a KEV match establishes exploitation of a CVE in the wild, not compromise of a particular machine.

OSV is optional and sends package metadata to its public API. Unsupported ecosystems, missing versions, and items not processed within the budget are recorded as skipped. It does not cover every proprietary Windows/macOS application. Offline packs record source time, hash, and staleness; a recorded hash alone is not publisher authentication. Pin the publisher public key with a signed intelligence bundle when distributor authentication is required.

## Evidence signing and recipient encryption

```bash
rsat keygen keys
rsat audit --bundle --signing-key keys/signing.key.pem --recipient-key keys/recipient.pub.pem
rsat verify evidence.rsat.zip --trusted-key keys/signing.pub.pem
rsat decrypt evidence.rsat.enc --key keys/recipient.key.pem --output decrypted.zip
rsat verify decrypted.zip --trusted-key keys/signing.pub.pem
```

Keep private keys outside the repository and protect them with filesystem access controls. The generated private key files are unencrypted PEM files; use a protected workstation or managed key handling. Share public keys separately. `verify` without `--trusted-key` checks integrity and a self-supplied signature, and explicitly reports that signer trust has not been established.

## Remediation

```bash
rsat plan audit.json --output plan.json
rsat apply plan.json windows-firewall-enable --backup firewall-before.json
rsat apply plan.json windows-firewall-enable --backup firewall-before.json --execute --recovery-access
rsat rollback firewall-before.json
rsat rollback firewall-before.json --execute --recovery-access
```

Default behavior is dry-run. Execution plans and rollback backups are bound to the collected endpoint hostname fingerprint; generate a fresh audit/plan on the target and preserve it locally. Automated actions are limited to Windows firewall enablement, macOS firewall enablement, and macOS stealth mode. Other controls receive manual instructions. Review the plan on the target, preserve console/recovery access, and check centrally managed policy ownership. A successful command is followed by native verification. Re-audit for the full control result. Some platform states cannot be safely reconstructed automatically and require manual recovery.

## Existing SSH and reachability

```bash
rsat remote auditor@host.example --binary /opt/rsat/rsat --output remote-audit.json
rsat winrm host.example --binary "C:\Program Files\RSAT\rsat.exe" --output remote-windows.json
rsat probe host.example --ports 22 3389 --output reachability.json
rsat audit --reachability reachability.json
```

Remote operation requires existing key-based SSH access, a known host key, and RSAT installed or copied and verified on the target by the operator. No credentials are stored. Probe results describe reachability from that particular probe host at that time. Imported evidence is not automatically trusted or cryptographically associated with a target endpoint.

## OSCAL and local AI

```bash
rsat oscal audit.json --output oscal-export
rsat summary audit.json --model your-local-model --output draft-summary.json
```

OSCAL produces paired assessment-plan/results files, with a required organization-supplied SSP link. The schemas are checked in the test pipeline. UNKNOWN/ERROR outcomes are marked explicitly in observations and target remarks; do not interpret them as measured compliance failure.

The AI adapter uses a local Ollama-compatible endpoint and requires citations to actual finding IDs. Generated prose is unverified and never changes outcomes or executes commands. Review it against the deterministic report. Model licensing and hardware requirements are separate from RSAT's MIT license.

## Return codes

`0`: workflow completed, including audits with findings. `1`: invalid input or workflow error. `2`: audit has failed controls when `--fail-on-findings` is specified. `130`: interrupted. A completed audit may still contain UNKNOWN/ERROR controls; inspect coverage.
