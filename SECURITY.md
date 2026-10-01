# Security policy

RSAT 2.x is the maintained line. The legacy 1.0 checks can give false reassurance and should be replaced.

Report vulnerabilities privately using [GitHub private vulnerability reporting](https://github.com/Kajahkura/RSAT_Project/security/advisories/new) when available. If the repository has not enabled this feature, contact the maintainer through the contact details on their GitHub profile. Do not attach client evidence or secrets to public issues.

Audit mode is read-only and has no telemetry, persistent service, automatic elevation, or implicit remediation. It uses bounded native commands and labels unavailable evidence explicitly. Run only on systems you are authorized to assess.

Report data can contain installed software, users, processes, and network configuration. Files are created exclusively with restrictive permissions where supported. Encrypt the evidence bundle for transfer; plaintext local reports and ZIP bundles remain present unless you remove them. Windows ACLs and filesystem access controls should be reviewed separately.

Pin a signing public key independently before trusting a bundle. Embedded public keys do not establish signer trust. Signatures prove signed bytes, not endpoint health, collection truthfulness, or compliance. A compromised endpoint can misreport local evidence.

Remediation is a separate explicit command with a small allowlist. Firewall changes may interrupt access. Execution requires privileged access and acknowledgment of a recovery route; local policy can be overridden by MDM or Group Policy. Backup files are sensitive local inputs, not externally attested records.

Optional OSV requests disclose package names, versions, and ecosystems. Local AI accepts only loopback IP endpoints, blocks redirects, and never executes output. Model prose remains subject to human review.
