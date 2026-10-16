// Public RSAT control labels used in redacted reports; imported prose is excluded.
export const publicControls:Record<string,{title:string;remediation:string}> = {
  "RSAT-ENC-001": {
    "title": "BitLocker protection active on every fixed volume",
    "remediation": "Resume BitLocker protection after confirming firmware/update work is complete. Inspect every fixed volume."
  },
  "RSAT-ENC-002": {
    "title": "BitLocker fixed volumes fully encrypted",
    "remediation": "Enable BitLocker on applicable fixed volumes and allow encryption to complete."
  },
  "RSAT-ENC-003": {
    "title": "BitLocker key protectors configured",
    "remediation": "Configure approved key protectors and verify recovery arrangements without exporting recovery secrets."
  },
  "RSAT-ENC-004": {
    "title": "FileVault enabled",
    "remediation": "Enable FileVault in System Settings and verify recovery arrangements."
  },
  "RSAT-FW-001": {
    "title": "Every Windows firewall profile enabled",
    "remediation": "Enable Domain, Private and Public firewall profiles through the owning local or central policy."
  },
  "RSAT-FW-002": {
    "title": "Windows default inbound traffic blocked",
    "remediation": "Set default inbound traffic to Block for every profile; review allowed services."
  },
  "RSAT-FW-003": {
    "title": "Windows blocked traffic logging enabled",
    "remediation": "Enable blocked traffic logging with appropriate retention and access controls."
  },
  "RSAT-FW-004": {
    "title": "macOS application firewall enabled",
    "remediation": "Enable the macOS application firewall."
  },
  "RSAT-FW-005": {
    "title": "macOS firewall stealth mode enabled",
    "remediation": "Enable stealth mode if compatible with the device role."
  },
  "RSAT-FW-006": {
    "title": "Linux nftables input policy drops by default",
    "remediation": "Configure an appropriate nftables input policy, preserving authorized access. Other backends require separate evidence."
  },
  "RSAT-AV-001": {
    "title": "Antivirus enabled",
    "remediation": "Verify the approved endpoint protection product and its effective policy. If another product is installed, document supporting evidence and an exception."
  },
  "RSAT-AV-002": {
    "title": "Real-time protection enabled",
    "remediation": "Verify the approved endpoint protection product and its effective policy. If another product is installed, document supporting evidence and an exception."
  },
  "RSAT-AV-003": {
    "title": "Behavior monitoring enabled",
    "remediation": "Verify the approved endpoint protection product and its effective policy. If another product is installed, document supporting evidence and an exception."
  },
  "RSAT-AV-004": {
    "title": "Tamper protection enabled",
    "remediation": "Verify the approved endpoint protection product and its effective policy. If another product is installed, document supporting evidence and an exception."
  },
  "RSAT-AV-005": {
    "title": "Defender signatures no more than two days old",
    "remediation": "Refresh antivirus signatures and check update connectivity."
  },
  "RSAT-BOOT-001": {
    "title": "Secure Boot enabled",
    "remediation": "Check platform support and enable Secure Boot using vendor procedures. Preserve boot recovery access."
  },
  "RSAT-BOOT-002": {
    "title": "TPM present",
    "remediation": "Verify that a supported TPM is available and enabled. Do not clear the TPM without recovery planning."
  },
  "RSAT-BOOT-003": {
    "title": "TPM ready",
    "remediation": "Investigate TPM readiness using vendor guidance; preserve encryption recovery access."
  },
  "RSAT-BOOT-004": {
    "title": "Virtualization-based security running",
    "remediation": "Evaluate device compatibility and enable virtualization-based security under the approved baseline."
  },
  "RSAT-BOOT-005": {
    "title": "macOS System Integrity Protection enabled",
    "remediation": "Re-enable System Integrity Protection using Apple recovery procedures after checking device requirements."
  },
  "RSAT-BOOT-006": {
    "title": "macOS authenticated root enabled",
    "remediation": "Restore authenticated-root protection using supported Apple recovery procedures."
  },
  "RSAT-SOFT-001": {
    "title": "macOS Gatekeeper enabled",
    "remediation": "Enable Gatekeeper assessment and investigate why it was disabled."
  },
  "RSAT-REMOTE-001": {
    "title": "RDP requires Network Level Authentication",
    "remediation": "Require Network Level Authentication where RDP is permitted. Restrict network access separately."
  },
  "RSAT-REMOTE-002": {
    "title": "SMBv1 disabled",
    "remediation": "Disable SMBv1 after checking legacy dependencies."
  },
  "RSAT-REMOTE-003": {
    "title": "SMB server signing required",
    "remediation": "Require SMB signing after validating compatibility and central policy."
  },
  "RSAT-REMOTE-004": {
    "title": "macOS remote login disabled",
    "remediation": "Disable remote login when unnecessary; otherwise document the approved role and SSH controls."
  },
  "RSAT-REMOTE-005": {
    "title": "Linux direct root SSH login disabled",
    "remediation": "Set PermitRootLogin no and validate sshd configuration and recovery access before reloading."
  },
  "RSAT-REMOTE-006": {
    "title": "Linux SSH password authentication disabled",
    "remediation": "Use managed SSH keys or an approved alternative; confirm access before disabling password authentication."
  },
  "RSAT-ID-001": {
    "title": "Windows guest account disabled",
    "remediation": "Disable the local guest account."
  },
  "RSAT-ID-002": {
    "title": "User Account Control enabled",
    "remediation": "Enable UAC in the approved local or central policy."
  },
  "RSAT-ID-003": {
    "title": "UAC prompts administrators",
    "remediation": "Configure administrator consent prompts according to the approved baseline."
  },
  "RSAT-ID-004": {
    "title": "macOS guest account disabled",
    "remediation": "Disable guest login unless specifically required and approved."
  },
  "RSAT-ID-005": {
    "title": "Only root has Linux UID zero",
    "remediation": "Investigate unexpected UID-zero accounts before changing identity configuration."
  },
  "RSAT-UPDATE-001": {
    "title": "No pending reboot indicator",
    "remediation": "Schedule a reboot if required. This control does not establish patch currency."
  },
  "RSAT-UPDATE-002": {
    "title": "Live update search reports no available updates",
    "remediation": "Review and install applicable vendor updates. The result reflects the configured update source at the recorded search time."
  },
  "RSAT-UPDATE-003": {
    "title": "Windows automatic update policy does not disable updates",
    "remediation": "Ensure effective update management is enabled. An absent policy requires separate evidence."
  },
  "RSAT-UPDATE-004": {
    "title": "macOS automatic update schedule enabled",
    "remediation": "Enable the automatic software update schedule or document equivalent managed update controls."
  },
  "RSAT-UPDATE-005": {
    "title": "Linux automatic update timer present",
    "remediation": "Configure distribution-supported automatic update scheduling or document an equivalent managed process."
  },
  "RSAT-LOG-001": {
    "title": "Linux audit service active",
    "remediation": "Install and configure auditd when required by the device baseline."
  },
  "RSAT-BACKUP-001": {
    "title": "Recent macOS backup evidence",
    "remediation": "Verify a recent backup and perform a separate restoration test; a backup timestamp alone does not prove recovery."
  },
  "RSAT-BACKUP-002": {
    "title": "Backup restoration independently tested",
    "remediation": "Attach independent evidence of a successful restoration test; endpoint configuration alone is insufficient."
  },
  "RSAT-MGMT-001": {
    "title": "macOS enrolled in device management",
    "remediation": "For managed business devices, enroll through the authorized organization. Personal devices may need a documented exception."
  }
};
