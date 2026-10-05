# RSAT 2.1 evidence platform

RSAT combines a portable Python collector with an optional React/TypeScript browser workspace. Both remain MIT licensed and usable without cloud accounts.

## Collection and AI security

```sh
rsat audit --progress --inventory --ai-tools --output audit-output
rsat audit --ai-tools --mcp-config selected-mcp.json --output audit-output
```

Progress goes to stderr; `--stdout` remains JSON. Per-query timing starts after the Python runtime is ready. Frozen executable extraction happens before Python, so an outer process watchdog is still necessary when diagnosing native startup. WSL and containers carry explicit guest scope; a WSL firewall result does not measure the Windows host firewall.

Dpkg inventory preserves distro release, source/binary identities, architecture and epochs. OSV queries use normalized distro/source identity and account for every skipped package. Package matching still depends on vendor data coverage and exact release semantics.

The optional five AI rules assess identified model listeners and explicitly selected MCP declarations. Config arguments, credential values, raw private names and URL queries are excluded. Listener inference does not establish product identity, authentication or external reachability. Permissions and hashes are declarations; passing a declaration rule does not verify runtime enforcement or plugin integrity.

## Evidence assistance, graph and rechecks

```sh
rsat ask audit.json 'why is firewall unknown?'
rsat adaptive audit.json
rsat recheck linux-firewall --output fresh-observation.json
rsat graph audit.json --output graph.json
rsat simulate audit.json RSAT-FW-006
rsat summary audit.json --model YOUR_LOCAL_MODEL --output summary.json
rsat mcp audit.json
```

The offline assistant retrieves exact stored findings. The optional loopback model selects typed claims bound to an audit hash; contradictory outcomes, changed audits and arbitrary prose are rejected. Displayed text comes from stored evidence. This is constrained evidence selection, not general model reasoning or verification of all factual prose inside imported evidence.

Adaptive planning suggests a bounded fixed registry of read-only measurements; it never executes a proposal. `recheck` requires an explicit CLI invocation. Graph edges carry scope, time, source IDs and confidence. Supported risk relationships and conditional co-occurrences are distinguished from verified operational attack paths. Simulation assumes selected controls corrected and never changes settings.

MCP uses newline JSON-RPC over stdio, exposing only one explicitly selected audit and four read-only tools. OS process permissions govern access. There is no HTTP MCP server, public OAuth flow, model-driven shell or remediation tool. Tool output is untrusted data. A local typed HTTP companion is available with an exact Origin/Host allowlist, bearer token, bounded bodies and loopback binding:

```sh
rsat companion audit.json --token-file strong-session-token.txt --origin http://127.0.0.1:5173
```

The hosted workspace currently uses file import. Browser private-network compatibility and automated local pairing are separate prerequisites for connecting it to the companion.

## Signed history and self-hosted enrollment

```sh
rsat device-init device-keys
rsat snapshot audit.json --keys device-keys --store history.db --output snapshot.json
rsat history history.db DEVICE_ID --keep-last 10
rsat watch --keys device-keys --store history.db --output snapshots --count 3 --interval 60
```

Device identity is the SHA-256 of its Ed25519 public PEM key. Snapshots sign the complete audit, sequence and previous snapshot hash. Local history rejects replay, gaps and altered signatures. Retention preserves the current chain anchor. Watch is an explicit bounded foreground process; nothing installs itself as a background service. Key files have private permissions where POSIX permissions apply; Windows users should set directory ACLs. OS vault/TPM key custody and automatic rotation are not implemented.

The optional organization store provides expiring hashed bearer tokens, tenant-scoped device challenges, proof of possession, pinned upload keys, monotonic history and device revocation. Administrative commands require filesystem ownership of the store:

```sh
rsat org-token org.db TEAM --scopes enroll upload read revoke --output team-token.json
rsat org-operation org.db challenge key-request.json --token-file team-token.json --output challenge.json
rsat enrollment-proof challenge.json --key device-keys/signing.key.pem --output proof.json
rsat org-operation org.db enroll proof.json --token-file team-token.json
```

`key-request.json` contains `public_key`. Upload input contains `device_id` and `snapshot`. Read/revoke input contains `device_id`. Use distinct narrowly scoped tokens for operational clients. Signed plaintext evidence is readable by the self-hosted store owner. This is not end-to-end encrypted cloud synchronization, a production identity service or a managed fleet installer. Deploy behind your own authenticated TLS gateway and encrypted storage if exposing an organization service.

## Interoperability and trust

```sh
rsat sbom audit.json --output inventory.cdx.json
rsat mlbom model-manifest.json --output models.cdx.json
rsat ocsf audit.json --output findings.ocsf.json
rsat external external-evidence.json --output imported.json
rsat csaf signed-publisher.json --publisher-key publisher.pub.pem
rsat vex audit.json signed-vex.json --publisher-key publisher.pub.pem --product EXACT_PRODUCT_ID
rsat connector https://your-source/context --kind identity --subject SUBJECT --token-file credential.txt --output identity.json
```

SBOMs describe collected packages rather than full binary composition. ML-BOMs accept explicit model/dataset name, SHA-256, source and license metadata; hashes and supplied provenance are not independently measured. Generic HTTPS connectors enforce transport, response limits and subject IDs, but need a real provider contract and independently verified identity mapping. No generic endpoint audit establishes MFA, conditional access or cloud permissions.

Publisher envelopes contain `document` plus a base64 Ed25519 `signature` over RSAT canonical JSON. The key must be independently pinned. OpenVEX and CSAF retain explicit product IDs and freshness. VEX decisions annotate original findings without silently deleting them. Standard publisher discovery, certificate-based signature formats and vendor-specific product mapping remain separate adapters.

Imported attestation is explicitly unverified. Hardware-backed RATS/TPM trust requires an independent verifier, fresh challenges, endorsement policy and known-good measurements. A device signature does not satisfy those requirements.

## Updates and reviewed policy drafts

```sh
pip install 'rsat-audit[updates]'
rsat update-fetch TARGET --root pinned-root.json --metadata-url https://publisher/metadata/ --target-url https://publisher/targets/ --directory update-cache
rsat policy-draft reviewed-draft.json
```

The maintained python-tuf client verifies repository metadata and downloads into persistent rollback state. It never installs or executes the download. Initial root distribution and threshold-signed repository operation are publisher responsibilities. Existing GitHub downloads are not represented as a TUF repository.

Draft input requires `policy`, `sources`, `fixtures` and `review`. Every rule needs PASS, FAIL and UNKNOWN fixtures, bounded declarative operators and an explicit reviewer/hash declaration before signed publication. Passing fixtures does not establish source accuracy; independently reviewed golden-device checks remain necessary.
