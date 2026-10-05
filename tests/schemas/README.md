# OSCAL schema provenance

Unmodified NIST OSCAL 1.1.3 release schemas:

- https://github.com/usnistgov/OSCAL/releases/download/v1.1.3/oscal_assessment-plan_schema.json
- https://github.com/usnistgov/OSCAL/releases/download/v1.1.3/oscal_assessment-results_schema.json

SHA-256:

```text
0850be91252390dde740a98fd2f0fc504cd0ba66fe8940c2b6242b7aa2fb36eb  assessment-plan.json
d9e34757f0c12aff61f52b821f0b8f83ba0ba75b3a149a202b08ba82f82bc4c3  assessment-results.json
```

These retain NIST's original notices and are used solely for export validation. The Unicode `pattern` keyword is evaluated with `regex` because Python's built-in regular expressions do not support the schema's Unicode categories. Other schema validation is unchanged.

CycloneDX files are the official 1.6 JSON schema and its JSF/SPDX references from https://github.com/CycloneDX/specification/tree/1.6/schema (Apache-2.0). CSAF 2.0 is from https://github.com/oasis-tcs/csaf/tree/master/csaf_2.0/json_schema (OASIS terms). These upstream schemas retain their original terms and are test data, separate from RSAT's MIT code. Retrieved 5 October 2026. Export tests validate SBOM and ML-BOM documents against the official CycloneDX schema. CSAF tests validate imported publisher documents before extraction. OCSF mappings are checked against versioned upstream class/object definitions, not represented as full schema certification.
