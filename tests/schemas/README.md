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
