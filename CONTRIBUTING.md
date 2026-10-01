# Contributing to RSAT

RSAT welcomes collectors, original rule packs, interoperability improvements, documentation, and reproducible defect reports.

Use Python 3.11 or newer. Production binaries are built with Python 3.13.

```bash
git clone https://github.com/Kajahkura/RSAT_Project.git
cd RSAT_Project
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -r requirements-dev.txt -e .
python -m ruff check src tests scripts
python -m pytest --cov=rsat --cov-fail-under=80
python scripts/native_smoke.py
```

Keep collection read-only. Do not collect credentials, recovery passwords, browser histories, or private documents. Missing, malformed, stale, and inaccessible evidence must never silently pass. Add meaningful regression cases for any interpretation change and specify the OS/build and privileges used for native validation.

Rules are constrained JSON, not executable plugins. Give each control a stable ID, explicit platform applicability, severity, remediation, and traceable sources. Use original content or establish redistribution rights; a publicly downloadable benchmark is not necessarily unrestricted content.

Before opening a pull request, describe the concrete failure or workflow, the resulting behavior, validation performed, and remaining native limitations. New native commands require timeout and failure tests. Changes to automated remediation require precondition, dry-run, backup, injection, verification, and rollback tests.

Contributions are accepted under the repository MIT license. Do not submit third-party material under incompatible terms. Report security weaknesses through the process in [SECURITY.md](SECURITY.md).
