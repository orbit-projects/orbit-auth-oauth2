# Orbit Auth OAuth 2.0 and OpenID Connect: development

This package declares support for `>=3.11,<3.15` in `pyproject.toml`. That declaration is distinct from evidence that hosted CI ran.

Use the checks for each language manifest present in this repository:

### Python package

```bash
python -m pip install -e '.[dev]' build
pip-audit --skip-editable --progress-spinner off
pytest
ruff check src tests
ruff format --check src tests
mypy
```

Optional SDKs and live-service tests are described by the package README. Do not run an opt-in live test against a shared or production service unless its own documentation explicitly supports that use.

The current local quality matrix passes on CPython 3.11, 3.12, 3.13, and 3.14: all 31 tests, Ruff
lint and format checks, strict mypy, dependency audits, and wheel/sdist builds pass on each
interpreter. Editable Core and Auth distributions are skipped by pip-audit and are audited in their
own repositories. It exercises deterministic local protocol and callback cases; it does not verify a
live authorization server, client registration, or provider-specific consent and logout behavior.

## Contribution expectations

Add focused regression coverage for behavior changes. Update the README and relevant guide when a contract, configuration option, security property, lifecycle rule, or operational assumption changes. Report the exact versions and services exercised; local checks do not imply hosted CI or release validation.
