# Contributing to ARC Protocol

---

## How to Run Tests

Install the package in editable mode with development dependencies:

```bash
pip install -e ".[dev]"
```

Run the full unit test suite:

```bash
pytest tests/ -v
```

Run the red team suite separately:

```bash
make red-team
```

Run both unit tests and red team together:

```bash
make test-all
```

The current test counts are:

| Suite | Count |
|-------|-------|
| Unit tests | 51 |
| Red team tests | 43 |
| v1.1 regression | 15 |
| Total | 58 |

All 58 tests must pass before any pull request is merged.

---

## Code Style

ARC uses `ruff` for linting and formatting.

Check for lint errors:

```bash
ruff check src/ tests/ demo/
```

Apply formatting:

```bash
ruff format src/ tests/ demo/
```

Type checking uses `mypy`:

```bash
mypy src/arc/
```

All three commands must exit 0 before submitting a pull request.

---

## Submitting Changes

1. Fork the repository.
2. Create a branch: `git checkout -b feature/your-feature-name`
3. Write tests for any new functionality. New functions in `src/arc/` without corresponding tests will not be merged.
4. Ensure all 58 tests pass before submitting.
5. Ensure `ruff check`, `ruff format`, and `mypy` exit 0.
6. Open a pull request against `main`.

Pull request descriptions must include:

- What the change does.
- Why it is needed.
- Which tests cover it.
- Whether it is a breaking change (see protocol change rules below).

---

## Reporting Security Vulnerabilities

Do not open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the disclosure policy and contact information.

---

## Protocol Changes

The signing payload is defined in `build_signing_payload()` in `src/arc/signing.py`. Any change to this function is a **breaking change** to the protocol and requires the following:

1. Bump the minor version in `pyproject.toml` and `src/arc/__init__.py`.
2. Document the change in `CHANGELOG.md` under a new version heading, including the exact fields added, removed, or reordered.
3. Update the signing specification in `docs/signing_specification.md` with the new payload structure and an example.
4. Add tests in `tests/test_signing.py` and `tests/test_red_team.py` covering the new signing surface. The red team tests must attempt to exploit any field that is newly added to or removed from the envelope.
5. Update the test count badge in `README.md` to reflect the new total.

Changes to `schemas/` that add required fields to existing schemas are also breaking changes and follow the same process.

---

## Adding New Resource Types

New resource types (entries in the `resource_type` enum in `schemas/before-state.schema.json`) require:

1. A new entry in the `enum` array in `schemas/before-state.schema.json`.
2. A corresponding `capture_*` function in `src/arc/snapshot.py`.
3. A corresponding `rollback_*` function in `src/arc/snapshot.py` if the resource type supports rollback (`is_reversible=True`).
4. Tests in `tests/test_receipt.py` covering capture and rollback for the new type.
5. A note in `CHANGELOG.md` under the next version heading.

Resource types where rollback is structurally impossible (for example, `email:message` after delivery) must set `is_reversible=False`. Do not implement a stub rollback function that silently does nothing.
