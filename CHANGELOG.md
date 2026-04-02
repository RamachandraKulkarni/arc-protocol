# Changelog

All notable changes to ARC Protocol are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-04-02

### Breaking Changes

- Expanded the signing payload from five fields to seven fields. Added `outcome` and `is_reversible`. The payload signed by `build_signing_payload()` in `src/arc/signing.py` now contains: `receipt_id`, `intent_id`, `outcome_hash`, `before_state_hash`, `signed_at`, `outcome`, `is_reversible`. Receipts signed under v1.0 fail v1.1 verification. There is no migration path; receipts must be re-issued under v1.1.

### Security Fixes

Six exploitable holes were identified by an independent red team test suite (43 tests). All six are fixed in this release.

**Hole 1: outcome string outside signed envelope**

The `phase_2.execution.outcome` field ("success", "failure", "partial") was not included in the provider's signing payload. An attacker with access to a receipt could change "failure" to "success" without invalidating the provider signature. Fix: `outcome` is now included in `build_signing_payload()`.

**Hole 2: is_reversible outside signed envelope**

The `phase_2.inverse.is_reversible` boolean was not included in the provider's signing payload. An attacker could change `true` to `false` to suppress rollback availability without breaking the signature. Fix: `is_reversible` is now included in `build_signing_payload()`.

**Hole 3: content_hash not verified in Merkle leaf recomputation**

`verify_consistency()` in `ARCInMemoryLog` checked that `previous_root` and `merkle_root` chained correctly between entries, but did not recompute the Merkle leaf from the stored `content_hash`. An attacker could modify `content_hash` in a log entry without breaking the root chain. Fix: `verify_consistency()` now rebuilds the Merkle tree from all `content_hash` values and compares the computed root against the stored `merkle_root` at each entry.

**Hole 4: duplicate receipt_id accepted (replay attack)**

The log server accepted multiple `commit_intent()` calls with the same `receipt_id`. An attacker could replay a known-valid Phase 1 commitment to inflate the log or overwrite a Phase 1 entry. Fix: `commit_intent()` and `commit_receipt()` now reject any `receipt_id` that already exists in the log. The error is `ARCLogError` with status 409.

**Hole 5: backdated intent not detected**

`verify_receipt()` did not check that `phase_1.intent.declared_at` was before `phase_2.execution.started_at`. An attacker could construct a receipt where the intent was declared after execution began, defeating the causal ordering guarantee. Fix: `verify_receipt()` now checks `declared_at < started_at` and adds `"timing_valid"` to the `checks` dict. Failure adds an entry to `errors`.

**Hole 6: Phase 1 accepted after Phase 2**

The log server accepted a `commit_intent()` call for a `receipt_id` that already had a committed Phase 2 receipt. This allowed an attacker to insert a Phase 1 entry retroactively, making it appear that intent was declared before execution when it was not. Fix: `commit_intent()` now rejects any `receipt_id` that already has a Phase 2 receipt entry in the log.

### Added

- Duplicate receipt_id guard in `commit_intent()`: returns HTTP 409 if `receipt_id` already present.
- Duplicate receipt_id guard in `commit_receipt()`: returns HTTP 409 if `receipt_id` already present.
- Phase 1 ordering enforcement in `commit_intent()`: returns HTTP 409 if Phase 2 already exists for this `receipt_id`.
- Content_hash leaf integrity check in `verify_consistency()`: rebuilds tree from `content_hash` values and compares against stored roots.
- Structural contradiction check in `verify_receipt()`: `is_reversible=False` with `inverse_signature` present is flagged as invalid with a specific error message.
- `timing_valid` check in `verify_receipt()`: ensures `declared_at` precedes `started_at`.
- 15 new regression tests covering all six holes (in `tests/test_red_team.py`). All 15 pass against v1.1.

### Changed

- `build_signing_payload()` signature: now requires `outcome: str` and `is_reversible: bool` parameters in addition to the five v1.0 parameters.
- `verify_receipt()` `checks` dict: added `timing_valid` key.

---

## [1.0.0] - 2026-03-01

### Added

- Core protocol: Action Receipt with Phase 1 (intent and before-state) and Phase 2 (execution and provider attestation).
- Ed25519 signing via the `cryptography` library. Five-field signing payload: `receipt_id`, `intent_id`, `outcome_hash`, `before_state_hash`, `signed_at`.
- RFC 6962 Merkle tree implementation with leaf hash `SHA-256(0x00 || data)` and node hash `SHA-256(0x01 || left || right)`.
- Seven JSON Schema draft-2020-12 definitions in `schemas/`.
- `@signed_tool` decorator as the primary user-facing integration point.
- `ARCInMemoryLog` for testing and demos without HTTP.
- `ARCLogClient` HTTP client for the log server.
- FastAPI log server (`arc_log/`) with SQLite-backed storage and three endpoints: `POST /v1/log/intent`, `POST /v1/log/receipt`, `GET /v1/log/verify/{receipt_id}`.
- Snapshot capture and rollback for `filesystem:file`, `filesystem:directory`, `memory:key`, and `api:response` resource types.
- 51 tests passing across `test_signing.py`, `test_receipt.py`, `test_merkle.py`, `test_log.py`, `test_decorator.py`, and `test_e2e.py`.
- Demo scenarios: `demo_basic.py`, `demo_disaster.py`, `demo_verify.py`.
- ULID-based ID generation with prefixes: `arc_`, `intent_`, `snap_`, `log_`.
- `verify_receipt()` returning `{"valid": bool, "checks": {...}, "errors": [...]}`.
