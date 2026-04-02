# Security Policy

---

## Reporting Vulnerabilities

**Non-critical issues** (medium and low severity per the classification below): open a GitHub issue with the label `security`. Include a description of the issue and reproduction steps.

**Critical and high severity issues** (signature verification bypass, log integrity bypass, key material exposure, replay attack vectors): email security@arc-protocol.org before any public disclosure. Include:

- A description of the vulnerability.
- The affected component (`src/arc/`, `arc_log/`, `schemas/`).
- Reproduction steps or a proof-of-concept test.
- Your preferred credit name or handle for the hall of fame (optional).

Do not disclose critical or high severity vulnerabilities publicly until a fix is released and coordinated disclosure is agreed upon with the maintainers.

---

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgment of report | Within 72 hours |
| Status update with preliminary assessment | Within seven days |
| Fix timeline communicated | Within 14 days |
| Fix released and coordinated disclosure | As agreed with reporter |

---

## Severity Classification

**Critical**

- Signature verification bypass: a receipt that should fail `verify_receipt()` returns `valid=True`.
- Log integrity bypass: a tampered log entry passes `verify_consistency()`.
- Key material exposure: private key bytes accessible via a public API or log entry.

**High**

- Replay attack vectors: a previously committed receipt can be submitted again without detection.
- Timestamp manipulation: a backdated intent passes `verify_receipt()` timing checks.
- Phase ordering bypass: Phase 2 committed before Phase 1 passes log validation.

**Medium**

- Edge case handling: a valid receipt fails verification in a specific but uncommon scenario.
- Schema validation gaps: a malformed receipt passes `jsonschema.validate()`.
- Error message leakage: internal state exposed via error responses.

**Low**

- Documentation errors that could mislead an implementor.
- Non-exploitable code quality issues (unused imports, dead branches).
- Demo script failures that do not affect the library.

---

## Scope

**In scope:**

- `src/arc/`: all modules (signing, receipt, merkle, snapshot, log_client, decorator, ids).
- `arc_log/`: server, storage, merkle.
- `schemas/`: any schema gap that allows a non-compliant receipt to pass validation.
- Any combination of the above that allows a receipt to verify as valid when it should not.

**Out of scope:**

- `demo/` scripts: these are illustrative only and not production code.
- Test harness security: `tests/` is not a production surface.
- Third-party dependencies: report vulnerabilities in `cryptography`, `fastapi`, `httpx`, or `jsonschema` to their respective maintainers.
- Issues that require physical access to the machine running the log server.

---

## Hall of Fame

Reporters of valid critical or high severity issues will be credited here by name or handle at their preference. No valid reports have been received to date.
