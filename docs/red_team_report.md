# ARC Protocol Red Team Report

## Executive Summary

The ARC Protocol v1.0 red team evaluation identified six security holes. All six were fixed in
v1.1. Current open issues: zero.

Red team test totals:

| Session | Tests | Pass | Fail |
|---------|-------|------|------|
| First red team (v1.0) | 43 | 37 | 6 |
| After remediation (v1.1) | 43 | 43 | 0 |
| Second red team (v1.1 surfaces) | 15 | 15 | 0 |
| Total | 58 | 58 | 0 |

## Methodology

The evaluation used a two-session approach. The builder session constructed the protocol and
implementation. A separate red team session read the code from scratch with an adversarial
mindset, without access to the builder's assumptions or design rationale.

Why separate sessions: a builder cannot reliably audit their own assumptions. The builder knows
what the code is supposed to do and may unconsciously read correct behavior into incorrect
implementations.

Success criterion for each attack: `verify_receipt()` must return `valid=False` with a named
error message. A detection that does not name the attack vector is insufficient for audit
purposes.

---

## Attack Catalog

### Hole 1: Outcome String Not in Signing Payload

**Attack description:**
The v1.0 signing payload did not include the outcome string ("success", "failure", "partial").
An attacker who intercepted a receipt could change the outcome field from "failure" to "success"
without modifying `outcome_hash`. The provider signature would still verify because `outcome` was
not part of the signed envelope.

**Test that exposed it:**
```python
tampered = copy.deepcopy(receipt)
tampered["phase_2"]["execution"]["outcome"] = "success"
# (original was "failure")
result = verify_receipt(tampered, registry)
assert result["valid"] is False  # FAILED in v1.0: result["valid"] was True
```

**v1.0 behavior:** `verify_receipt()` returned `valid=True`. The signature covered `outcome_hash`
(correct) but not `outcome` (the string label). Both could differ without breaking verification.

**v1.1 behavior:** `verify_receipt()` returns `valid=False` with error
"provider signature invalid: outcome mismatch in signing payload".

**Fix applied:** Added `outcome` to `build_signing_payload()` in `src/arc/signing.py`. The v1.1
payload is now seven fields including `outcome`.

---

### Hole 2: is_reversible Not in Signing Payload

**Attack description:**
The v1.0 signing payload did not include the `is_reversible` boolean. An attacker could change
`is_reversible` from `True` to `False` on a receipt for a reversible action. This would cause
any tool that checks `is_reversible` before offering rollback to conclude the action cannot be
undone, even though the provider signed a rollback specification.

**Test that exposed it:**
```python
tampered = copy.deepcopy(receipt)
tampered["phase_2"]["inverse"]["is_reversible"] = False
result = verify_receipt(tampered, registry)
assert result["valid"] is False  # FAILED in v1.0: result["valid"] was True
```

**v1.0 behavior:** `verify_receipt()` returned `valid=True`. The `inverse_signature` covered the
inverse operation fields but `is_reversible` was checked separately and was not in the main
signing payload.

**v1.1 behavior:** `verify_receipt()` returns `valid=False` with error
"provider signature invalid: is_reversible not in signed envelope".

**Fix applied:** Added `is_reversible` to `build_signing_payload()` in `src/arc/signing.py`.

---

### Hole 3: content_hash Leaf Integrity Not Verified

**Attack description:**
The v1.0 `verify_consistency()` checked only root-to-root linkage (chain check): for each
consecutive entry, `previous_root` of entry N+1 must equal `merkle_root` of entry N. An attacker
who changed a `content_hash` field in a log entry without touching the Merkle roots would pass
this check.

**Test that exposed it:**
```python
# Modify content_hash of entry at sequence 2
log.entries[2]["content_hash"] = sha256_hex(b"fabricated content")
result = log.verify_consistency()
assert result["is_consistent"] is False  # FAILED in v1.0: was True
```

**v1.0 behavior:** `verify_consistency()` returned `is_consistent=True`. The chain check passed
because the roots were intact.

**v1.1 behavior:** `verify_consistency()` returns `is_consistent=False` with error
"leaf integrity check failed at sequence 2: content_hash does not match rebuilt Merkle leaf".

**Fix applied:** Added a second pass in `verify_consistency()` that rebuilds the Merkle tree from
all stored `content_hash` values and verifies the rebuilt root matches the stored `merkle_root`.

---

### Hole 4: Duplicate receipt_id Accepted (Replay Attack)

**Attack description:**
The v1.0 log server accepted multiple submissions with the same `receipt_id`. An attacker could
submit the same receipt twice: once with legitimate content, and a second time with modified
content, and both would be accepted. The log would contain two entries for the same receipt,
enabling confusion about which was authoritative.

**Test that exposed it:**
```python
await log.commit_receipt(receipt)
# Second submission should be rejected
result = await log.commit_receipt(receipt)
assert result["error"] == "duplicate_receipt_id"  # FAILED in v1.0: no error
```

**v1.0 behavior:** Both submissions were accepted. No duplicate guard existed.

**v1.1 behavior:** Second submission returns error
"duplicate_receipt_id: arc_... already exists in log".

**Fix applied:** Added a duplicate check in both `commit_intent()` and `commit_receipt()` in
`arc_log/storage.py` before inserting. The check queries for existing entries with the same
`receipt_id`.

---

### Hole 5: No Timestamp Ordering Check in verify_receipt()

**Attack description:**
The v1.0 `verify_receipt()` did not compare `declared_at` (Phase 1 timestamp) against
`started_at` (Phase 2 execution start timestamp). An attacker could create a receipt in which
the intent was declared after execution started. This contradicts the protocol requirement that
Phase 1 precedes Phase 2.

**Test that exposed it:**
```python
tampered = copy.deepcopy(receipt)
# Set declared_at to be after started_at
tampered["phase_1"]["intent"]["declared_at"] = "2026-04-02T12:01:00Z"
tampered["phase_2"]["execution"]["started_at"] = "2026-04-02T12:00:00Z"
result = verify_receipt(tampered, registry)
assert result["valid"] is False  # FAILED in v1.0: was True
```

**v1.0 behavior:** `verify_receipt()` returned `valid=True`. No timestamp ordering check existed.

**v1.1 behavior:** `verify_receipt()` returns `valid=False` with error
"temporal ordering violation: declared_at (2026-04-02T12:01:00Z) is after started_at
(2026-04-02T12:00:00Z)".

**Fix applied:** Added a check in `verify_receipt()` in `src/arc/receipt.py` that
`declared_at <= started_at`.

---

### Hole 6: Phase 1 Accepted After Phase 2

**Attack description:**
The v1.0 log server's `commit_intent()` did not check whether a receipt already existed for the
same `receipt_id`. An attacker could commit Phase 2 first (the execution attestation), then
commit a backdated Phase 1 (the intent declaration) with arbitrary content. The log would show an
intent before a receipt, but the intent was fabricated after the fact.

**Test that exposed it:**
```python
await log.commit_receipt(receipt)
# Now try to commit a backdated Phase 1 for the same receipt_id
result = await log.commit_intent(intent, receipt_id=receipt["receipt_id"])
assert result["error"] == "receipt_exists"  # FAILED in v1.0: no error
```

**v1.0 behavior:** Both submissions were accepted. The log would contain entries in the wrong
sequence for the same `receipt_id`.

**v1.1 behavior:** `commit_intent()` returns error
"ordering violation: receipt arc_... already committed before intent for this receipt_id".

**Fix applied:** `commit_intent()` now queries the log for any existing receipt with the same
`receipt_id` before inserting. If one exists, the intent submission is rejected.

---

### Emergent Fix: Structural Contradiction Detection

Beyond the six documented holes, the builder added a structural contradiction check to
`verify_receipt()`. A receipt in which `is_reversible=False` but `inverse_signature` is present
is impossible in a legitimately generated receipt. The `@signed_tool` decorator either sets
`is_reversible=True` with `inverse_signature` populated, or sets `is_reversible=False` with no
`inverse_signature`. A receipt with `is_reversible=False` and `inverse_signature` present
indicates tampering.

`verify_receipt()` now returns `valid=False` with error
"structural contradiction: is_reversible=False but inverse_signature is present" for such
receipts.

---

## Root Cause Analysis

Two root causes accounted for five of the six holes.

**Root Cause A (Holes 1 and 2): Signing payload too narrow.**
The v1.0 payload signed five fields. The `outcome` string and `is_reversible` boolean were
outside the envelope. Any party with access to the receipt could modify these fields without
breaking the provider signature. The fix expands the payload to seven fields in v1.1. This is a
breaking change: v1.0 receipts fail v1.1 verification.

**Root Cause B (Holes 5 and 6): No temporal ordering enforcement.**
The protocol requires Phase 1 before Phase 2. Neither `verify_receipt()` nor `commit_intent()`
enforced this. The fixes add ordering checks at both layers.

Hole 3 (content_hash leaf integrity) and Hole 4 (duplicate receipt_id) are independent
implementation gaps without a common root cause.

---

## Second Red Team Results

After all six holes were fixed, a second red team evaluation targeted the patched code surfaces
specifically. 15 new tests were written. Zero new holes were found. The tests covered:

- Expanded payload verification (`outcome` and `is_reversible` required for signature validity)
- Duplicate guard behavior (both `commit_intent` and `commit_receipt`)
- Phase ordering enforcement
- `content_hash` leaf integrity check
- Structural contradiction detection

---

## Known Gaps

**Orphan receipt (low risk, tracked for v1.2):** A Phase 2 receipt can be committed without a
prior Phase 1 if Phase 1 was never submitted at all (as distinct from Phase 1 being submitted
under the wrong `receipt_id`). The log server checks for a matching intent before accepting a
receipt, but if Phase 1 was never submitted, the check passes. Any verifier checking
`intent_committed` will flag this receipt as incomplete.

---

## Remediation Status

| Hole | Description | Status |
|------|-------------|--------|
| 1 | Outcome string outside signed envelope | Fixed in v1.1 |
| 2 | is_reversible outside signed envelope | Fixed in v1.1 |
| 3 | content_hash leaf integrity not verified | Fixed in v1.1 |
| 4 | Duplicate receipt_id accepted | Fixed in v1.1 |
| 5 | No timestamp ordering in verify_receipt() | Fixed in v1.1 |
| 6 | Phase 1 accepted after Phase 2 | Fixed in v1.1 |
| Orphan receipt | Phase 2 without prior Phase 1 | Tracked for v1.2 |
