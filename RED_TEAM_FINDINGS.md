# ARC Protocol  -  Red Team Findings

**Tested by:** Adversarial test suite (`tests/red_team/`)
**Date:** 2026-04-02
**Protocol version:** 1.0
**Implementation:** `src/arc/`

This document records every protocol hole found during red team testing.
A hole is a case where `verify_receipt()` returns `valid=True` when it should return `valid=False`,
or where the transparency log accepts something it should reject.

**Finding holes is success. Hiding them is failure.**

---

## Summary Table

| Hole | Attack Vector | Detected? | Severity |
|------|--------------|-----------|----------|
| 1 | Outcome field (success/failure) changed | **NOT DETECTED** | High |
| 2 | `is_reversible` changed True→False | **NOT DETECTED** | High |
| 3 | Log `content_hash` modified, chain intact | **NOT DETECTED** | Medium |
| 4 | Duplicate receipt submitted to log | **NOT DETECTED** | Medium |
| 5 | Timestamp ordering not checked | **NOT DETECTED** | High |
| 6 | Phase 1 committed after Phase 2 in log | **NOT DETECTED** | High |

---

## Hole 1: `outcome` Field Not In Signing Payload

**Test:** `tests/red_team/test_attack_1_fabrication.py::TestResultFabrication::test_fabricated_success_on_actual_failure`

**Attack:**
An agent calls a tool that raises an exception. The receipt records `outcome="failure"`.
The agent changes `outcome` from `"failure"` to `"success"` in the receipt.

**Why it works:**
The provider's signing payload is:
```
sha256_hex(canonical_json({
    "before_state_hash": ...,
    "intent_id": ...,
    "outcome_hash": ...,
    "receipt_id": ...,
    "signed_at": ...,
}))
```
The `outcome` field (the string `"success"` / `"failure"` / `"partial"`) is **not included**
in the signing payload. Only `outcome_hash` (the SHA-256 of the actual result dict) is signed.

**Effect:**
- Provider signature still verifies (unchanged fields).
- Schema validates (both enum values are allowed).
- `verify_receipt()` returns `valid=True`.

**What should happen:**
`verify_receipt()` should return `valid=False` with an error naming `outcome` field tampering.

**Fix:**
Include the `outcome` string in the signing payload:
```python
payload_obj = {
    "before_state_hash": before_state_hash,
    "intent_id": intent_id,
    "outcome": outcome,           # ADD THIS
    "outcome_hash": outcome_hash,
    "receipt_id": receipt_id,
    "signed_at": signed_at,
}
```

---

## Hole 2: Inverse Operation Not In Signing Payload

**Test:** `tests/red_team/test_attack_4_rollback_lie.py::TestRollbackDenial::test_agent_cannot_forge_is_reversible_false`

**Attack:**
Agent changes `phase_2.inverse.is_reversible` from `True` to `False` in the receipt.
This suppresses the inverse operation, hiding the rollback capability from users.

**Why it works:**
The provider signing payload does not include any inverse operation fields.
When `is_reversible=False`, `verify_receipt()` skips the `inverse_signature_valid` check
entirely and sets it to `None`. Since `None is not False` evaluates to `True`, the receipt
passes all checks.

**Effect:**
- Provider signature still verifies.
- `inverse_signature_valid` is set to `None` (treated as "not applicable").
- `verify_receipt()` returns `valid=True`.

**What should happen:**
`verify_receipt()` should detect that `is_reversible` was changed and return `valid=False`.

**Fix (Option A  -  preferred):**
Include `is_reversible` in the provider signing payload alongside the other execution fields.

**Fix (Option B):**
When `inverse` object is present and has additional fields beyond `is_reversible`,
require the `inverse_signature` to verify even when `is_reversible=False`.

---

## Hole 3: `content_hash` Modification Not Detected by Chain Check

**Test:** `tests/red_team/test_attack_2_log_tamper.py::TestLogTampering::test_content_hash_modification_not_detected_by_chain_check`

**Attack:**
Attacker modifies the `content_hash` of a log entry (changing the record of what was committed)
without updating the `merkle_root` for that entry.

**Why it works:**
`verify_consistency()` checks the `previous_root → merkle_root` chain between consecutive
entries. It does **not** recompute the Merkle tree from `content_hash` values. The chain is
intact (no root was changed), so the check passes.

**Effect:**
`verify_consistency()` returns `is_consistent=True` despite `content_hash` being tampered.

**What should happen:**
Any modification to `content_hash` should be detectable by recomputing the Merkle leaf hash
from the content and comparing to the stored `merkle_root`.

**Fix:**
Extend `verify_consistency()` to recompute `leaf_hash(content_hash)` for each entry and
verify it appears correctly in the stored Merkle tree:
```python
from arc.merkle import leaf_hash, MerkleTree

def verify_consistency(self) -> dict:
    # ... existing chain check ...
    # Also: recompute tree from scratch and compare roots
    recomputed_tree = MerkleTree()
    for entry in entries:
        recomputed_tree.append(entry["content_hash"])
    if recomputed_tree.root() != entries[-1]["merkle_root"]:
        is_consistent = False
        errors.append("Merkle root mismatch: content_hash values do not match stored tree")
```

---

## Hole 4: Log Does Not Reject Duplicate Receipt Submissions

**Test:** `tests/red_team/test_attack_5_replay.py::TestReplayAttack::test_duplicate_receipt_id_rejected_by_log`

**Attack:**
The same receipt (same `receipt_id`) is submitted to `commit_receipt()` a second time.

**Why it works:**
`ARCInMemoryLog.commit_receipt()` calls `_append("receipt", receipt_id, receipt_dict)`
without checking whether `receipt_id` already has an entry in `_receipt_entries`.

**Effect:**
The second submission creates a second log entry with the same `receipt_id` but a new
sequence number. The log now contains two receipt entries for the same action.

**What should happen:**
`commit_receipt()` must raise `ARCLogError` if a receipt entry already exists for
the given `receipt_id`.

**Fix:**
```python
def commit_receipt(self, receipt_dict: dict) -> dict:
    receipt_id = receipt_dict["receipt_id"]
    with self._lock:
        existing = self._receipt_entries.get(receipt_id, [])
        has_receipt = any(
            self._entries[s]["entry_type"] == "receipt"
            for s in existing
            if s < len(self._entries)
        )
        if has_receipt:
            raise ARCLogError(f"Receipt already committed: {receipt_id}")
    _, commitment = self._append("receipt", receipt_id, receipt_dict)
    return commitment
```

---

## Hole 5: No Timestamp Ordering Check in `verify_receipt()`

**Tests:**
- `tests/red_team/test_attack_5_replay.py::TestReplayAttack::test_no_freshness_check_in_verify_receipt`
- `tests/red_team/test_attack_6_backdate.py::TestBackdatedIntent::test_declared_at_after_execution_flagged`

**Attack:**
Agent sets `declared_at` (Phase 1 intent timestamp) to a time **after**
`execution.started_at` (Phase 2). This is logically impossible  -  you cannot declare intent
after you have already acted.

**Why it works:**
`verify_receipt()` does not check any timestamp ordering. It only checks:
1. Schema validation (format only, not ordering)
2. Provider signature (covers `signed_at`, not `declared_at` or `started_at`)
3. Inverse signature
4. Sequence number monotonicity (log sequence numbers, not wall-clock times)

**Effect:**
A receipt with `declared_at = "2099-12-31T23:59:59Z"` and `started_at = "2026-01-01T00:00:00Z"`
passes `verify_receipt()` with `valid=True`.

**What should happen:**
`verify_receipt()` should check:
1. `declared_at < execution.started_at` (intent before action)
2. `execution.started_at <= execution.completed_at` (positive duration)
3. `execution.completed_at <= provider_attestation.signed_at` (signed after completion)

**Fix:**
Add a timestamp ordering check to `verify_receipt()`:
```python
try:
    declared_at = receipt["phase_1"]["intent"]["declared_at"]
    started_at = receipt["phase_2"]["execution"]["started_at"]
    completed_at = receipt["phase_2"]["execution"]["completed_at"]
    signed_at = receipt["phase_2"]["provider_attestation"]["signed_at"]

    if declared_at >= started_at:
        checks["timestamps_ordered"] = False
        errors.append(
            f"Timestamp ordering violation: declared_at ({declared_at}) must be "
            f"before execution.started_at ({started_at})"
        )
    if started_at > completed_at:
        errors.append("started_at must be <= completed_at")
    if completed_at > signed_at:
        errors.append("completed_at must be <= signed_at")
except Exception as e:
    errors.append(f"Timestamp check error: {e}")
```

---

## Hole 6: Log Does Not Enforce Phase 1 Before Phase 2 Ordering

**Test:** `tests/red_team/test_attack_6_backdate.py::TestBackdatedIntent::test_intent_committed_after_receipt_rejected`

**Attack:**
Agent commits a Phase 2 receipt entry to the log first (skipping Phase 1),
then commits a Phase 1 intent entry for the **same** `receipt_id` afterward.
This allows retroactively manufacturing a "prior intent declaration" for an action
that was already executed and logged.

**Why it works:**
`ARCInMemoryLog.commit_intent()` calls `_append("intent", receipt_id, intent_dict)`
without checking whether a receipt entry already exists for the same `receipt_id`.

**Effect:**
The log accepts the backdated intent. An attacker can manufacture a pre-action audit trail
after the fact. The `verify()` check for a given `receipt_id` would show both entries
as `intent_committed=True` and `receipt_committed=True`  -  appearing legitimate.

**What should happen:**
`commit_intent()` must raise `ARCLogError` if a receipt entry already exists for
the given `receipt_id`.

**Fix:**
```python
def commit_intent(self, intent_dict: dict, receipt_id: str) -> dict:
    with self._lock:
        existing = self._receipt_entries.get(receipt_id, [])
        has_receipt = any(
            self._entries[s]["entry_type"] == "receipt"
            for s in existing
            if s < len(self._entries)
        )
        if has_receipt:
            raise ARCLogError(
                f"Cannot commit intent after receipt for {receipt_id}: "
                f"intent must precede receipt in the log"
            )
    _, commitment = self._append("intent", receipt_id, intent_dict)
    return commitment
```

---

## What ARC Gets Right

Despite the holes above, the following attacks are definitively caught:

| What ARC Catches | Test |
|---|---|
| outcome_hash change (result fabrication) | Attack 1, tests 1-3 |
| Merkle chain breaks from merkle_root / previous_root tampering | Attack 2 |
| Signature from wrong keypair | Attack 3 |
| Provider not in registry | Attack 3 |
| Phase 1 sequence > Phase 2 sequence | Attack 6 |
| Tampered `valid_until` on inverse op | Attack 4 |
| Rollback execution from snapshot | Attack 4 |

---

## Threat Model Note

ARC's signing payload covers `{receipt_id, intent_id, outcome_hash, before_state_hash, signed_at}`.
Any field outside this set can be modified without breaking the provider signature.
Fields currently outside the signed payload include:
- `outcome` (the string enum value)
- `is_reversible` and all inverse operation fields
- All timestamps except `signed_at`
- `error_code`, `error_message`
- `provider_id`, `provider_name`
- `declared_by` (agent identity)

Each of these is a potential forgery surface. The fixes in Holes 1, 2, and 5 address the
highest-severity cases. A comprehensive fix would include all execution fields in the payload.
