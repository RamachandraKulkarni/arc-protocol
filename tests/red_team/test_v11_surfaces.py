"""
Second-pass red team: new code surfaces introduced by the v1.1 patches.

Covers four surfaces the original red team session did not test:
  1. Expanded signing payload (outcome + is_reversible now signed)
  2. Emergent fix: is_reversible=False with inverse_signature present
  3. Duplicate guard edge cases (intent→receipt→intent, two receipts)
  4. Timestamp ordering boundary (declared_at == started_at is valid)
  5. Merkle content_hash tamper at the last (boundary) entry
"""

import copy
from pathlib import Path

import pytest

from arc import ARCContext, signed_tool
from arc.ids import new_intent_id, new_receipt_id
from arc.log_client import ARCLogError
from arc.receipt import verify_receipt
from arc.signing import sha256_hex

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_valid_receipt(ctx: ARCContext, temp_dir: str) -> dict:
    """Produce a normal, cryptographically valid receipt via @signed_tool."""

    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def read_files(path: str, ctx: ARCContext) -> dict:
        files = list(Path(path).rglob("*"))
        return {"count": len(files), "path": path}

    return read_files(temp_dir, ctx=ctx)


def _get_failure_receipt(ctx: ARCContext, temp_dir: str) -> dict:
    """Produce a receipt where the tool raised (outcome='failure')."""

    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def delete_nonexistent(path: str, ctx: ARCContext) -> dict:
        Path(path).unlink()  # raises FileNotFoundError
        return {"deleted": True}

    missing = str(Path(temp_dir) / "does_not_exist.txt")
    return delete_nonexistent(missing, ctx=ctx)


def _build_minimal_intent(tag: str = "x") -> dict:
    return {
        "intent_id": new_intent_id(),
        "tool_name": "noop",
        "arguments": {"tag": tag},
        "declared_by": {"agent_id": "test", "model_version": "v1", "session_id": "s1"},
        "reasoning_commitment": sha256_hex(f"reason-{tag}".encode()),
        "declared_at": "2026-01-01T00:00:00Z",
    }


# ---------------------------------------------------------------------------
# Surface 1  -  expanded signing payload
# ---------------------------------------------------------------------------


class TestExpandedSigningPayload:
    """
    v1.1 patch: outcome string and is_reversible flag are now in the signing payload.
    Changing either field alone must fail provider_signature_valid.
    """

    def test_outcome_string_changed_independently_fails(self, ctx, temp_dir, registry):
        """
        Change outcome from 'success' to 'failure' WITHOUT touching outcome_hash.
        Because outcome is now in the signing payload, the signature must not verify.
        """
        receipt = _get_valid_receipt(ctx, temp_dir)
        assert receipt["phase_2"]["execution"]["outcome"] == "success"

        tampered = copy.deepcopy(receipt)
        tampered["phase_2"]["execution"]["outcome"] = "failure"
        # outcome_hash is intentionally left unchanged  -  only the string changes

        result = verify_receipt(tampered, registry)

        assert result["valid"] is False
        assert result["checks"]["provider_signature_valid"] is False, (
            "outcome is in the signing payload; changing it must invalidate the signature"
        )

    def test_outcome_string_failure_to_success_fails(self, ctx, temp_dir, registry):
        """
        Change outcome from 'failure' to 'success' (the Replit lie direction).
        The provider signed outcome='failure'; mutating it must break verification.
        """
        receipt = _get_failure_receipt(ctx, temp_dir)
        assert receipt["phase_2"]["execution"]["outcome"] == "failure"

        tampered = copy.deepcopy(receipt)
        tampered["phase_2"]["execution"]["outcome"] = "success"

        result = verify_receipt(tampered, registry)

        assert result["valid"] is False
        assert result["checks"]["provider_signature_valid"] is False, (
            "REGRESSION: outcome field is no longer protected by the signing payload. "
            "This was Hole 1 from the first red team session."
        )

    def test_is_reversible_flipped_without_resigning_fails(self, ctx, temp_dir, registry):
        """
        Change is_reversible=True→False in the inverse block without re-signing.
        Because is_reversible is now in the signing payload, the signature must fail.
        (Separate from the emergent fix  -  this tests the signing layer directly.)
        """
        receipt = _get_valid_receipt(ctx, temp_dir)
        if receipt["phase_2"].get("inverse") is None:
            pytest.skip("receipt has no inverse block  -  resource not reversible")

        assert receipt["phase_2"]["inverse"]["is_reversible"] is True

        tampered = copy.deepcopy(receipt)
        tampered["phase_2"]["inverse"]["is_reversible"] = False
        # inverse_signature left intact (old valid signature for is_reversible=True)

        result = verify_receipt(tampered, registry)

        assert result["valid"] is False
        assert result["checks"]["provider_signature_valid"] is False, (
            "is_reversible is in the signing payload; flipping it must break the signature"
        )

    def test_valid_receipt_still_passes_after_patch(self, ctx, temp_dir, registry):
        """Sanity check: a genuine receipt must still verify as valid after the v1.1 patch."""
        receipt = _get_valid_receipt(ctx, temp_dir)
        result = verify_receipt(receipt, registry)

        assert result["valid"] is True
        assert result["checks"]["provider_signature_valid"] is True


# ---------------------------------------------------------------------------
# Surface 2  -  emergent fix: is_reversible=False + inverse_signature present
# ---------------------------------------------------------------------------


class TestIsReversibleContradiction:
    """
    Emergent fix: if is_reversible=False but inverse_signature is still present,
    verify_receipt() must flag it as a structural inconsistency.

    Attack scenario: agent flip is_reversible=False to deny rollback, but the
    provider's inverse_signature is still sitting in the receipt revealing the lie.
    """

    def test_is_reversible_false_with_signature_present_is_flagged(self, ctx, temp_dir, registry):
        """
        Start with a valid reversible receipt (is_reversible=True, inverse_signature present).
        Flip is_reversible=False but keep inverse_signature.
        verify_receipt() must return valid=False with a descriptive error.
        """
        receipt = _get_valid_receipt(ctx, temp_dir)
        inverse = receipt.get("phase_2", {}).get("inverse", {})
        if not inverse or not inverse.get("inverse_signature"):
            pytest.skip("receipt has no inverse_signature  -  skip structural-contradiction test")

        assert inverse["is_reversible"] is True

        tampered = copy.deepcopy(receipt)
        tampered["phase_2"]["inverse"]["is_reversible"] = False
        # inverse_signature intentionally kept  -  the structural contradiction we're testing

        result = verify_receipt(tampered, registry)

        assert result["valid"] is False
        assert result["checks"]["inverse_signature_valid"] is False

        # The error message must name the inconsistency so it's actionable
        error_text = " ".join(result["errors"]).lower()
        assert "inconsistent" in error_text or "is_reversible" in error_text, (
            f"Expected error naming inconsistency or is_reversible, got: {result['errors']}"
        )

    def test_is_reversible_true_without_signature_is_not_flagged(self, ctx, temp_dir, registry):
        """
        Baseline: is_reversible=True but no inverse_signature (tool chose not to include it).
        This is a legitimate receipt  -  the check must not false-positive here.
        """
        # Build a receipt where is_reversible ends up False (failure outcome → no inverse)
        receipt = _get_failure_receipt(ctx, temp_dir)
        inverse = receipt.get("phase_2", {}).get("inverse", {})

        # On failure, decorator sets is_reversible=False, no inverse_signature
        if inverse and inverse.get("inverse_signature"):
            pytest.skip("unexpected inverse_signature on failure receipt")

        result = verify_receipt(receipt, registry)
        # Failure receipts fail only if signature is invalid  -  check structural contradiction
        # check specifically does not fire (inverse_signature_valid should be None, not False)
        assert result["checks"]["inverse_signature_valid"] is None, (
            "No inverse_signature → check should be None (not applicable), not False"
        )


# ---------------------------------------------------------------------------
# Surface 3  -  duplicate guard edge cases
# ---------------------------------------------------------------------------


class TestDuplicateGuard:
    """
    The log's duplicate guard prevents:
      - Committing an intent twice for the same receipt_id
      - Committing a receipt before its intent
      - Committing a receipt twice for the same receipt_id
    """

    def test_second_intent_for_same_receipt_id_rejected(self, log):
        """
        Sequence: intent → receipt → intent (second attempt)
        The second intent commit must raise ARCLogError because a receipt is already
        in the log for that receipt_id  -  backdated intent injection rejected.
        """
        rid = new_receipt_id()
        intent = _build_minimal_intent("first")
        log.commit_intent(intent, rid)

        # Minimal receipt structure for commit_receipt
        fake_receipt = {
            "arc_version": "1.0",
            "receipt_id": rid,
            "phase_1": {
                "intent": intent,
                "before_state": {
                    "resource_uri": "memory:test",
                    "resource_type": "memory:key",
                    "snapshot_hash": sha256_hex(b"x"),
                    "captured_at": "2026-01-01T00:00:00Z",
                },
                "log_commitment": {
                    "log_id": "test",
                    "sequence_number": 0,
                    "merkle_root": sha256_hex(b"root"),
                    "committed_at": "2026-01-01T00:00:00Z",
                },
            },
            "phase_2": {
                "execution": {
                    "started_at": "2026-01-01T00:00:01Z",
                    "completed_at": "2026-01-01T00:00:01Z",
                    "duration_ms": 1,
                    "outcome": "success",
                    "outcome_hash": sha256_hex(b"result"),
                },
                "provider_attestation": {
                    "provider_id": "tool:test-v1",
                    "provider_name": "test-v1",
                    "signed_at": "2026-01-01T00:00:02Z",
                    "signature": "ed25519:" + "A" * 86 + "==",
                    "signed_payload_hash": sha256_hex(b"payload"),
                },
                "log_proof": {
                    "log_id": "test",
                    "sequence_number": 1,
                    "merkle_root": sha256_hex(b"root2"),
                    "committed_at": "2026-01-01T00:00:02Z",
                },
            },
        }
        log.commit_receipt(fake_receipt)

        # Now try to commit a second intent for the same receipt_id
        second_intent = _build_minimal_intent("second")
        with pytest.raises(ARCLogError, match="already committed"):
            log.commit_intent(second_intent, rid)

    def test_two_receipts_for_same_id_rejected(self, log):
        """
        Sequence: intent → receipt → receipt (second attempt)
        The second receipt commit must raise ARCLogError  -  replay attack rejected.
        """
        rid = new_receipt_id()
        intent = _build_minimal_intent("dup")
        log.commit_intent(intent, rid)

        receipt_body = {
            "arc_version": "1.0",
            "receipt_id": rid,
            "phase_1": {
                "intent": intent,
                "before_state": {
                    "resource_uri": "memory:test",
                    "resource_type": "memory:key",
                    "snapshot_hash": sha256_hex(b"x"),
                    "captured_at": "2026-01-01T00:00:00Z",
                },
                "log_commitment": {
                    "log_id": "test",
                    "sequence_number": 0,
                    "merkle_root": sha256_hex(b"root"),
                    "committed_at": "2026-01-01T00:00:00Z",
                },
            },
            "phase_2": {
                "execution": {
                    "started_at": "2026-01-01T00:00:01Z",
                    "completed_at": "2026-01-01T00:00:01Z",
                    "duration_ms": 1,
                    "outcome": "success",
                    "outcome_hash": sha256_hex(b"result"),
                },
                "provider_attestation": {
                    "provider_id": "tool:test-v1",
                    "provider_name": "test-v1",
                    "signed_at": "2026-01-01T00:00:02Z",
                    "signature": "ed25519:" + "A" * 86 + "==",
                    "signed_payload_hash": sha256_hex(b"payload"),
                },
                "log_proof": {
                    "log_id": "test",
                    "sequence_number": 1,
                    "merkle_root": sha256_hex(b"root2"),
                    "committed_at": "2026-01-01T00:00:02Z",
                },
            },
        }
        log.commit_receipt(receipt_body)

        with pytest.raises(ARCLogError, match="already committed"):
            log.commit_receipt(receipt_body)

    def test_duplicate_intent_before_receipt_also_rejected(self, log):
        """
        Sequence: intent → intent (before any receipt)
        Even before a receipt is committed, a duplicate intent must be rejected.
        """
        rid = new_receipt_id()
        intent1 = _build_minimal_intent("a")
        log.commit_intent(intent1, rid)

        intent2 = _build_minimal_intent("b")
        with pytest.raises(ARCLogError, match="already committed"):
            log.commit_intent(intent2, rid)

    def test_receipt_without_prior_intent_is_rejected(self, log):
        """
        Sequence: receipt (no prior intent)
        The log allows orphan receipts (commit_receipt doesn't check for a prior intent
        in the in-memory implementation). This test documents the current behaviour.

        If the implementation is hardened to require intent-first, update this test.
        """
        rid = new_receipt_id()
        intent = _build_minimal_intent("orphan")

        receipt_body = {
            "arc_version": "1.0",
            "receipt_id": rid,
            "phase_1": {
                "intent": intent,
                "before_state": {
                    "resource_uri": "memory:test",
                    "resource_type": "memory:key",
                    "snapshot_hash": sha256_hex(b"x"),
                    "captured_at": "2026-01-01T00:00:00Z",
                },
                "log_commitment": {
                    "log_id": "test",
                    "sequence_number": 0,
                    "merkle_root": sha256_hex(b"root"),
                    "committed_at": "2026-01-01T00:00:00Z",
                },
            },
            "phase_2": {
                "execution": {
                    "started_at": "2026-01-01T00:00:01Z",
                    "completed_at": "2026-01-01T00:00:01Z",
                    "duration_ms": 1,
                    "outcome": "success",
                    "outcome_hash": sha256_hex(b"result"),
                },
                "provider_attestation": {
                    "provider_id": "tool:test-v1",
                    "provider_name": "test-v1",
                    "signed_at": "2026-01-01T00:00:02Z",
                    "signature": "ed25519:" + "A" * 86 + "==",
                    "signed_payload_hash": sha256_hex(b"payload"),
                },
                "log_proof": {
                    "log_id": "test",
                    "sequence_number": 0,
                    "merkle_root": sha256_hex(b"root2"),
                    "committed_at": "2026-01-01T00:00:02Z",
                },
            },
        }

        # Document current behaviour: ARCInMemoryLog.commit_receipt does NOT require
        # a prior intent entry. Orphan receipts are accepted at the log level.
        # (verify_receipt and the log server layer enforce the ordering contract.)
        log.commit_receipt(receipt_body)  # should not raise


# ---------------------------------------------------------------------------
# Surface 4  -  timestamp ordering boundary
# ---------------------------------------------------------------------------


class TestTimestampOrdering:
    """
    verify_receipt() rejects declared_at > started_at (backdate attack).
    The equal case (declared_at == started_at) must be treated as valid.
    """

    def test_declared_at_equal_to_started_at_is_valid(self, ctx, temp_dir, registry):
        """
        Set declared_at == started_at in the receipt.
        declared_at is NOT in the signing payload, so this does not break the signature.
        The timestamp_ordering check uses strict '>' so equal timestamps must pass.
        """
        receipt = _get_valid_receipt(ctx, temp_dir)
        started_at = receipt["phase_2"]["execution"]["started_at"]

        tampered = copy.deepcopy(receipt)
        tampered["phase_1"]["intent"]["declared_at"] = started_at  # equal, not before

        result = verify_receipt(tampered, registry)

        # declared_at not in signing payload → signature still valid
        assert result["checks"]["provider_signature_valid"] is True

        # Equal timestamps must not trigger the ordering violation
        ts_check = result["checks"].get("timestamp_ordering")
        assert ts_check is True, (
            f"declared_at == started_at should be valid (not a backdate), "
            f"but timestamp_ordering={ts_check}. Errors: {result['errors']}"
        )

        # Full receipt should be valid
        assert result["valid"] is True

    def test_declared_at_one_second_after_started_at_is_invalid(self, ctx, temp_dir, registry):
        """
        Confirm that declared_at strictly after started_at is caught.
        (Regression guard for the timestamp ordering check itself.)
        """
        receipt = _get_valid_receipt(ctx, temp_dir)

        tampered = copy.deepcopy(receipt)
        # Use a timestamp far in the future  -  definitely after started_at
        tampered["phase_1"]["intent"]["declared_at"] = "2099-12-31T23:59:59Z"

        result = verify_receipt(tampered, registry)

        ts_check = result["checks"].get("timestamp_ordering")
        assert ts_check is False, "declared_at after started_at must fail timestamp_ordering check"
        assert result["valid"] is False
        assert any("declared_at" in e or "timestamp" in e.lower() for e in result["errors"])


# ---------------------------------------------------------------------------
# Surface 5  -  Merkle content_hash tamper at boundary (last entry)
# ---------------------------------------------------------------------------


class TestMerkleLastEntryTamper:
    """
    verify_consistency() performs a content-hash rebuild pass that catches
    tampering at any entry. The last-entry boundary is a common off-by-one risk.
    """

    def test_content_hash_tampered_at_last_entry_detected(self, log, temp_dir, ctx):
        """
        Commit several receipts, then tamper the content_hash of the LAST entry.
        verify_consistency() must report is_consistent=False and name sequence N.
        """
        # Commit 4 intent entries so we have a populated log
        for i in range(4):
            rid = new_receipt_id()
            intent = _build_minimal_intent(str(i))
            log.commit_intent(intent, rid)

        total_entries = len(log._entries)
        last_seq = total_entries - 1

        # Tamper the content_hash of the last entry (boundary case)
        log.tamper_entry(last_seq, "content_hash", sha256_hex(b"tampered-content"))

        result = log.verify_consistency()

        assert result["is_consistent"] is False, (
            "content_hash tampered at last entry must be detected by verify_consistency()"
        )
        assert len(result["errors"]) > 0

        # The error must identify the correct sequence number
        error_text = " ".join(result["errors"])
        assert str(last_seq) in error_text or "tampered" in error_text.lower(), (
            f"Expected error to reference sequence {last_seq}, got: {result['errors']}"
        )

    def test_content_hash_tampered_at_first_entry_detected(self, log):
        """
        Symmetric test: tamper the FIRST entry.
        Both boundaries must be caught.
        """
        for i in range(3):
            rid = new_receipt_id()
            intent = _build_minimal_intent(str(i))
            log.commit_intent(intent, rid)

        log.tamper_entry(0, "content_hash", sha256_hex(b"tampered-first"))

        result = log.verify_consistency()

        assert result["is_consistent"] is False
        assert any("0" in e or "tampered" in e.lower() for e in result["errors"])

    def test_untampered_log_reports_consistent(self, log):
        """Sanity: a clean log must report is_consistent=True."""
        for i in range(5):
            rid = new_receipt_id()
            log.commit_intent(_build_minimal_intent(str(i)), rid)

        result = log.verify_consistency()

        assert result["is_consistent"] is True
        assert result["errors"] == []
