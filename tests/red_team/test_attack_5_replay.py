"""
ATTACK 5: Replay Attack
An agent submits a previously valid receipt as if it represents a new action —
to reuse a valid proof for a different context, or claim credit for work not re-done.

WHAT ARC MUST DETECT:
- Receipt IDs are unique (ULID-based, not reusable)
- The log must reject submitting the same receipt_id twice
- Sequence numbers in a receipt must be >= previously committed sequence numbers

HOLES FOUND (see RED_TEAM_FINDINGS.md):
- The in-memory log does NOT reject duplicate receipt submissions. Committing the
  same receipt twice succeeds silently (Hole 4).
- verify_receipt() has no freshness check — a receipt from the past is considered
  valid indefinitely (Hole 5).
"""

import copy
import shutil
from pathlib import Path

import pytest

from arc import ARCContext, signed_tool
from arc.log_client import ARCLogError
from arc.receipt import verify_receipt
from arc.signing import sha256_hex


class TestReplayAttack:

    def _get_valid_receipt(self, ctx, temp_dir):
        file_path = str(Path(temp_dir) / "file1.txt")

        @signed_tool(resource="filesystem", resource_uri_from_args="path")
        def read_file(path: str, ctx: ARCContext) -> dict:
            return {"content": Path(path).read_text()}

        return read_file(file_path, ctx=ctx)

    def test_duplicate_receipt_id_rejected_by_log(self, ctx, temp_dir):
        """
        Submit the same receipt twice. The log must reject the second submission
        because receipt_id already exists.

        EXPECTED: Second commit_receipt() raises ARCLogError with 'duplicate' or
                  'already committed' message.
        ACTUAL: Second commit_receipt() succeeds silently — no duplicate detection.

        THIS TEST EXPOSES A HOLE. See RED_TEAM_FINDINGS.md: Hole 4.
        """
        receipt = self._get_valid_receipt(ctx, temp_dir)

        # First commit already happened inside the tool call.
        # Attempt to commit the same receipt again:
        try:
            ctx.log.commit_receipt(receipt)
            # If we reach here, the log accepted the duplicate — that's the hole
            duplicate_accepted = True
        except ARCLogError:
            duplicate_accepted = False

        # This assertion WILL FAIL — exposing the hole:
        assert not duplicate_accepted, (
            "HOLE 4: The transparency log does not check for duplicate receipt_id on "
            "commit_receipt(). The same receipt can be submitted multiple times without "
            "rejection. An agent could replay a valid past receipt as if it represents a "
            "new action. See RED_TEAM_FINDINGS.md."
        )

    def test_receipt_id_uniqueness_per_call(self, ctx, temp_dir):
        """
        Each tool call generates a distinct receipt_id (ULID-based).
        No two legitimate receipts should share the same ID.
        """
        file_path = str(Path(temp_dir) / "file1.txt")

        @signed_tool(resource="filesystem", resource_uri_from_args="path")
        def read_file(path: str, ctx: ARCContext) -> dict:
            return {"content": Path(path).read_text()}

        receipts = [read_file(file_path, ctx=ctx) for _ in range(5)]
        receipt_ids = [r["receipt_id"] for r in receipts]
        assert len(set(receipt_ids)) == 5, (
            f"All 5 receipts must have unique IDs, got: {receipt_ids}"
        )

    def test_replayed_receipt_has_different_sequence_numbers(self, ctx, temp_dir, registry):
        """
        A legitimately replayed receipt (same tool, different call) gets NEW sequence
        numbers from the log. A verifier comparing sequence numbers against a timestamp
        can detect that the sequence numbers are inconsistent with claimed timing.

        This tests that sequence monotonicity is maintained and is a PARTIAL defense
        against replay — sequence numbers are always increasing.
        """
        file_path = str(Path(temp_dir) / "file1.txt")

        @signed_tool(resource="filesystem", resource_uri_from_args="path")
        def read_file(path: str, ctx: ARCContext) -> dict:
            return {"content": Path(path).read_text()}

        receipt1 = read_file(file_path, ctx=ctx)
        receipt2 = read_file(file_path, ctx=ctx)

        seq1_p1 = receipt1["phase_1"]["log_commitment"]["sequence_number"]
        seq2_p1 = receipt2["phase_1"]["log_commitment"]["sequence_number"]

        assert seq2_p1 > seq1_p1, (
            "Second call must have a higher Phase 1 sequence number than the first"
        )

        # Both receipts must verify independently
        result1 = verify_receipt(receipt1, registry)
        result2 = verify_receipt(receipt2, registry)
        assert result1["valid"] is True
        assert result2["valid"] is True

    def test_no_freshness_check_in_verify_receipt(self, ctx, temp_dir, registry):
        """
        verify_receipt() does not check whether a receipt is recent.
        An arbitrarily old receipt passes verification without a freshness bound.

        EXPECTED: If verify_receipt() had a max_age parameter, old timestamps would fail.
        ACTUAL: verify_receipt() has no freshness checking. A receipt backdated to 2020
                still passes all cryptographic checks.

        THIS TEST DOCUMENTS A LIMITATION. See RED_TEAM_FINDINGS.md: Hole 5.
        """
        receipt = self._get_valid_receipt(ctx, temp_dir)

        # Backdating timestamps does NOT break the signature (timestamps are not in
        # the signing payload). This is a documentation test, not a tamper test.
        # The signature covers: receipt_id, intent_id, outcome_hash, before_state_hash, signed_at
        # "signed_at" IS in the payload, so changing it WOULD break the signature.
        # However, the declared_at and execution timestamps are NOT in the payload.

        tampered = copy.deepcopy(receipt)
        # Change declared_at (not in signing payload) to 2020
        tampered["phase_1"]["intent"]["declared_at"] = "2020-01-01T00:00:00Z"
        # Change started_at / completed_at (not in signing payload)
        tampered["phase_2"]["execution"]["started_at"] = "2020-01-01T00:00:00Z"
        tampered["phase_2"]["execution"]["completed_at"] = "2020-01-01T00:00:00Z"

        result = verify_receipt(tampered, registry)

        # These timestamps are not in the signing payload, so the signature still verifies.
        # The receipt passes all checks despite impossible timestamps.
        # This documents the limitation rather than asserting a failure.
        if result["valid"] is True:
            # Document: no freshness/timestamp ordering check is implemented
            assert result["checks"]["sequence_numbers_monotonic"] is True
            # Note: a complete implementation would reject timestamps in 2020
            # See RED_TEAM_FINDINGS.md: Hole 5 for the timestamp ordering gap
