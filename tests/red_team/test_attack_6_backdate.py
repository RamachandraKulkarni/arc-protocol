"""
ATTACK 6: Backdated Intent
An agent acts first, then manufactures a Phase 1 entry claiming it declared intent
before acting. Without this, the log would show Phase 2 without a matching Phase 1.

WHAT ARC MUST DETECT:
- Phase 1 entries must be committed BEFORE Phase 2 entries for the same receipt_id
- Timestamp declared_at must be before execution started_at
- Phase 1 sequence_number must be < Phase 2 sequence_number

HOLES FOUND (see RED_TEAM_FINDINGS.md):
- The log does NOT enforce Phase 1 before Phase 2 ordering per receipt_id (Hole 6)
- verify_receipt() does NOT check timestamp ordering (declared_at < started_at) (Hole 5)
"""

import copy
from pathlib import Path

from arc import ARCContext, signed_tool
from arc.ids import new_intent_id, new_receipt_id
from arc.log_client import ARCLogError
from arc.receipt import verify_receipt
from arc.signing import sha256_hex


class TestBackdatedIntent:
    def _get_valid_receipt(self, ctx, temp_dir):
        @signed_tool(resource="filesystem", resource_uri_from_args="path")
        def list_files(path: str, ctx: ARCContext) -> dict:
            return {"files": [f.name for f in Path(path).iterdir()]}

        return list_files(temp_dir, ctx=ctx)

    def _build_minimal_intent(self, receipt_id: str) -> dict:
        return {
            "intent_id": new_intent_id(),
            "tool_name": "fake_tool",
            "arguments": {},
            "declared_by": {
                "agent_id": "attacker",
                "model_version": "evil-v1",
                "session_id": "attack-session",
            },
            "reasoning_commitment": sha256_hex(b"fake reasoning"),
            "declared_at": "2026-01-01T00:00:00Z",
        }

    def test_intent_committed_after_receipt_rejected(self, log):
        """
        Normal flow: Phase 1 (intent), then Phase 2 (receipt).
        Attack: commit Phase 2 first (orphan receipt), then commit Phase 1 for same receipt_id.

        EXPECTED: The second commit of intent raises ARCLogError because a receipt
                  already exists for this receipt_id.
        ACTUAL: The log accepts both commits regardless of ordering  -  no ordering check.

        THIS TEST EXPOSES A HOLE. See RED_TEAM_FINDINGS.md: Hole 6.
        """
        receipt_id = new_receipt_id()

        # Build a minimal fake receipt (simplified  -  doesn't need to pass schema)
        fake_receipt = {
            "arc_version": "1.0",
            "receipt_id": receipt_id,
            "phase_1": {
                "intent": self._build_minimal_intent(receipt_id),
                "before_state": {
                    "resource_uri": "file:///test",
                    "resource_type": "filesystem:file",
                    "snapshot_hash": sha256_hex(b"test"),
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
                    "completed_at": "2026-01-01T00:00:02Z",
                    "duration_ms": 1000,
                    "outcome": "success",
                    "outcome_hash": sha256_hex(b"{}"),
                },
                "provider_attestation": {
                    "provider_id": "tool:test-provider",
                    "provider_name": "test-provider",
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

        # ATTACK: commit Phase 2 first
        log.commit_receipt(fake_receipt)

        # Now try to commit Phase 1 for the SAME receipt_id
        # Expected: rejected. Actual: accepted (hole).
        backdated_intent = self._build_minimal_intent(receipt_id)
        try:
            log.commit_intent(backdated_intent, receipt_id)
            orphan_accepted = True
        except ARCLogError:
            orphan_accepted = False

        # This assertion WILL FAIL  -  exposing the hole:
        assert not orphan_accepted, (
            "HOLE 6: The transparency log does not enforce Phase 1 before Phase 2 ordering "
            "per receipt_id. An agent can commit a receipt (Phase 2) first, then commit a "
            "backdated intent (Phase 1) for the same receipt_id. The log accepts both. "
            "See RED_TEAM_FINDINGS.md."
        )

    def test_declared_at_after_execution_flagged(self, ctx, temp_dir, registry):
        """
        The intent's declared_at timestamp is AFTER the execution's started_at.
        This is logically impossible  -  intent must precede action.

        EXPECTED: verify_receipt() returns valid=False naming timestamp ordering.
        ACTUAL: verify_receipt() does not check timestamp ordering at all.

        THIS TEST EXPOSES A HOLE. See RED_TEAM_FINDINGS.md: Hole 5.
        """
        receipt = self._get_valid_receipt(ctx, temp_dir)

        tampered = copy.deepcopy(receipt)
        # Move declared_at to AFTER execution completed
        tampered["phase_1"]["intent"]["declared_at"] = "2099-12-31T23:59:59Z"

        result = verify_receipt(tampered, registry)

        # This assertion WILL FAIL  -  exposing the hole:
        assert result["valid"] is False, (
            "HOLE 5: verify_receipt() does not check timestamp ordering. Setting "
            "declared_at to a time after execution does not fail verification. "
            "An agent could fabricate a pre-action intent timestamp retroactively. "
            "See RED_TEAM_FINDINGS.md."
        )
        assert any(
            "timestamp" in e.lower() or "ordering" in e.lower() or "declared_at" in e.lower()
            for e in result["errors"]
        )

    def test_phase1_sequence_after_phase2_sequence_flagged(self, ctx, temp_dir, registry):
        """
        The log_commitment.sequence_number in Phase 1 is HIGHER than Phase 2's.
        This proves Phase 1 was added to the log AFTER Phase 2  -  unambiguous backdating.

        ARC DETECTS THIS: verify_receipt() checks phase2_seq > phase1_seq.
        This is one of the checks that WORKS correctly.
        """
        receipt = self._get_valid_receipt(ctx, temp_dir)

        p1_seq = receipt["phase_1"]["log_commitment"]["sequence_number"]
        p2_seq = receipt["phase_2"]["log_proof"]["sequence_number"]
        assert p1_seq < p2_seq, "Sanity: Phase 1 must precede Phase 2 in valid receipt"

        # Tamper: give Phase 1 a sequence number higher than Phase 2
        tampered = copy.deepcopy(receipt)
        tampered["phase_1"]["log_commitment"]["sequence_number"] = p2_seq + 10
        tampered["phase_2"]["log_proof"]["sequence_number"] = p1_seq

        result = verify_receipt(tampered, registry)

        assert result["valid"] is False
        assert result["checks"]["sequence_numbers_monotonic"] is False
        assert (
            any("sequence" in e.lower() or "monoton" in e.lower() for e in result["errors"])
            or not result["checks"]["sequence_numbers_monotonic"]
        ), f"Expected error about sequence ordering, got: {result['errors']}"

    def test_valid_phase1_before_phase2_passes(self, ctx, temp_dir, registry):
        """
        Baseline: a legitimate receipt where Phase 1 strictly precedes Phase 2
        passes the sequence number monotonicity check.
        """
        receipt = self._get_valid_receipt(ctx, temp_dir)

        p1_seq = receipt["phase_1"]["log_commitment"]["sequence_number"]
        p2_seq = receipt["phase_2"]["log_proof"]["sequence_number"]

        assert p1_seq < p2_seq
        result = verify_receipt(receipt, registry)
        assert result["valid"] is True
        assert result["checks"]["sequence_numbers_monotonic"] is True
