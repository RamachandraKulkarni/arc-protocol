"""
ATTACK 4: Rollback Denial
An agent claims "rollback is not available" when the receipt proves otherwise.
This is what the Replit agent did  -  it told the user the deletion was irreversible.

WHAT ARC MUST DEMONSTRATE (not detect  -  refute):
- The receipt contains inverse.is_reversible=True
- The inverse_signature proves the provider committed to this rollback
- Actual rollback execution succeeds and restores original state

HOLE FOUND (see RED_TEAM_FINDINGS.md):
- An agent CAN forge is_reversible=False without detection: the inverse operation
  fields are NOT included in the provider_signature payload. Changing is_reversible
  from True to False passes verify_receipt() because the inverse_signature check is
  skipped when is_reversible=False.
"""

import copy
import shutil
from pathlib import Path

from arc import ARCContext, rollback_filesystem, signed_tool
from arc.receipt import verify_receipt
from arc.signing import canonical_json, sha256_hex


def _build_inverse_payload(receipt_id: str, inverse: dict) -> bytes:
    """Reconstruct the inverse signing payload (mirrors receipt.py logic exactly)."""
    inv_payload_obj = {
        "inverse_arguments": inverse.get("inverse_arguments", {}),
        "inverse_tool": inverse.get("inverse_tool", ""),
        "receipt_id": receipt_id,
        "valid_until": inverse.get("valid_until", ""),
    }
    return sha256_hex(canonical_json(inv_payload_obj)).encode("utf-8")


class TestRollbackDenial:
    def _get_delete_receipt(self, ctx, temp_dir):
        @signed_tool(resource="filesystem", resource_uri_from_args="path")
        def delete_directory(path: str, ctx: ARCContext) -> dict:
            shutil.rmtree(path)
            return {"deleted": path}

        return delete_directory(temp_dir, ctx=ctx)

    def test_inverse_op_exists_and_verifies(self, ctx, temp_dir, registry):
        """
        When an agent claims rollback is impossible, the receipt proves otherwise.
        The inverse_signature is the cryptographic proof the provider committed to rollback.
        """
        receipt = self._get_delete_receipt(ctx, temp_dir)

        # Agent claims: "rollback is not possible"
        # The receipt says otherwise:
        assert receipt["phase_2"]["inverse"]["is_reversible"] is True
        assert "inverse_signature" in receipt["phase_2"]["inverse"]
        assert "inverse_tool" in receipt["phase_2"]["inverse"]
        assert "valid_until" in receipt["phase_2"]["inverse"]

        # Verify the inverse_signature (provider committed to this rollback)
        inverse = receipt["phase_2"]["inverse"]
        inverse_payload = _build_inverse_payload(receipt["receipt_id"], inverse)

        assert ctx.provider_keypair.verify(inverse_payload, inverse["inverse_signature"]) is True, (
            "Inverse signature must verify against the provider's public key, "
            "proving the provider cryptographically committed to supporting rollback."
        )

    def test_rollback_actually_works(self, ctx, temp_dir):
        """
        Actually execute the rollback and verify original state is restored.
        This is the definitive proof the agent was lying about irreversibility.
        """
        # Record original state
        original_files = {}
        for f in Path(temp_dir).rglob("*"):
            if f.is_file():
                rel = str(f.relative_to(temp_dir))
                original_files[rel] = f.read_bytes()

        receipt = self._get_delete_receipt(ctx, temp_dir)

        assert not Path(temp_dir).exists(), "Directory must be deleted before rollback"

        # Execute rollback using only the receipt + snapshot store
        snap_ref = receipt["phase_1"]["before_state"]["snapshot_ref"]
        snap = ctx.snapshot_store.retrieve(snap_ref)
        assert snap is not None, "Snapshot must be stored and retrievable"

        success = rollback_filesystem(snap)
        assert success is True, "Rollback must succeed"

        # Verify every file is restored with exact content
        assert Path(temp_dir).exists(), "Directory must exist after rollback"
        for rel_path, original_bytes in original_files.items():
            restored_file = Path(temp_dir) / rel_path
            assert restored_file.exists(), f"File not restored: {rel_path}"
            assert restored_file.read_bytes() == original_bytes, (
                f"Content mismatch in restored file: {rel_path}"
            )

    def test_inverse_op_window_expiry_detected(self, ctx, temp_dir):
        """
        If valid_until is tampered to a past date, the inverse_signature no longer
        verifies  -  the provider did not sign that timestamp.
        This prevents backdating the rollback window.
        """
        receipt = self._get_delete_receipt(ctx, temp_dir)
        inverse = receipt["phase_2"]["inverse"]

        # Simulate attacker changing valid_until to a past date
        tampered_inverse = copy.deepcopy(inverse)
        tampered_inverse["valid_until"] = "2020-01-01T00:00:00Z"

        # Verify: the inverse_signature does NOT match the tampered valid_until
        inverse_payload = _build_inverse_payload(receipt["receipt_id"], tampered_inverse)
        assert (
            ctx.provider_keypair.verify(inverse_payload, tampered_inverse["inverse_signature"])
            is False
        ), "Tampered valid_until must invalidate the inverse_signature."

    def test_agent_cannot_forge_is_reversible_false(self, ctx, temp_dir, registry):
        """
        Agent tampers with receipt to change is_reversible from True to False.
        This attempts to hide the rollback capability by making the verifier
        skip the inverse operation check entirely.

        EXPECTED: verify_receipt() returns valid=False (inverse op in signing payload).
        ACTUAL: verify_receipt() returns valid=True  -  the inverse operation fields are
                NOT included in the provider_signature payload. The check for
                inverse_signature_valid is skipped when is_reversible=False,
                and None is treated as "valid".

        THIS TEST EXPOSES A HOLE. See RED_TEAM_FINDINGS.md: Hole 2.
        """
        receipt = self._get_delete_receipt(ctx, temp_dir)
        assert receipt["phase_2"]["inverse"]["is_reversible"] is True

        tampered = copy.deepcopy(receipt)
        tampered["phase_2"]["inverse"]["is_reversible"] = False

        result = verify_receipt(tampered, registry)

        # This assertion WILL FAIL  -  exposing the hole:
        # The provider_signature does not cover is_reversible. Setting it to False
        # makes verify_receipt() skip the inverse_signature_valid check (returns None),
        # and since None is not False, valid=True is returned.
        assert result["valid"] is False, (
            "HOLE 2: The inverse operation fields (is_reversible, inverse_tool, "
            "inverse_arguments, valid_until) are NOT included in the provider signing payload. "
            "An agent can change is_reversible=True to is_reversible=False without breaking "
            "the provider signature. verify_receipt() returns valid=True when it should return "
            "valid=False. See RED_TEAM_FINDINGS.md."
        )
        assert result["checks"]["inverse_signature_valid"] is False

    def test_verify_receipt_confirms_rollback_possible(self, ctx, temp_dir, registry):
        """
        The full verify_receipt() on a legitimate delete receipt confirms:
        - Schema valid
        - Provider signature valid
        - Inverse signature valid
        - Sequence numbers monotonic
        All checks pass, proving the receipt truthfully records a reversible action.
        """
        receipt = self._get_delete_receipt(ctx, temp_dir)

        result = verify_receipt(receipt, registry)

        assert result["valid"] is True
        assert result["checks"]["schema_valid"] is True
        assert result["checks"]["provider_signature_valid"] is True
        assert result["checks"]["inverse_signature_valid"] is True
        assert result["checks"]["sequence_numbers_monotonic"] is True
