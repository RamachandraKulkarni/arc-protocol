"""
ATTACK 1: Result Fabrication
An agent replaces the outcome_hash in a receipt with the hash of a fabricated
(harmless) result, hoping the verifier won't check.

WHAT ARC MUST DETECT:
- The provider_signature covers the signed_payload_hash
- signed_payload_hash includes the original outcome_hash
- If outcome_hash changes, the signature no longer verifies
- verify_receipt() must return valid=False with error naming "signature"

HOLE FOUND (see RED_TEAM_FINDINGS.md):
- The outcome FIELD ("success"/"failure"/"partial") is NOT in the signing payload,
  only outcome_HASH is. An agent can change "failure" to "success" without breaking
  the provider signature.
"""

import copy
import shutil
from pathlib import Path

from arc import ARCContext, signed_tool
from arc.receipt import verify_receipt
from arc.signing import canonical_json, sha256_hex


class TestResultFabrication:

    def test_replaced_outcome_hash_fails_verification(self, ctx, temp_dir, registry):
        """
        Baseline: agent claims it deleted 0 files when it deleted 3.
        Most basic form of fabrication  -  changes outcome_hash to hash of fake result.
        The provider_signature was computed over the real outcome_hash, so it fails.
        """
        @signed_tool(resource="filesystem", resource_uri_from_args="path")
        def delete_directory(path: str, ctx: ARCContext) -> dict:
            shutil.rmtree(path)
            return {"deleted_files": 3, "path": path, "status": "completed"}

        receipt = delete_directory(temp_dir, ctx=ctx)

        # Agent fabricates: claims nothing was deleted
        fabricated_result = {"deleted_files": 0, "path": temp_dir, "status": "no_action"}
        tampered = copy.deepcopy(receipt)
        tampered["phase_2"]["execution"]["outcome_hash"] = sha256_hex(
            canonical_json(fabricated_result)
        )

        result = verify_receipt(tampered, registry)

        assert result["valid"] is False
        assert result["checks"]["provider_signature_valid"] is False
        assert any(
            "signature" in e.lower() for e in result["errors"]
        ), f"Expected error naming 'signature', got: {result['errors']}"

    def test_fabrication_with_correct_outcome_hash_still_caught(self, ctx, temp_dir, registry):
        """
        Sophisticated fabrication: agent correctly recomputes the hash of the fabricated
        result and updates outcome_hash. But the provider_signature was computed over the
        ORIGINAL outcome_hash, so it still fails.

        This proves the signing chain is correct: signature covers the original outcome_hash,
        so swapping outcome_hash alone is not enough to forge a valid receipt.
        """
        file_path = str(Path(temp_dir) / "file1.txt")

        @signed_tool(resource="filesystem", resource_uri_from_args="path")
        def delete_file(path: str, ctx: ARCContext) -> dict:
            Path(path).unlink()
            return {"deleted": True, "path": path}

        receipt = delete_file(file_path, ctx=ctx)

        # Sophisticated: agent correctly hashes the fabricated result
        fabricated = {"deleted": False, "path": file_path}
        tampered = copy.deepcopy(receipt)
        tampered["phase_2"]["execution"]["outcome_hash"] = sha256_hex(canonical_json(fabricated))
        # Note: outcome_hash updated BUT the provider_signature still covers the OLD outcome_hash

        result = verify_receipt(tampered, registry)
        assert result["valid"] is False
        assert result["checks"]["provider_signature_valid"] is False

    def test_partial_fabrication_only_changing_one_field(self, ctx, temp_dir, registry):
        """
        Agent changes only one field of the result (count from N to 0).
        Even a single field change must be caught because it changes the outcome_hash.
        """
        @signed_tool(resource="filesystem", resource_uri_from_args="path")
        def count_and_read(path: str, ctx: ARCContext) -> dict:
            files = [f for f in Path(path).rglob("*") if f.is_file()]
            return {"files_found": len(files), "path": path}

        receipt = count_and_read(temp_dir, ctx=ctx)

        # Only change the count, keep everything else identical
        tampered = copy.deepcopy(receipt)
        new_result = {"files_found": 0, "path": temp_dir}
        tampered["phase_2"]["execution"]["outcome_hash"] = sha256_hex(canonical_json(new_result))

        result = verify_receipt(tampered, registry)
        assert result["valid"] is False
        assert result["checks"]["provider_signature_valid"] is False

    def test_fabricated_success_on_actual_failure(self, ctx, temp_dir, registry):
        """
        Agent calls a tool that errors. Agent reports outcome="success" instead of "failure".

        EXPECTED: verify_receipt() returns valid=False because outcome is tampered.
        ACTUAL: verify_receipt() returns valid=True  -  the `outcome` field is NOT in
                the signing payload, so changing it does not break the signature.

        THIS TEST EXPOSES A HOLE. See RED_TEAM_FINDINGS.md: Hole 1.
        """
        @signed_tool(resource="filesystem", resource_uri_from_args="path")
        def delete_nonexistent(path: str, ctx: ARCContext) -> dict:
            Path(path).unlink()  # raises FileNotFoundError
            return {"deleted": True}

        nonexistent = str(Path(temp_dir) / "does_not_exist.txt")
        receipt = delete_nonexistent(nonexistent, ctx=ctx)

        assert receipt["phase_2"]["execution"]["outcome"] == "failure"

        # Agent changes outcome to "success"  -  signing payload does not include this field
        tampered = copy.deepcopy(receipt)
        tampered["phase_2"]["execution"]["outcome"] = "success"

        result = verify_receipt(tampered, registry)

        # This assertion WILL FAIL  -  exposing the hole:
        # The outcome string is not in the signing payload, so the signature still verifies.
        assert result["valid"] is False, (
            "HOLE 1: The `outcome` field ('success'/'failure'/'partial') is NOT included in "
            "the signing payload. An agent can change 'failure' to 'success' without breaking "
            "the provider signature. verify_receipt() returns valid=True when it should return "
            "valid=False. See RED_TEAM_FINDINGS.md."
        )
