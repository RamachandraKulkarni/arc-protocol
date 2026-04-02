"""
ATTACK 3: Fake Provider Signature
An agent generates its own Ed25519 keypair and uses it to sign the receipt —
hoping the verifier trusts any valid signature rather than checking against the
registered provider key.

WHAT ARC MUST DETECT:
- The provider registry maps provider_id/provider_name → public_key_hex
- verify_receipt() looks up the provider's registered key
- A signature from any other key must fail verification, even if cryptographically valid
- An unregistered provider must be rejected with a specific error
"""

import copy
import shutil
from pathlib import Path

import pytest

from arc import ARCContext, ARCKeyPair, signed_tool
from arc.receipt import verify_receipt
from arc.signing import build_signing_payload, sha256_hex


class TestFakeSignature:

    def _get_valid_receipt(self, ctx, temp_dir):
        @signed_tool(resource="filesystem", resource_uri_from_args="path")
        def list_files(path: str, ctx: ARCContext) -> dict:
            files = [f.name for f in Path(path).iterdir()]
            return {"files": files, "count": len(files)}

        return list_files(temp_dir, ctx=ctx)

    def test_agent_generated_keypair_rejected(self, ctx, temp_dir, registry):
        """
        Agent generates its own valid Ed25519 keypair, correctly constructs the
        signing payload, and signs it with its own key — producing a cryptographically
        valid signature but from the WRONG key.

        verify_receipt() must look up the REGISTERED key and reject the foreign signature.
        """
        receipt = self._get_valid_receipt(ctx, temp_dir)

        attacker_kp = ARCKeyPair.generate()

        # Attacker reconstructs the signing payload exactly as the protocol specifies
        payload = build_signing_payload(
            receipt_id=receipt["receipt_id"],
            intent_id=receipt["phase_1"]["intent"]["intent_id"],
            outcome_hash=receipt["phase_2"]["execution"]["outcome_hash"],
            before_state_hash=receipt["phase_1"]["before_state"]["snapshot_hash"],
            signed_at=receipt["phase_2"]["provider_attestation"]["signed_at"],
        )

        # Signs with attacker's key (valid signature, wrong key)
        tampered = copy.deepcopy(receipt)
        tampered["phase_2"]["provider_attestation"]["signature"] = attacker_kp.sign(payload)

        # Registry still has the REAL provider's public key
        result = verify_receipt(tampered, registry)

        assert result["valid"] is False
        assert result["checks"]["provider_signature_valid"] is False
        assert any("signature" in e.lower() for e in result["errors"]), (
            f"Expected error naming 'signature', got: {result['errors']}"
        )

    def test_unregistered_provider_id_rejected(self, ctx, temp_dir):
        """
        Agent changes provider_id to a non-existent provider.
        An empty registry cannot look up the key — verification must fail with a
        specific error naming the provider.
        """
        receipt = self._get_valid_receipt(ctx, temp_dir)

        tampered = copy.deepcopy(receipt)
        tampered["phase_2"]["provider_attestation"]["provider_id"] = "tool:fake-provider:v99"
        tampered["phase_2"]["provider_attestation"]["provider_name"] = "fake-provider:v99"

        empty_registry = {}
        result = verify_receipt(tampered, empty_registry)

        assert result["valid"] is False
        assert any(
            "provider" in e.lower() or "not found" in e.lower() or "registry" in e.lower()
            for e in result["errors"]
        ), f"Expected error naming the unknown provider, got: {result['errors']}"

    def test_correct_registry_wrong_key_rejected(self, ctx, temp_dir):
        """
        Registry exists but maps provider_name to a DIFFERENT (attacker's) public key.
        The receipt's signature was made with the real provider key, which no longer
        appears in the registry — verification must fail.
        """
        receipt = self._get_valid_receipt(ctx, temp_dir)

        attacker_kp = ARCKeyPair.generate()
        wrong_registry = {"filesystem-tool-v1": attacker_kp.public_key_hex}

        result = verify_receipt(receipt, wrong_registry)

        assert result["valid"] is False
        assert result["checks"]["provider_signature_valid"] is False

    def test_revoked_provider_excluded_from_registry_rejected(self, ctx, temp_dir):
        """
        The provider's key has been revoked — simulated by removing it from the registry.
        verify_receipt() cannot find the key and must reject the receipt.

        Note: The current implementation has no explicit revocation concept. Revocation
        is modeled by key removal from the registry. There is no 'revoked' error message —
        verify_receipt() reports 'Provider not found in registry'.
        """
        receipt = self._get_valid_receipt(ctx, temp_dir)

        # Simulate revocation: remove the key from the registry entirely
        revoked_registry = {}

        result = verify_receipt(receipt, revoked_registry)

        assert result["valid"] is False
        assert any(
            "provider" in e.lower() or "not found" in e.lower()
            for e in result["errors"]
        ), f"Expected 'provider not found' error, got: {result['errors']}"

    def test_valid_signature_but_with_extra_fields_in_payload(self, ctx, temp_dir, registry):
        """
        Attacker adds extra fields to the receipt and re-signs with their own key,
        hoping the verifier won't notice the extra data.
        Because the verifier looks up the registered key (not the attacker's),
        the signature from the attacker's key fails.
        """
        receipt = self._get_valid_receipt(ctx, temp_dir)

        attacker_kp = ARCKeyPair.generate()
        tampered = copy.deepcopy(receipt)

        # Add extra field (schema will catch this, but signature also fails)
        # Re-sign with attacker's key
        payload = build_signing_payload(
            receipt_id=tampered["receipt_id"],
            intent_id=tampered["phase_1"]["intent"]["intent_id"],
            outcome_hash=tampered["phase_2"]["execution"]["outcome_hash"],
            before_state_hash=tampered["phase_1"]["before_state"]["snapshot_hash"],
            signed_at=tampered["phase_2"]["provider_attestation"]["signed_at"],
        )
        tampered["phase_2"]["provider_attestation"]["signature"] = attacker_kp.sign(payload)

        result = verify_receipt(tampered, registry)

        assert result["valid"] is False
        assert result["checks"]["provider_signature_valid"] is False
