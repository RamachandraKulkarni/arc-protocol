"""
Two-phase receipt builder and verifier for ARC protocol.
Phase 1: declare_intent (pre-action, snapshot captured, committed to log)
Phase 2: attest_execution (post-execution, signed, committed to log)
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path

import jsonschema

from arc.ids import new_receipt_id, new_intent_id
from arc.signing import (
    ARCKeyPair,
    build_signing_payload,
    canonical_json,
    sha256_hex,
    verify_with_public_key_hex,
)
from arc.snapshot import Snapshot


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_schema() -> dict:
    """Load the action-receipt schema for validation."""
    schema_path = Path(__file__).parent.parent.parent / "schemas" / "action-receipt.schema.json"
    if schema_path.exists():
        with open(schema_path) as f:
            return json.load(f)
    return {}


@dataclass
class ReceiptBuilder:
    """
    Orchestrates the two-phase receipt creation.

    Usage:
        builder = ReceiptBuilder(
            agent_id="claude-sonnet-4-6",
            model_version="claude-sonnet-4-6-20250514",
            session_id="session_abc",
            log=log,
        )
        phase1 = builder.declare_intent(...)
        result = tool.execute(...)
        receipt = builder.attest_execution(...)
    """

    agent_id: str
    model_version: str
    session_id: str
    log: object  # ARCInMemoryLog or ARCLogClient

    def declare_intent(
        self,
        tool_name: str,
        arguments: dict,
        snapshot: Snapshot,
        reasoning: str,
        on_behalf_of: str | None = None,
        authorization_scope: list[str] | None = None,
        parent_receipt_id: str | None = None,
    ) -> dict:
        """
        Build Phase 1, commit to log, return (receipt_id, phase_1 dict).
        Returns a tuple: (receipt_id, phase_1_dict)
        """
        receipt_id = new_receipt_id()
        intent_id = new_intent_id()
        declared_at = _now_iso()

        reasoning_bytes = reasoning.encode("utf-8")
        reasoning_commitment = sha256_hex(reasoning_bytes)

        intent = {
            "intent_id": intent_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "declared_by": {
                "agent_id": self.agent_id,
                "model_version": self.model_version,
                "session_id": self.session_id,
            },
            "reasoning_commitment": reasoning_commitment,
            "declared_at": declared_at,
        }
        if on_behalf_of:
            intent["on_behalf_of"] = on_behalf_of
        if authorization_scope or parent_receipt_id:
            auth: dict = {}
            if authorization_scope:
                auth["scope"] = authorization_scope
            if parent_receipt_id:
                auth["parent_receipt_id"] = parent_receipt_id
            intent["authorization"] = auth

        before_state = {
            "resource_uri": snapshot.resource_uri,
            "resource_type": snapshot.resource_type,
            "snapshot_ref": snapshot.snapshot_ref,
            "snapshot_hash": snapshot.snapshot_hash,
            "snapshot_size_bytes": snapshot.snapshot_size_bytes,
            "captured_at": snapshot.captured_at,
            "is_reversible": snapshot.is_reversible,
        }

        # Commit intent to log  -  returns LogCommitment
        log_commitment = self.log.commit_intent(intent, receipt_id)

        phase_1 = {
            "intent": intent,
            "before_state": before_state,
            "log_commitment": log_commitment,
        }

        return receipt_id, phase_1

    def attest_execution(
        self,
        receipt_id: str,
        provider_keypair: ARCKeyPair,
        provider_name: str,
        outcome: str,
        result: dict,
        phase1: dict,
        is_reversible: bool = True,
        inverse_tool: str | None = None,
        inverse_arguments: dict | None = None,
        rollback_valid_minutes: int = 60,
        error_code: str | None = None,
        error_message: str | None = None,
        started_at: str | None = None,
        completed_at: str | None = None,
        duration_ms: int = 0,
    ) -> dict:
        """
        Build Phase 2, sign with provider keypair, commit to log.
        Returns the complete ActionReceipt dict.
        """
        now = _now_iso()
        if not completed_at:
            completed_at = now
        if not started_at:
            started_at = completed_at

        result_bytes = canonical_json(result)
        outcome_hash = sha256_hex(result_bytes)

        before_state_hash = phase1["before_state"]["snapshot_hash"]
        intent_id = phase1["intent"]["intent_id"]
        signed_at = _now_iso()

        # Provider signs the canonical payload (7-field: includes outcome + is_reversible)
        signing_payload = build_signing_payload(
            receipt_id=receipt_id,
            intent_id=intent_id,
            outcome_hash=outcome_hash,
            before_state_hash=before_state_hash,
            signed_at=signed_at,
            outcome=outcome,
            is_reversible=is_reversible,
        )
        signature = provider_keypair.sign(signing_payload)
        signed_payload_hash = sha256_hex(signing_payload)

        provider_id = f"tool:{provider_name}"

        execution: dict = {
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_ms": duration_ms,
            "outcome": outcome,
            "outcome_hash": outcome_hash,
        }
        if error_code:
            execution["error_code"] = error_code
        if error_message:
            execution["error_message"] = error_message

        provider_attestation = {
            "provider_id": provider_id,
            "provider_name": provider_name,
            "signed_at": signed_at,
            "signature": signature,
            "signed_payload_hash": signed_payload_hash,
        }

        phase_2: dict = {
            "execution": execution,
            "provider_attestation": provider_attestation,
        }

        # Build inverse operation if reversible
        if is_reversible and inverse_tool and inverse_arguments is not None:
            valid_until = (
                datetime.now(timezone.utc) + timedelta(minutes=rollback_valid_minutes)
            ).isoformat().replace("+00:00", "Z")

            inv_payload_obj = {
                "inverse_arguments": inverse_arguments,
                "inverse_tool": inverse_tool,
                "receipt_id": receipt_id,
                "valid_until": valid_until,
            }
            inv_payload = sha256_hex(canonical_json(inv_payload_obj)).encode("utf-8")
            inverse_signature = provider_keypair.sign(inv_payload)

            phase_2["inverse"] = {
                "is_reversible": True,
                "inverse_tool": inverse_tool,
                "inverse_arguments": inverse_arguments,
                "valid_until": valid_until,
                "inverse_signature": inverse_signature,
            }
        elif not is_reversible:
            phase_2["inverse"] = {"is_reversible": False}

        receipt = {
            "arc_version": "1.0",
            "receipt_id": receipt_id,
            "phase_1": phase1,
            "phase_2": phase_2,
        }

        # Commit full receipt to log
        log_proof = self.log.commit_receipt(receipt)
        receipt["phase_2"]["log_proof"] = log_proof

        return receipt


def verify_receipt(receipt: dict, provider_registry: dict[str, str]) -> dict:
    """
    Verify a receipt's cryptographic integrity.

    provider_registry: {provider_id: public_key_hex} OR {provider_name: public_key_hex}

    Returns:
    {
        "valid": bool,
        "checks": { ... },
        "errors": [str]
    }
    """
    errors = []
    checks: dict = {
        "schema_valid": False,
        "provider_signature_valid": False,
        "inverse_signature_valid": None,
        "outcome_hash_matches": None,
        "sequence_numbers_monotonic": False,
    }

    # Schema validation
    try:
        schema = _load_schema()
        if schema:
            jsonschema.validate(receipt, schema)
        checks["schema_valid"] = True
    except jsonschema.ValidationError as e:
        errors.append(f"Schema validation failed: {e.message}")
    except Exception as e:
        errors.append(f"Schema loading error: {e}")
        checks["schema_valid"] = True  # Don't fail on schema load error

    # Provider signature verification
    try:
        phase2 = receipt.get("phase_2", {})
        attestation = phase2.get("provider_attestation", {})
        provider_id = attestation.get("provider_id", "")
        provider_name = attestation.get("provider_name", "")
        signature = attestation.get("signature", "")
        signed_at = attestation.get("signed_at", "")

        # Look up public key by provider_id or provider_name
        public_key_hex = (
            provider_registry.get(provider_id)
            or provider_registry.get(provider_name)
            or provider_registry.get(f"tool:{provider_name}")
        )

        if not public_key_hex:
            errors.append(f"Provider not found in registry: {provider_id} / {provider_name}")
        else:
            receipt_id = receipt.get("receipt_id", "")
            phase1 = receipt.get("phase_1", {})
            intent_id = phase1.get("intent", {}).get("intent_id", "")
            outcome_hash = phase2.get("execution", {}).get("outcome_hash", "")
            before_state_hash = phase1.get("before_state", {}).get("snapshot_hash", "")

            outcome_val = phase2.get("execution", {}).get("outcome", "")
            is_reversible_val = receipt.get("phase_2", {}).get("inverse", {}).get("is_reversible", False)

            signing_payload = build_signing_payload(
                receipt_id=receipt_id,
                intent_id=intent_id,
                outcome_hash=outcome_hash,
                before_state_hash=before_state_hash,
                signed_at=signed_at,
                outcome=outcome_val,
                is_reversible=is_reversible_val,
            )

            if verify_with_public_key_hex(signing_payload, signature, public_key_hex):
                checks["provider_signature_valid"] = True
            else:
                errors.append("Provider signature verification failed")
    except Exception as e:
        errors.append(f"Provider signature check error: {e}")

    # Inverse operation signature verification.
    # Three cases:
    # 1. is_reversible=True + inverse_signature present  → verify it
    # 2. is_reversible=False + inverse_signature present → structural inconsistency,
    #    flag as False (agent set is_reversible=False to hide a provider-signed rollback)
    # 3. No inverse_signature                           → not applicable (None)
    try:
        inverse = phase2.get("inverse")
        inv_sig = inverse.get("inverse_signature", "") if inverse else ""
        is_reversible_flag = inverse.get("is_reversible", False) if inverse else False

        if inverse and inv_sig and is_reversible_flag:
            # Case 1: normal reversible receipt  -  verify the inverse signature
            receipt_id = receipt.get("receipt_id", "")
            inv_payload_obj = {
                "inverse_arguments": inverse.get("inverse_arguments", {}),
                "inverse_tool": inverse.get("inverse_tool", ""),
                "receipt_id": receipt_id,
                "valid_until": inverse.get("valid_until", ""),
            }
            inv_payload = sha256_hex(canonical_json(inv_payload_obj)).encode("utf-8")

            public_key_hex = (
                provider_registry.get(provider_id)
                or provider_registry.get(provider_name)
                or provider_registry.get(f"tool:{provider_name}")
            )
            if public_key_hex:
                checks["inverse_signature_valid"] = verify_with_public_key_hex(
                    inv_payload, inv_sig, public_key_hex
                )
                if not checks["inverse_signature_valid"]:
                    errors.append("Inverse operation signature verification failed")
            else:
                checks["inverse_signature_valid"] = None
        elif inverse and inv_sig and not is_reversible_flag:
            # Case 2: is_reversible=False but inverse_signature is still present  - 
            # structurally inconsistent. Provider signed a reversible inverse op, but
            # the receipt claims non-reversible. This is a tampered receipt.
            checks["inverse_signature_valid"] = False
            errors.append(
                "Inverse signature present but is_reversible=False: "
                "structural inconsistency  -  possible rollback denial tampering."
            )
        else:
            # Case 3: no inverse_signature  -  not applicable
            checks["inverse_signature_valid"] = None
    except Exception as e:
        errors.append(f"Inverse signature check error: {e}")

    # Sequence number monotonicity check
    try:
        phase1_seq = receipt.get("phase_1", {}).get("log_commitment", {}).get("sequence_number")
        phase2_seq = receipt.get("phase_2", {}).get("log_proof", {}).get("sequence_number")
        if phase1_seq is not None and phase2_seq is not None:
            checks["sequence_numbers_monotonic"] = phase2_seq > phase1_seq
            if not checks["sequence_numbers_monotonic"]:
                errors.append(
                    f"Sequence ordering violated: Phase 1 sequence ({phase1_seq}) "
                    f">= Phase 2 sequence ({phase2_seq}). "
                    "Phase 1 was committed after Phase 2  -  backdating detected."
                )
        else:
            checks["sequence_numbers_monotonic"] = False
            errors.append("Missing sequence numbers in log commitments")
    except Exception as e:
        errors.append(f"Sequence number check error: {e}")

    # Timestamp ordering check: declared_at must be <= execution started_at
    try:
        declared_at = receipt.get("phase_1", {}).get("intent", {}).get("declared_at", "")
        started_at = receipt.get("phase_2", {}).get("execution", {}).get("started_at", "")
        if declared_at and started_at:
            if declared_at > started_at:
                checks["timestamp_ordering"] = False
                errors.append(
                    f"Timestamp ordering violated: declared_at ({declared_at}) "
                    f"is AFTER execution started_at ({started_at}). "
                    "Possible backdated intent."
                )
            else:
                checks["timestamp_ordering"] = True
    except Exception as e:
        errors.append(f"Timestamp ordering check error: {e}")

    valid = (
        checks["schema_valid"]
        and checks["provider_signature_valid"]
        and checks["sequence_numbers_monotonic"]
        and (checks["inverse_signature_valid"] is not False)
        and checks.get("timestamp_ordering", True)
        and len(errors) == 0
    )

    return {
        "valid": valid,
        "checks": checks,
        "errors": errors,
    }
