"""Tests for receipt building, signing, and verification."""

import copy
import json
import os
from pathlib import Path

from arc import (
    ARCContext,
    rollback_filesystem,
    signed_tool,
)
from arc.receipt import verify_receipt
from arc.signing import sha256_hex


def test_full_receipt_creation(ctx, temp_dir):
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def read_file(path: str, ctx: ARCContext) -> dict:
        content = Path(path).read_text()
        return {"content": content, "length": len(content)}

    receipt = read_file(str(Path(temp_dir) / "file1.txt"), ctx=ctx)

    assert receipt["arc_version"] == "1.0"
    assert receipt["receipt_id"].startswith("arc_")
    assert "phase_1" in receipt
    assert "phase_2" in receipt
    assert receipt["phase_2"]["execution"]["outcome"] == "success"


def test_receipt_has_all_required_fields(ctx, temp_dir):
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def touch_file(path: str, ctx: ARCContext) -> dict:
        return {"path": path}

    receipt = touch_file(str(Path(temp_dir) / "file1.txt"), ctx=ctx)

    # Check top-level
    assert "arc_version" in receipt
    assert "receipt_id" in receipt
    assert "phase_1" in receipt
    assert "phase_2" in receipt

    # Check phase_1
    p1 = receipt["phase_1"]
    assert "intent" in p1
    assert "before_state" in p1
    assert "log_commitment" in p1

    # Check intent
    intent = p1["intent"]
    assert "intent_id" in intent
    assert "tool_name" in intent
    assert "reasoning_commitment" in intent
    assert intent["reasoning_commitment"].startswith("sha256:")

    # Check phase_2
    p2 = receipt["phase_2"]
    assert "execution" in p2
    assert "provider_attestation" in p2
    assert "log_proof" in p2


def test_provider_signature_valid(ctx, temp_dir):
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def read_file(path: str, ctx: ARCContext) -> dict:
        return {"content": Path(path).read_text()}

    receipt = read_file(str(Path(temp_dir) / "file1.txt"), ctx=ctx)
    provider_id = receipt["phase_2"]["provider_attestation"]["provider_id"]

    result = verify_receipt(receipt, {provider_id: ctx.provider_keypair.public_key_hex})
    assert result["valid"] is True
    assert result["checks"]["provider_signature_valid"] is True


def test_tampered_outcome_hash_fails_verification(ctx, temp_dir):
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def read_file(path: str, ctx: ARCContext) -> dict:
        return {"content": Path(path).read_text()}

    receipt = read_file(str(Path(temp_dir) / "file1.txt"), ctx=ctx)
    provider_id = receipt["phase_2"]["provider_attestation"]["provider_id"]

    tampered = copy.deepcopy(receipt)
    tampered["phase_2"]["execution"]["outcome_hash"] = sha256_hex(b"fabricated result")

    result = verify_receipt(tampered, {provider_id: ctx.provider_keypair.public_key_hex})
    assert result["valid"] is False
    assert result["checks"]["provider_signature_valid"] is False


def test_inverse_op_present_for_reversible(ctx, temp_dir):
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def delete_file(path: str, ctx: ARCContext) -> dict:
        os.remove(path)
        return {"deleted": path}

    file_path = str(Path(temp_dir) / "file1.txt")
    receipt = delete_file(file_path, ctx=ctx)

    assert "inverse" in receipt["phase_2"]
    assert receipt["phase_2"]["inverse"]["is_reversible"] is True
    assert "inverse_signature" in receipt["phase_2"]["inverse"]
    assert "inverse_tool" in receipt["phase_2"]["inverse"]


def test_rollback_restores_state(ctx, temp_dir):
    file_path = str(Path(temp_dir) / "file1.txt")
    original_content = Path(file_path).read_text()

    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def delete_file(path: str, ctx: ARCContext) -> dict:
        os.remove(path)
        return {"deleted": path}

    receipt = delete_file(file_path, ctx=ctx)
    assert not Path(file_path).exists()

    snap = ctx.snapshot_store.retrieve(
        receipt["phase_1"]["before_state"]["snapshot_ref"]
    )
    success = rollback_filesystem(snap)
    assert success is True
    assert Path(file_path).exists()
    assert Path(file_path).read_text() == original_content


def test_log_commitment_present(ctx, temp_dir):
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def read_file(path: str, ctx: ARCContext) -> dict:
        return {"content": Path(path).read_text()}

    receipt = read_file(str(Path(temp_dir) / "file1.txt"), ctx=ctx)

    lc = receipt["phase_1"]["log_commitment"]
    assert "log_id" in lc
    assert "sequence_number" in lc
    assert "merkle_root" in lc
    assert lc["merkle_root"].startswith("sha256:")

    lp = receipt["phase_2"]["log_proof"]
    assert lp["sequence_number"] > lc["sequence_number"]


def test_failed_tool_still_generates_receipt(ctx, temp_dir):
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def failing_tool(path: str, ctx: ARCContext) -> dict:
        raise RuntimeError("Simulated failure")

    receipt = failing_tool(str(Path(temp_dir) / "file1.txt"), ctx=ctx)

    assert receipt["phase_2"]["execution"]["outcome"] == "failure"
    assert receipt["phase_2"]["execution"]["error_code"] == "RuntimeError"
    assert "phase_1" in receipt
    assert "phase_2" in receipt


def test_receipt_id_format(ctx, temp_dir):
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def read_file(path: str, ctx: ARCContext) -> dict:
        return {}

    receipt = read_file(str(Path(temp_dir) / "file1.txt"), ctx=ctx)
    import re
    assert re.match(r"^arc_[0-9A-Z]{26}$", receipt["receipt_id"])
    assert re.match(r"^intent_[0-9A-Z]{26}$", receipt["phase_1"]["intent"]["intent_id"])


def test_schema_validation(ctx, temp_dir):
    """Receipt must pass JSON Schema validation."""
    import jsonschema
    schema_path = Path(__file__).parent.parent / "schemas" / "action-receipt.schema.json"
    schema = json.loads(schema_path.read_text())

    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def read_file(path: str, ctx: ARCContext) -> dict:
        return {"content": Path(path).read_text()}

    receipt = read_file(str(Path(temp_dir) / "file1.txt"), ctx=ctx)
    # Should not raise
    jsonschema.validate(receipt, schema)
