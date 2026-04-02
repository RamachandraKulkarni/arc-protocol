"""
Full end-to-end tests for the ARC protocol.
Reproduces the Replit scenario: delete directory, detect fabrication, rollback.
"""

import copy
import shutil
import tempfile
from pathlib import Path

import pytest

from arc import (
    ARCContext,
    ARCInMemoryLog,
    ARCKeyPair,
    SnapshotStore,
    rollback_filesystem,
    signed_tool,
)
from arc.receipt import verify_receipt
from arc.signing import canonical_json, sha256_hex


@pytest.fixture
def disaster_temp_dir():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "report.txt").write_text("Q1 2026 Financial Report\nRevenue: $4.2M")
        (Path(d) / "config.json").write_text('{"database": "prod", "version": "2.1.0"}')
        (Path(d) / "users.csv").write_text("id,name,email\n1,Alice,alice@co.com\n2,Bob,bob@co.com")
        yield d


def test_full_disaster_scenario(disaster_temp_dir):
    """
    Reproduce the Replit scenario end-to-end.
    Agent deletes directory → receipt captured → fabrication detected → rollback succeeds.
    """
    provider_kp = ARCKeyPair.generate()
    log = ARCInMemoryLog()
    store = SnapshotStore()
    ctx = ARCContext(
        agent_id="test-agent",
        model_version="test-model-v1",
        session_id="test-session-disaster",
        provider_keypair=provider_kp,
        provider_name="filesystem-tool-v1",
        log=log,
        snapshot_store=store,
        on_behalf_of="user:test@example.com",
    )

    # 1. Record original state
    original_files = [f for f in Path(disaster_temp_dir).rglob("*") if f.is_file()]
    assert len(original_files) == 3

    # 2. Execute destructive action with ARC
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def delete_directory(path: str, ctx: ARCContext) -> dict:
        files = [str(f) for f in Path(path).rglob("*") if f.is_file()]
        shutil.rmtree(path)
        return {"deleted": path, "files_removed": len(files)}

    receipt = delete_directory(disaster_temp_dir, ctx=ctx)

    # 3. Verify directory is gone
    assert not Path(disaster_temp_dir).exists()

    # 4. Receipt should be valid
    provider_id = receipt["phase_2"]["provider_attestation"]["provider_id"]
    verification = verify_receipt(receipt, {provider_id: provider_kp.public_key_hex})
    assert verification["valid"] is True

    # 5. SIMULATE: Agent fabricates "nothing was deleted"
    fabricated_result = {"deleted": "none", "files_removed": 0}
    fabricated_hash = sha256_hex(canonical_json(fabricated_result))

    tampered = copy.deepcopy(receipt)
    tampered["phase_2"]["execution"]["outcome_hash"] = fabricated_hash

    fabrication_check = verify_receipt(tampered, {provider_id: provider_kp.public_key_hex})
    assert fabrication_check["valid"] is False
    assert fabrication_check["checks"]["provider_signature_valid"] is False

    # 6. SIMULATE: Agent claims "rollback impossible"
    # But the receipt says otherwise:
    assert receipt["phase_2"]["inverse"]["is_reversible"] is True
    assert "inverse_signature" in receipt["phase_2"]["inverse"]

    # Verify inverse signature
    inv_check = verify_receipt(receipt, {provider_id: provider_kp.public_key_hex})
    assert inv_check["checks"]["inverse_signature_valid"] is True

    # 7. Execute rollback using inverse op + snapshot
    snap = store.retrieve(receipt["phase_1"]["before_state"]["snapshot_ref"])
    assert snap is not None
    success = rollback_filesystem(snap)

    # 8. Verify restoration
    assert success is True
    assert Path(disaster_temp_dir).exists()
    restored_files = [f for f in Path(disaster_temp_dir).rglob("*") if f.is_file()]
    assert len(restored_files) == len(original_files)

    # Verify file contents are identical
    for orig_file in original_files:
        restored = Path(disaster_temp_dir) / orig_file.name
        assert restored.exists(), f"File {orig_file.name} not restored"
        assert restored.read_bytes() == orig_file.read_bytes()

    # 9. Verify log consistency
    log_check = log.verify_consistency()
    assert log_check["is_consistent"] is True

    # 10. SIMULATE: Agent tampers with log
    log.tamper_entry(0, "merkle_root", "sha256:" + "f" * 64)
    tamper_check = log.verify_consistency()
    assert tamper_check["is_consistent"] is False


def test_phase1_committed_before_execution():
    """Phase 1 must be in the log before Phase 2."""
    log = ARCInMemoryLog()
    store = SnapshotStore()
    ctx = ARCContext(
        agent_id="agent",
        model_version="v1",
        session_id="sess",
        provider_keypair=ARCKeyPair.generate(),
        provider_name="tool-v1",
        log=log,
        snapshot_store=store,
    )

    @signed_tool(resource="dict")
    def my_tool(ctx: ARCContext) -> dict:
        return {"done": True}

    receipt = my_tool(ctx=ctx)

    p1_seq = receipt["phase_1"]["log_commitment"]["sequence_number"]
    p2_seq = receipt["phase_2"]["log_proof"]["sequence_number"]
    assert p1_seq < p2_seq


def test_reasoning_commitment_is_hash_of_reasoning(ctx, temp_dir):
    """The reasoning_commitment in phase_1 must be SHA-256 of actual reasoning."""
    test_reasoning = "User asked me to read file for analysis"

    @signed_tool(
        resource="filesystem",
        resource_uri_from_args="path",
        reasoning=test_reasoning,
    )
    def read_file(path: str, ctx: ARCContext) -> dict:
        return {}

    receipt = read_file(str(Path(temp_dir) / "file1.txt"), ctx=ctx)
    commitment = receipt["phase_1"]["intent"]["reasoning_commitment"]
    expected = sha256_hex(test_reasoning.encode("utf-8"))
    assert commitment == expected


def test_snapshot_hash_integrity(ctx, temp_dir):
    """snapshot_hash in before_state must match actual snapshot content."""
    from arc.signing import canonical_json, sha256_hex

    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def read_file(path: str, ctx: ARCContext) -> dict:
        return {}

    receipt = read_file(str(Path(temp_dir) / "file1.txt"), ctx=ctx)
    snap_ref = receipt["phase_1"]["before_state"]["snapshot_ref"]
    snap = ctx.snapshot_store.retrieve(snap_ref)
    assert snap is not None

    expected_hash = sha256_hex(canonical_json(snap.content))
    assert receipt["phase_1"]["before_state"]["snapshot_hash"] == expected_hash


def test_multiple_sequential_receipts(ctx, temp_dir):
    """Multiple tool calls should generate distinct receipts with monotonic sequences."""

    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def read_file(path: str, ctx: ARCContext) -> dict:
        return {}

    r1 = read_file(str(Path(temp_dir) / "file1.txt"), ctx=ctx)
    r2 = read_file(str(Path(temp_dir) / "file2.txt"), ctx=ctx)

    assert r1["receipt_id"] != r2["receipt_id"]
    # Phase 1 of r2 must come after Phase 2 of r1
    r1_p2_seq = r1["phase_2"]["log_proof"]["sequence_number"]
    r2_p1_seq = r2["phase_1"]["log_commitment"]["sequence_number"]
    assert r2_p1_seq > r1_p2_seq
