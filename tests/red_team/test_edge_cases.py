"""
Edge cases and boundary conditions.
These test inputs that are technically valid but exercise limits the builder may not have tested.
"""

import threading
import time

import pytest

from arc import (
    ARCContext,
    ARCKeyPair,
    rollback_filesystem,
    signed_tool,
)
from arc.log_client import ARCInMemoryLog
from arc.receipt import verify_receipt
from arc.signing import canonical_json
from arc.snapshot import SnapshotStore, capture_filesystem


class TestEdgeCases:

    def test_empty_arguments_dict(self, ctx, tmp_path):
        """Tool called with no arguments beyond ctx  -  receipt still generated."""
        @signed_tool(resource="dict")
        def noop(ctx: ARCContext) -> dict:
            return {"done": True}

        receipt = noop(ctx=ctx)
        assert receipt["arc_version"] == "1.0"
        assert receipt["receipt_id"].startswith("arc_")
        assert receipt["phase_2"]["execution"]["outcome"] == "success"

    def test_very_large_arguments(self, ctx, tmp_path):
        """Arguments with 1MB of data  -  receipt generation completes without error."""
        large_data = "x" * (1024 * 1024)

        @signed_tool(resource="dict", resource_uri_from_args="key")
        def process_large(key: str, data: str, ctx: ARCContext) -> dict:
            return {"length": len(data)}

        receipt = process_large("big-key", large_data, ctx=ctx)
        assert receipt["phase_2"]["execution"]["outcome"] == "success"

    def test_unicode_in_arguments(self, ctx, tmp_path):
        """
        Arguments contain Unicode (Chinese, Arabic, emoji).
        canonical_json must handle multi-byte characters correctly.
        """
        @signed_tool(resource="dict", resource_uri_from_args="key")
        def unicode_tool(key: str, value: str, ctx: ARCContext) -> dict:
            return {"processed": value, "len": len(value)}

        unicode_value = "你好世界 مرحبا بالعالم 🌍 ñoño"
        receipt = unicode_tool("unicode-key", unicode_value, ctx=ctx)
        assert receipt["phase_2"]["execution"]["outcome"] == "success"

        # Verify canonical_json handles unicode correctly (deterministic)
        obj = {"key": unicode_value, "n": 1}
        b1 = canonical_json(obj)
        b2 = canonical_json(obj)
        assert b1 == b2

    def test_deeply_nested_arguments(self, ctx, tmp_path):
        """
        Arguments nested 10 levels deep  -  hashing and serialization correct.
        """
        nested = {"level": 0}
        current = nested
        for i in range(1, 10):
            current["child"] = {"level": i}
            current = current["child"]

        @signed_tool(resource="dict", resource_uri_from_args="key")
        def nested_tool(key: str, data: dict, ctx: ARCContext) -> dict:
            return {"received": True}

        receipt = nested_tool("nested-key", nested, ctx=ctx)
        assert receipt["phase_2"]["execution"]["outcome"] == "success"

    def test_receipt_id_uniqueness_across_100_calls(self, ctx, tmp_path):
        """Generate 100 receipts rapidly  -  all receipt_ids must be globally unique."""
        @signed_tool(resource="dict")
        def quick_noop(ctx: ARCContext) -> dict:
            return {"ok": True}

        receipts = [quick_noop(ctx=ctx) for _ in range(100)]
        ids = [r["receipt_id"] for r in receipts]
        assert len(set(ids)) == 100, (
            f"Collision detected among {len(ids)} receipt IDs"
        )

    def test_concurrent_tool_calls(self, tmp_path):
        """
        Two @signed_tool calls running concurrently  -  both receipts valid, no ID collision.
        Thread safety of the Merkle tree and log must hold.
        """
        kp = ARCKeyPair.generate()
        log = ARCInMemoryLog()
        store = SnapshotStore()
        ctx1 = ARCContext(
            agent_id="agent-1", model_version="v1", session_id="s1",
            provider_keypair=kp, provider_name="tool-v1",
            log=log, snapshot_store=store,
        )
        ctx2 = ARCContext(
            agent_id="agent-2", model_version="v1", session_id="s2",
            provider_keypair=kp, provider_name="tool-v1",
            log=log, snapshot_store=store,
        )

        @signed_tool(resource="dict")
        def slow_noop(ctx: ARCContext) -> dict:
            time.sleep(0.01)
            return {"ok": True}

        receipts = []
        errors = []

        def run(c):
            try:
                receipts.append(slow_noop(ctx=c))
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=run, args=(ctx1,))
        t2 = threading.Thread(target=run, args=(ctx2,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert not errors, f"Concurrent calls raised: {errors}"
        assert len(receipts) == 2
        assert receipts[0]["receipt_id"] != receipts[1]["receipt_id"]

        registry = {"tool-v1": kp.public_key_hex}
        for r in receipts:
            result = verify_receipt(r, registry)
            assert result["valid"] is True, f"Concurrent receipt invalid: {result['errors']}"

    def test_tool_raises_exception_still_generates_receipt(self, ctx, tmp_path):
        """
        When the tool raises, outcome=failure and receipt is still committed.
        Failed actions must be logged  -  this is a core protocol guarantee.
        """
        @signed_tool(resource="dict")
        def always_fails(ctx: ARCContext) -> dict:
            raise ValueError("intentional test failure")

        receipt = always_fails(ctx=ctx)

        assert receipt["phase_2"]["execution"]["outcome"] == "failure"
        assert receipt["phase_2"]["execution"]["error_code"] == "ValueError"
        assert "intentional test failure" in receipt["phase_2"]["execution"]["error_message"]
        assert receipt["receipt_id"].startswith("arc_")

    def test_snapshot_of_empty_directory(self, ctx, tmp_path):
        """
        Snapshot of an empty directory  -  valid snapshot, rollback recreates empty dir.
        """
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        store = SnapshotStore()
        snap = capture_filesystem(str(empty_dir), store)

        assert snap.is_reversible is True
        assert snap.snapshot_hash.startswith("sha256:")

        # Delete the directory
        empty_dir.rmdir()
        assert not empty_dir.exists()

        # Rollback recreates the empty directory
        success = rollback_filesystem(snap)
        assert success is True
        assert empty_dir.exists()
        assert empty_dir.is_dir()

    def test_verify_receipt_with_empty_registry(self, ctx, tmp_path):
        """
        verify_receipt() with empty registry  -  must fail with specific error,
        not crash with an unhandled exception.
        """
        @signed_tool(resource="dict")
        def noop(ctx: ARCContext) -> dict:
            return {"ok": True}

        receipt = noop(ctx=ctx)
        result = verify_receipt(receipt, {})

        assert result["valid"] is False
        assert isinstance(result["errors"], list)
        assert len(result["errors"]) > 0
        assert any(
            "provider" in e.lower() or "not found" in e.lower() or "registry" in e.lower()
            for e in result["errors"]
        ), f"Expected registry error, got: {result['errors']}"

    def test_verify_receipt_with_none_registry_value(self, ctx, tmp_path, registry):
        """
        verify_receipt() handles a registry where the key maps to None  -  must fail
        gracefully, not raise AttributeError or TypeError.
        """
        @signed_tool(resource="dict")
        def noop(ctx: ARCContext) -> dict:
            return {"ok": True}

        receipt = noop(ctx=ctx)
        broken_registry = {"filesystem-tool-v1": None}
        # This should not raise  -  it should return valid=False
        try:
            result = verify_receipt(receipt, broken_registry)
            assert result["valid"] is False
        except Exception as e:
            pytest.fail(
                f"verify_receipt() raised {type(e).__name__} with None registry value: {e}"
            )

    def test_rollback_of_missing_file_does_not_crash(self, tmp_path):
        """
        Rollback is called for a file that was never present in the snapshot
        (absent resource type). Must return True or False cleanly, not raise.
        """
        store = SnapshotStore()
        absent_path = str(tmp_path / "never_existed.txt")
        snap = capture_filesystem(absent_path, store)

        # Rollback of an absent file: no-op or graceful failure
        try:
            success = rollback_filesystem(snap)
            assert isinstance(success, bool)
        except Exception as e:
            pytest.fail(f"rollback_filesystem raised {type(e).__name__}: {e}")

    def test_snapshot_hash_is_deterministic(self, tmp_path):
        """
        Two snapshots of the same content produce the same snapshot_hash.
        Determinism is required for before-state integrity verification.
        """
        test_file = tmp_path / "deterministic.txt"
        test_file.write_text("identical content")

        store1 = SnapshotStore()
        store2 = SnapshotStore()

        snap1 = capture_filesystem(str(test_file), store1)
        snap2 = capture_filesystem(str(test_file), store2)

        assert snap1.snapshot_hash == snap2.snapshot_hash, (
            "Same content must produce same snapshot_hash (determinism required for verification)"
        )

    def test_receipt_format_is_stable_across_calls(self, ctx, tmp_path, registry):
        """
        Two receipts from the same type of call have the same structure
        (same keys at every level), just different values.
        """
        @signed_tool(resource="dict")
        def noop(ctx: ARCContext) -> dict:
            return {"ok": True}

        def get_keys(d: dict, prefix: str = "") -> set:
            keys = set()
            for k, v in d.items():
                full = f"{prefix}.{k}" if prefix else k
                keys.add(full)
                if isinstance(v, dict):
                    keys |= get_keys(v, full)
            return keys

        r1 = noop(ctx=ctx)
        r2 = noop(ctx=ctx)

        keys1 = get_keys(r1)
        keys2 = get_keys(r2)

        assert keys1 == keys2, (
            f"Receipt structure differs between calls:\n"
            f"Only in r1: {keys1 - keys2}\n"
            f"Only in r2: {keys2 - keys1}"
        )

    def test_sequence_numbers_monotonically_increase_across_receipts(self, ctx, tmp_path):
        """
        Log sequence numbers must always increase. No receipt can claim a sequence
        number lower than what already exists in the log.
        """
        @signed_tool(resource="dict")
        def noop(ctx: ARCContext) -> dict:
            return {"ok": True}

        receipts = [noop(ctx=ctx) for _ in range(5)]
        p1_seqs = [r["phase_1"]["log_commitment"]["sequence_number"] for r in receipts]
        p2_seqs = [r["phase_2"]["log_proof"]["sequence_number"] for r in receipts]

        all_seqs = sorted(p1_seqs + p2_seqs)
        assert all_seqs == list(range(len(all_seqs))), (
            f"Sequence numbers must be 0..N with no gaps, got: {all_seqs}"
        )
