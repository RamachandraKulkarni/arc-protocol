"""
Red team fixtures for adversarial ARC protocol testing.
"""

import copy
import shutil
from pathlib import Path

import pytest

from arc import ARCContext, ARCInMemoryLog, ARCKeyPair, SnapshotStore, signed_tool
from arc.log_client import ARCLogError
from arc.signing import build_signing_payload, canonical_json, sha256_hex


@pytest.fixture
def provider_kp():
    return ARCKeyPair.generate()


@pytest.fixture
def log():
    return ARCInMemoryLog()


@pytest.fixture
def store():
    return SnapshotStore()


@pytest.fixture
def ctx(provider_kp, log, store):
    return ARCContext(
        agent_id="test-adversarial-agent",
        model_version="test-model-v1",
        session_id="red-team-session-001",
        provider_keypair=provider_kp,
        provider_name="filesystem-tool-v1",
        log=log,
        snapshot_store=store,
        on_behalf_of="user:redteam@test.com",
    )


@pytest.fixture
def registry(provider_kp):
    """Minimal provider registry: provider_name → public_key_hex"""
    return {"filesystem-tool-v1": provider_kp.public_key_hex}


@pytest.fixture
def temp_dir(tmp_path):
    """A temp directory with known test files."""
    d = tmp_path / "test_data"
    d.mkdir()
    (d / "file1.txt").write_text("file one content — important data")
    (d / "file2.txt").write_text("file two content — also important")
    (d / "config.json").write_text('{"setting": "production_value"}')
    (d / "subdir").mkdir()
    (d / "subdir" / "nested.txt").write_text("nested file content")
    return str(d)


@pytest.fixture
def populated_log(log, tmp_path):
    """A log with 10+ committed entries for tamper testing."""
    d = tmp_path / "pop_data"
    d.mkdir()
    (d / "f.txt").write_text("x")

    # Commit 10 entries directly via the log interface
    from arc.ids import new_intent_id, new_receipt_id

    for i in range(10):
        rid = new_receipt_id()
        intent = {
            "intent_id": new_intent_id(),
            "tool_name": "noop",
            "arguments": {"i": i},
            "declared_by": {"agent_id": "test", "model_version": "v1", "session_id": "s1"},
            "reasoning_commitment": sha256_hex(f"reason {i}".encode()),
            "declared_at": "2026-01-01T00:00:00Z",
        }
        log.commit_intent(intent, rid)

    return log


def build_inverse_payload(receipt_id: str, inverse: dict) -> bytes:
    """Reconstruct the inverse signing payload (mirrors receipt.py logic)."""
    inv_payload_obj = {
        "inverse_arguments": inverse.get("inverse_arguments", {}),
        "inverse_tool": inverse.get("inverse_tool", ""),
        "receipt_id": receipt_id,
        "valid_until": inverse.get("valid_until", ""),
    }
    return sha256_hex(canonical_json(inv_payload_obj)).encode("utf-8")


class TamperHelper:
    """Utilities for constructing tampered receipts in tests."""

    @staticmethod
    def replace_outcome_hash(receipt: dict, fake_result: dict) -> dict:
        r = copy.deepcopy(receipt)
        r["phase_2"]["execution"]["outcome_hash"] = sha256_hex(canonical_json(fake_result))
        return r

    @staticmethod
    def replace_provider_signature(receipt: dict, fake_keypair: ARCKeyPair) -> dict:
        r = copy.deepcopy(receipt)
        payload = build_signing_payload(
            receipt_id=r["receipt_id"],
            intent_id=r["phase_1"]["intent"]["intent_id"],
            outcome_hash=r["phase_2"]["execution"]["outcome_hash"],
            before_state_hash=r["phase_1"]["before_state"]["snapshot_hash"],
            signed_at=r["phase_2"]["provider_attestation"]["signed_at"],
        )
        r["phase_2"]["provider_attestation"]["signature"] = fake_keypair.sign(payload)
        return r


@pytest.fixture
def tamper():
    return TamperHelper()
