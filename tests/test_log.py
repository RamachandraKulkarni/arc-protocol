"""Tests for the ARCInMemoryLog."""



def test_commit_intent_returns_commitment(log):
    intent = {
        "intent_id": "intent_01JTXM9KP3FABCDE12345678AB",
        "tool_name": "test_tool",
        "arguments": {},
        "declared_by": {
            "agent_id": "agent-1",
            "model_version": "v1",
            "session_id": "sess-1",
        },
        "reasoning_commitment": "sha256:" + "a" * 64,
        "declared_at": "2026-04-02T00:00:00Z",
    }
    commitment = log.commit_intent(intent, "arc_01JTXM9KP3FABCDE12345678AB")
    assert "log_id" in commitment
    assert "sequence_number" in commitment
    assert commitment["sequence_number"] == 0
    assert "merkle_root" in commitment
    assert commitment["merkle_root"].startswith("sha256:")


def test_sequence_numbers_increment(log):
    receipt_id = "arc_01JTXM9KP3FABCDE12345678AB"
    intent = {
        "intent_id": "intent_01JTXM9KP3FABCDE12345678AB",
        "tool_name": "test_tool",
        "arguments": {},
        "declared_by": {"agent_id": "a", "model_version": "v1", "session_id": "s"},
        "reasoning_commitment": "sha256:" + "a" * 64,
        "declared_at": "2026-04-02T00:00:00Z",
    }
    c1 = log.commit_intent(intent, receipt_id)
    assert c1["sequence_number"] == 0

    receipt = {
        "arc_version": "1.0",
        "receipt_id": receipt_id,
        "phase_1": {
            "intent": intent,
            "before_state": {
                "resource_uri": "file:///test",
                "resource_type": "filesystem:file",
                "snapshot_hash": "sha256:" + "b" * 64,
                "captured_at": "2026-04-02T00:00:00Z",
            },
            "log_commitment": c1,
        },
        "phase_2": {
            "execution": {
                "started_at": "2026-04-02T00:00:00Z",
                "completed_at": "2026-04-02T00:00:01Z",
                "duration_ms": 100,
                "outcome": "success",
                "outcome_hash": "sha256:" + "c" * 64,
            },
            "provider_attestation": {
                "provider_id": "tool:test-v1",
                "provider_name": "test-v1",
                "signed_at": "2026-04-02T00:00:01Z",
                "signature": "ed25519:" + "A" * 86 + "==",
                "signed_payload_hash": "sha256:" + "d" * 64,
            },
            "log_proof": c1,
        },
    }
    c2 = log.commit_receipt(receipt)
    assert c2["sequence_number"] == 1


def test_verify_finds_entries(log):
    receipt_id = "arc_01JTXM9KP3FABCDE12345678AB"
    intent = {
        "intent_id": "intent_01JTXM9KP3FABCDE12345678AB",
        "tool_name": "test_tool",
        "arguments": {},
        "declared_by": {"agent_id": "a", "model_version": "v1", "session_id": "s"},
        "reasoning_commitment": "sha256:" + "a" * 64,
        "declared_at": "2026-04-02T00:00:00Z",
    }
    log.commit_intent(intent, receipt_id)
    result = log.verify(receipt_id)
    assert result["found"] is True
    assert result["intent_committed"] is True


def test_verify_unknown_receipt_id(log):
    result = log.verify("arc_ZZZZZZZZZZZZZZZZZZZZZZZZZZ")
    assert result["found"] is False


def test_consistency_after_tamper(log):
    receipt_id = "arc_01JTXM9KP3FABCDE12345678AB"
    intent = {
        "intent_id": "intent_01JTXM9KP3FABCDE12345678AB",
        "tool_name": "test_tool",
        "arguments": {},
        "declared_by": {"agent_id": "a", "model_version": "v1", "session_id": "s"},
        "reasoning_commitment": "sha256:" + "a" * 64,
        "declared_at": "2026-04-02T00:00:00Z",
    }
    log.commit_intent(intent, receipt_id)
    log.commit_intent(intent, receipt_id)  # second entry

    # Consistency check before tamper
    result = log.verify_consistency()
    assert result["is_consistent"] is True

    # Tamper with entry 0's merkle_root
    log.tamper_entry(0, "merkle_root", "sha256:" + "f" * 64)

    # Now consistency check should detect the break
    result = log.verify_consistency()
    assert result["is_consistent"] is False
