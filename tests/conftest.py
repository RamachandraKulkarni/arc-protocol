import tempfile
from pathlib import Path

import pytest

from arc import ARCContext, ARCInMemoryLog, ARCKeyPair, SnapshotStore


@pytest.fixture
def provider_keypair() -> ARCKeyPair:
    return ARCKeyPair.generate()


@pytest.fixture
def log() -> ARCInMemoryLog:
    return ARCInMemoryLog()


@pytest.fixture
def snapshot_store() -> SnapshotStore:
    return SnapshotStore()


@pytest.fixture
def ctx(provider_keypair, log, snapshot_store) -> ARCContext:
    return ARCContext(
        agent_id="test-agent",
        model_version="test-model-v1",
        session_id="test-session-001",
        provider_keypair=provider_keypair,
        provider_name="test-tool-v1",
        log=log,
        snapshot_store=snapshot_store,
        on_behalf_of="user:test@example.com",
    )


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "file1.txt").write_text("important data 1")
        (Path(d) / "file2.txt").write_text("important data 2")
        (Path(d) / "config.json").write_text('{"key": "value"}')
        yield d
