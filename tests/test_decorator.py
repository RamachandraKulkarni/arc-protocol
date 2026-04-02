"""Tests for @signed_tool decorator and ARCContext."""

import os
from pathlib import Path

import pytest

from arc import ARCContext, signed_tool


def test_decorator_returns_receipt(ctx, temp_dir):
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def list_files(path: str, ctx: ARCContext) -> dict:
        files = list(Path(path).iterdir())
        return {"count": len(files)}

    receipt = list_files(temp_dir, ctx=ctx)
    assert "arc_version" in receipt
    assert "receipt_id" in receipt


def test_decorator_sets_last_receipt(ctx, temp_dir):
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def list_files(path: str, ctx: ARCContext) -> dict:
        return {"count": 1}

    assert ctx.last_receipt is None
    list_files(temp_dir, ctx=ctx)
    assert ctx.last_receipt is not None


def test_decorator_captures_tool_name(ctx, temp_dir):
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def my_custom_tool(path: str, ctx: ARCContext) -> dict:
        return {}

    receipt = my_custom_tool(temp_dir, ctx=ctx)
    assert receipt["phase_1"]["intent"]["tool_name"] == "my_custom_tool"


def test_decorator_captures_arguments(ctx, temp_dir):
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def process_file(path: str, ctx: ARCContext) -> dict:
        return {}

    receipt = process_file(temp_dir, ctx=ctx)
    assert "path" in receipt["phase_1"]["intent"]["arguments"]


def test_decorator_failure_still_creates_receipt(ctx, temp_dir):
    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def failing(path: str, ctx: ARCContext) -> dict:
        raise ValueError("intentional failure")

    receipt = failing(temp_dir, ctx=ctx)
    assert receipt["phase_2"]["execution"]["outcome"] == "failure"
    assert receipt["phase_2"]["execution"]["error_code"] == "ValueError"


def test_decorator_on_behalf_of(temp_dir):
    from arc import ARCInMemoryLog, ARCKeyPair, SnapshotStore

    ctx = ARCContext(
        agent_id="agent-1",
        model_version="v1",
        session_id="sess-1",
        provider_keypair=ARCKeyPair.generate(),
        provider_name="tool-v1",
        log=ARCInMemoryLog(),
        snapshot_store=SnapshotStore(),
        on_behalf_of="user:alice@example.com",
    )

    @signed_tool(resource="filesystem", resource_uri_from_args="path")
    def read(path: str, ctx: ARCContext) -> dict:
        return {}

    receipt = read(temp_dir, ctx=ctx)
    assert receipt["phase_1"]["intent"].get("on_behalf_of") == "user:alice@example.com"


def test_decorator_dict_resource(ctx):
    data = {"users": [{"id": 1, "name": "Alice"}]}

    @signed_tool(resource="dict", resource_uri_from_args="key")
    def update_data(key: str, ctx: ARCContext) -> dict:
        return {"updated": True}

    receipt = update_data("my_key", ctx=ctx)
    assert receipt["phase_2"]["execution"]["outcome"] == "success"


def test_decorator_without_ctx_raises():
    @signed_tool(resource="dict")
    def my_tool() -> dict:
        return {}

    with pytest.raises((ValueError, TypeError)):
        my_tool()
