"""
@signed_tool decorator and ARCContext  -  the primary user-facing API.
Wraps any function with full ARC two-phase receipt protocol.
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
from typing import Any

from arc.receipt import ReceiptBuilder
from arc.signing import ARCKeyPair, sha256_hex
from arc.snapshot import SnapshotStore, capture_api_response, capture_dict, capture_filesystem


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class ARCContext:
    """Runtime context injected into signed_tool calls."""

    agent_id: str
    model_version: str
    session_id: str
    provider_keypair: ARCKeyPair
    provider_name: str
    log: Any  # ARCInMemoryLog | ARCLogClient
    snapshot_store: SnapshotStore
    on_behalf_of: str | None = None
    last_receipt: dict | None = None
    reasoning_store: dict = field(default_factory=dict)  # {reasoning_hash: reasoning_text}


def signed_tool(
    resource: str,
    resource_uri_from_args: str | None = None,
    rollback_valid_minutes: int = 60,
    capture_args: list[str] | None = None,
    reasoning: str = "Tool execution via ARC protocol",
):
    """
    Decorator that wraps a function with full ARC protocol execution.

    Parameters:
        resource: resource type  -  "filesystem", "dict", "api", "custom"
        resource_uri_from_args: name of the kwarg/arg that contains the resource path/URI
        rollback_valid_minutes: how long the inverse op is valid
        capture_args: which args to include in snapshot context
        reasoning: default reasoning text (can be overridden in context)

    The decorator:
    1. Captures before-state from the resource
    2. Calls declare_intent (Phase 1)  -  committed to log
    3. Calls the wrapped function
    4. Signs and commits Phase 2 (attestation)
    5. Returns the complete ActionReceipt dict

    If the wrapped function raises, outcome="failure" and receipt is still generated.
    The ARCContext is passed as keyword argument 'ctx'.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            ctx: ARCContext = kwargs.get("ctx") or (args[-1] if args and isinstance(args[-1], ARCContext) else None)
            if ctx is None:
                raise ValueError("ARCContext must be passed as 'ctx' keyword argument")

            # Extract resource URI from arguments
            resource_uri = _extract_resource_uri(func, args, kwargs, resource_uri_from_args)

            # Build arguments dict for receipt (exclude ctx)
            call_args = _build_args_dict(func, args, kwargs)

            # Capture before-state
            snapshot = _capture_before_state(resource, resource_uri, call_args, ctx.snapshot_store)

            # Build receipt builder
            builder = ReceiptBuilder(
                agent_id=ctx.agent_id,
                model_version=ctx.model_version,
                session_id=ctx.session_id,
                log=ctx.log,
            )

            # Determine reasoning
            tool_reasoning = reasoning

            # Phase 1: declare intent
            receipt_id, phase1 = builder.declare_intent(
                tool_name=func.__name__,
                arguments=call_args,
                snapshot=snapshot,
                reasoning=tool_reasoning,
                on_behalf_of=ctx.on_behalf_of,
            )

            # Store reasoning
            from arc.signing import sha256_hex
            reasoning_hash = sha256_hex(tool_reasoning.encode("utf-8"))
            ctx.reasoning_store[reasoning_hash] = tool_reasoning

            # Execute the tool
            started_at = _now_iso()
            start_ns = time.perf_counter_ns()
            outcome = "success"
            result: dict = {}
            error_code = None
            error_message = None

            try:
                raw_result = func(*args, **kwargs)
                if asyncio.iscoroutine(raw_result):
                    raw_result = asyncio.get_event_loop().run_until_complete(raw_result)
                if isinstance(raw_result, dict):
                    result = raw_result
                else:
                    result = {"result": raw_result}
            except Exception as e:
                outcome = "failure"
                error_code = type(e).__name__
                error_message = str(e)
                result = {"error": error_message}

            completed_at = _now_iso()
            duration_ms = (time.perf_counter_ns() - start_ns) // 1_000_000

            # Build inverse operation parameters
            is_reversible = snapshot.is_reversible
            inverse_tool = None
            inverse_arguments = None
            if is_reversible and outcome != "failure":
                inverse_tool = "restore_snapshot"
                inverse_arguments = {
                    "snapshot_ref": snapshot.snapshot_ref,
                    "resource_uri": snapshot.resource_uri,
                }

            # Phase 2: attest execution
            full_receipt = builder.attest_execution(
                receipt_id=receipt_id,
                provider_keypair=ctx.provider_keypair,
                provider_name=ctx.provider_name,
                outcome=outcome,
                result=result,
                phase1=phase1,
                is_reversible=is_reversible and outcome != "failure",
                inverse_tool=inverse_tool,
                inverse_arguments=inverse_arguments,
                rollback_valid_minutes=rollback_valid_minutes,
                error_code=error_code,
                error_message=error_message,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

            ctx.last_receipt = full_receipt
            return full_receipt

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            ctx: ARCContext = kwargs.get("ctx") or (args[-1] if args and isinstance(args[-1], ARCContext) else None)
            if ctx is None:
                raise ValueError("ARCContext must be passed as 'ctx' keyword argument")

            resource_uri = _extract_resource_uri(func, args, kwargs, resource_uri_from_args)
            call_args = _build_args_dict(func, args, kwargs)
            snapshot = _capture_before_state(resource, resource_uri, call_args, ctx.snapshot_store)

            builder = ReceiptBuilder(
                agent_id=ctx.agent_id,
                model_version=ctx.model_version,
                session_id=ctx.session_id,
                log=ctx.log,
            )

            tool_reasoning = reasoning
            receipt_id, phase1 = builder.declare_intent(
                tool_name=func.__name__,
                arguments=call_args,
                snapshot=snapshot,
                reasoning=tool_reasoning,
                on_behalf_of=ctx.on_behalf_of,
            )

            reasoning_hash = sha256_hex(tool_reasoning.encode("utf-8"))
            ctx.reasoning_store[reasoning_hash] = tool_reasoning

            started_at = _now_iso()
            start_ns = time.perf_counter_ns()
            outcome = "success"
            result: dict = {}
            error_code = None
            error_message = None

            try:
                raw_result = await func(*args, **kwargs)
                if isinstance(raw_result, dict):
                    result = raw_result
                else:
                    result = {"result": raw_result}
            except Exception as e:
                outcome = "failure"
                error_code = type(e).__name__
                error_message = str(e)
                result = {"error": error_message}

            completed_at = _now_iso()
            duration_ms = (time.perf_counter_ns() - start_ns) // 1_000_000

            is_reversible = snapshot.is_reversible
            inverse_tool = None
            inverse_arguments = None
            if is_reversible and outcome != "failure":
                inverse_tool = "restore_snapshot"
                inverse_arguments = {
                    "snapshot_ref": snapshot.snapshot_ref,
                    "resource_uri": snapshot.resource_uri,
                }

            full_receipt = builder.attest_execution(
                receipt_id=receipt_id,
                provider_keypair=ctx.provider_keypair,
                provider_name=ctx.provider_name,
                outcome=outcome,
                result=result,
                phase1=phase1,
                is_reversible=is_reversible and outcome != "failure",
                inverse_tool=inverse_tool,
                inverse_arguments=inverse_arguments,
                rollback_valid_minutes=rollback_valid_minutes,
                error_code=error_code,
                error_message=error_message,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

            ctx.last_receipt = full_receipt
            return full_receipt

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator


def _extract_resource_uri(func, args, kwargs, resource_uri_from_args: str | None) -> str | None:
    """Extract the resource URI from function arguments."""
    if resource_uri_from_args is None:
        return None

    # Try kwargs first
    if resource_uri_from_args in kwargs:
        return str(kwargs[resource_uri_from_args])

    # Try positional args using function signature
    import inspect
    try:
        sig = inspect.signature(func)
        param_names = list(sig.parameters.keys())
        idx = param_names.index(resource_uri_from_args)
        if idx < len(args):
            return str(args[idx])
    except (ValueError, TypeError):
        pass

    return None


def _build_args_dict(func, args, kwargs) -> dict:
    """Build a dict of all arguments passed to the function (excluding ctx)."""
    import inspect
    result = {}
    try:
        sig = inspect.signature(func)
        param_names = list(sig.parameters.keys())
        for i, arg in enumerate(args):
            if i < len(param_names):
                name = param_names[i]
                if name != "ctx" and not isinstance(arg, ARCContext):
                    result[name] = str(arg) if not isinstance(arg, (str, int, float, bool, list, dict)) else arg
    except Exception:
        pass

    for k, v in kwargs.items():
        if k != "ctx" and not isinstance(v, ARCContext):
            result[k] = str(v) if not isinstance(v, (str, int, float, bool, list, dict)) else v

    return result


def _capture_before_state(resource: str, resource_uri: str | None, call_args: dict, store: SnapshotStore):
    """Capture before-state based on resource type."""
    if resource == "filesystem" and resource_uri:
        return capture_filesystem(resource_uri, store)
    elif resource == "dict":
        key = resource_uri or "anonymous"
        return capture_dict(key, call_args, store)
    elif resource == "api" and resource_uri:
        return capture_api_response(resource_uri, call_args, store)
    else:
        # Custom or unknown: capture args as dict snapshot
        key = resource_uri or resource or "custom"
        return capture_dict(key, call_args, store)
