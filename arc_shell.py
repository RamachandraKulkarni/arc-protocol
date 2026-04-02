#!/usr/bin/env python3
"""
arc_shell.py  -  ARC Protocol Shell Wrapper

Wraps any shell command with full ARC proof-of-execution protocol.
Used by Claude Code, Codex, or any AI agent to make their tool calls verifiable.

Usage:
    python arc_shell.py "command here"
    python arc_shell.py "cat file.txt"
    python arc_shell.py "echo 'content' > output.txt"
    python arc_shell.py "rm -rf ./temp_dir"

What it does:
    1. Detects which files the command will touch
    2. Captures before-state of those files (snapshot)
    3. Commits Phase 1 (intent) to the ARC transparency log
    4. Runs the actual command
    5. Signs Phase 2 receipt (outcome + inverse op)
    6. Commits receipt to log
    7. Prints command output normally (agent sees real output)
    8. Appends RECEIPT:<id> to receipts.log (for later verification)

Environment variables:
    ARC_LOG_URL      Log server URL (default: http://localhost:8080)
    ARC_AGENT_ID     Agent identifier (default: detected from $USER + hostname)
    ARC_SESSION_ID   Session ID (default: generated once per process)
    ARC_PROVIDER_KEY Path to Ed25519 private key hex file (default: ~/.arc/provider.key)
    ARC_RECEIPTS_LOG Path to receipts log file (default: ./receipts.log)
    ARC_ON_BEHALF_OF Human user this agent acts for (default: $USER)
"""

import sys
import os
import re
import subprocess
import json
import hashlib
import socket
import time
from pathlib import Path
from datetime import datetime, timezone

# ── Try to import ARC. If not installed, print helpful error. ──────────────────
try:
    from arc import (
        ARCKeyPair,
        ARCLogClient,
        ARCInMemoryLog,
        SnapshotStore,
        sha256_hex,
    )
    from arc.ids import new_receipt_id, new_intent_id, new_snapshot_id
    from arc.signing import canonical_json, build_signing_payload, build_inverse_signing_payload
    from arc.snapshot import capture_filesystem, capture_dict, rollback_filesystem, Snapshot
    from arc.receipt import ReceiptBuilder
except ImportError:
    print(
        "ERROR: arc-protocol not installed. Run: pip install -e /path/to/arc-protocol",
        file=sys.stderr,
    )
    sys.exit(1)


# ── Configuration ──────────────────────────────────────────────────────────────

LOG_URL      = os.environ.get("ARC_LOG_URL", "http://localhost:8080")
AGENT_ID     = os.environ.get("ARC_AGENT_ID", f"agent@{socket.gethostname()}")
SESSION_ID   = os.environ.get("ARC_SESSION_ID", f"session_{int(time.time())}")
ON_BEHALF_OF = os.environ.get("ARC_ON_BEHALF_OF", os.environ.get("USER", "unknown"))
RECEIPTS_LOG = os.environ.get("ARC_RECEIPTS_LOG", "./receipts.log")
KEY_PATH     = os.environ.get("ARC_PROVIDER_KEY", os.path.expanduser("~/.arc/provider.key"))


# ── Key management ─────────────────────────────────────────────────────────────

def load_or_create_keypair(key_path: str) -> ARCKeyPair:
    """Load provider keypair from file, or generate and save a new one."""
    p = Path(key_path)
    if p.exists():
        return ARCKeyPair.from_private_key_hex(p.read_text().strip())
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        kp = ARCKeyPair.generate()
        p.write_text(kp.private_key_hex)
        p.chmod(0o600)
        print(f"[ARC] Generated new provider keypair → {key_path}", file=sys.stderr)
        print(f"[ARC] Public key: {kp.public_key_hex}", file=sys.stderr)
        return kp


# ── Resource detection ─────────────────────────────────────────────────────────

def detect_resource_paths(command: str) -> list[str]:
    """
    Heuristic: extract file paths from a shell command.
    Looks for:
      - Arguments that look like paths (start with / . ~ or contain /)
      - Redirection targets (> file, >> file, < file)
      - Common command patterns (cat X, cp X Y, mv X Y, rm X, echo > X)
    Returns list of absolute paths that exist OR might be created.
    """
    paths = []

    # Redirection targets
    for m in re.finditer(r"[>]{1,2}\s+([^\s;|&]+)", command):
        paths.append(m.group(1))

    # Standard path-like arguments
    tokens = re.split(r"\s+", command)
    skip_next = False
    skip_flags = {"-n", "-f", "-r", "-rf", "-p", "-v", "--output", "-o"}
    for i, token in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue
        if token.startswith("-"):
            if token in skip_flags:
                skip_next = True
            continue
        if i == 0:
            continue  # skip the command itself
        if (token.startswith("/") or
                token.startswith("./") or
                token.startswith("../") or
                token.startswith("~") or
                ("/" in token and not token.startswith("http"))):
            paths.append(token)

    # Expand ~ and make absolute
    resolved = []
    for p in paths:
        expanded = os.path.expanduser(p)
        if not os.path.isabs(expanded):
            expanded = os.path.join(os.getcwd(), expanded)
        resolved.append(expanded)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for p in resolved:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return unique


def detect_resource_type(path: str) -> str:
    """Return ARC resource_type for a path."""
    p = Path(path)
    if p.is_dir():
        return "filesystem:directory"
    elif p.is_file():
        return "filesystem:file"
    else:
        # Doesn't exist yet  -  will be created
        return "filesystem:file"


def infer_is_destructive(command: str) -> bool:
    """Return True if command likely modifies or deletes files."""
    cmd = command.strip().lower()
    destructive_verbs = ["rm", "rmdir", "mv", "cp", "echo", "printf", "tee",
                          "truncate", "dd", "install", "chmod", "chown", "touch",
                          "mkdir", "write", "sed", "awk", "python", "node"]
    first_token = cmd.split()[0] if cmd.split() else ""
    has_redirect = ">" in command
    return first_token in destructive_verbs or has_redirect


# ── Before-state capture ───────────────────────────────────────────────────────

def capture_before_states(paths: list[str], store: SnapshotStore) -> list[dict]:
    """
    Capture before-state for each detected path.
    Returns list of before_state dicts for embedding in Phase 1.
    If path doesn't exist, records that as the before-state (empty).
    """
    before_states = []
    for path in paths[:3]:  # limit to 3 resources per command for demo
        if Path(path).exists():
            snap = capture_filesystem(path, store)
        else:
            # File doesn't exist yet  -  create a "null" snapshot
            snap = Snapshot(
                snapshot_ref=new_snapshot_id(),
                resource_uri=f"file://{path}",
                resource_type="filesystem:file",
                content={"exists": False, "path": path},
                snapshot_hash=sha256_hex(canonical_json({"exists": False, "path": path})),
                snapshot_size_bytes=0,
                captured_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                is_reversible=True,
            )
            store.store(snap)

        before_states.append({
            "resource_uri": snap.resource_uri,
            "resource_type": snap.resource_type,
            "snapshot_ref": snap.snapshot_ref,
            "snapshot_hash": snap.snapshot_hash,
            "snapshot_size_bytes": snap.snapshot_size_bytes,
            "captured_at": snap.captured_at,
            "is_reversible": snap.is_reversible,
        })
    return before_states


# ── Main wrapper ───────────────────────────────────────────────────────────────

def run(command: str) -> int:
    """
    Full ARC-wrapped execution of a shell command.
    Returns the exit code of the underlying command.
    """

    # ── Setup ─────────────────────────────────────────────────────────────────
    provider_kp = load_or_create_keypair(KEY_PATH)
    store = SnapshotStore()

    # Connect to log (fall back to in-memory if server unreachable)
    try:
        log = ARCLogClient(base_url=LOG_URL)
        log.health_check()  # raises if unreachable
    except Exception:
        print(
            f"[ARC] Warning: log server at {LOG_URL} unreachable. "
            "Using in-memory log (receipts will not be publicly verifiable).",
            file=sys.stderr,
        )
        log = ARCInMemoryLog()

    receipt_id = new_receipt_id()
    intent_id  = new_intent_id()
    now        = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # ── Detect resources ───────────────────────────────────────────────────────
    paths = detect_resource_paths(command)
    if not paths:
        # Fall back to CWD as the resource (catch-all)
        paths = [os.getcwd()]

    # ── Phase 1: Capture before-state and commit intent ───────────────────────
    print(f"[ARC] Capturing before-state for: {paths[:3]}", file=sys.stderr)
    before_states = capture_before_states(paths, store)

    # For Phase 1, use first resource as primary before_state
    primary_before = before_states[0] if before_states else {
        "resource_uri": f"filesystem:{os.getcwd()}",
        "resource_type": "filesystem:directory",
        "snapshot_ref": new_snapshot_id(),
        "snapshot_hash": sha256_hex(b"unknown"),
        "snapshot_size_bytes": 0,
        "captured_at": now,
        "is_reversible": False,
    }

    # Hash the reasoning (command itself is the "reasoning" for the wrapper)
    reasoning_text = f"Executing: {command}"
    reasoning_hash = sha256_hex(reasoning_text.encode())

    phase1_intent = {
        "intent_id": intent_id,
        "tool_name": "bash",
        "tool_provider_id": f"provider:arc-shell:{AGENT_ID}",
        "arguments": {"command": command, "cwd": os.getcwd()},
        "declared_by": {
            "agent_id": AGENT_ID,
            "model_version": os.environ.get("ARC_MODEL_VERSION", "unknown"),
            "session_id": SESSION_ID,
        },
        "on_behalf_of": ON_BEHALF_OF,
        "reasoning_commitment": reasoning_hash,
        "declared_at": now,
    }

    # Commit Phase 1 to log
    try:
        p1_commitment = log.commit_intent(phase1_intent, receipt_id=receipt_id)
    except Exception as e:
        print(f"[ARC] Phase 1 log commit failed: {e}", file=sys.stderr)
        p1_commitment = {
            "log_id": "local",
            "sequence_number": -1,
            "merkle_root": sha256_hex(b"local"),
            "committed_at": now,
        }

    phase1 = {
        "intent": phase1_intent,
        "before_state": primary_before,
        "log_commitment": p1_commitment,
        "extra_resources": before_states[1:],  # additional affected resources
    }

    print(f"[ARC] Phase 1 committed. Intent: {intent_id}", file=sys.stderr)

    # ── Execute the actual command ─────────────────────────────────────────────
    exec_start = datetime.now(timezone.utc)

    result = subprocess.run(
        command,
        shell=True,
        capture_output=False,  # let stdout/stderr flow through to the agent
        text=True,
    )

    exec_end = datetime.now(timezone.utc)
    duration_ms = int((exec_end - exec_start).total_seconds() * 1000)

    outcome = "success" if result.returncode == 0 else "failure"

    # ── Build result object and hash it ───────────────────────────────────────
    result_obj = {
        "exit_code": result.returncode,
        "outcome": outcome,
        "command": command,
        "duration_ms": duration_ms,
    }
    outcome_hash = sha256_hex(canonical_json(result_obj))

    # ── Phase 2: Build and sign receipt ───────────────────────────────────────
    signed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Build the signing payload (exact same construction as verify_receipt expects)
    signing_payload = build_signing_payload(
        receipt_id=receipt_id,
        intent_id=intent_id,
        outcome_hash=outcome_hash,
        before_state_hash=primary_before["snapshot_hash"],
        signed_at=signed_at,
    )
    provider_signature = provider_kp.sign(signing_payload)

    # Build inverse operation
    is_destructive = infer_is_destructive(command)
    if is_destructive and primary_before.get("is_reversible"):
        valid_until_dt = datetime.fromtimestamp(
            exec_end.timestamp() + 3600, tz=timezone.utc
        )
        valid_until = valid_until_dt.isoformat().replace("+00:00", "Z")
        inverse_args = {"snapshot_ref": primary_before["snapshot_ref"]}

        inv_payload = build_inverse_signing_payload(
            receipt_id=receipt_id,
            inverse_tool="restore_snapshot",
            inverse_arguments=inverse_args,
            valid_until=valid_until,
        )
        inverse_signature = provider_kp.sign(inv_payload)

        inverse = {
            "is_reversible": True,
            "inverse_tool": "restore_snapshot",
            "inverse_arguments": inverse_args,
            "valid_until": valid_until,
            "inverse_signature": inverse_signature,
            "estimated_duration_ms": 500,
        }
    else:
        inverse = {"is_reversible": False}

    phase2_execution = {
        "started_at": exec_start.isoformat().replace("+00:00", "Z"),
        "completed_at": exec_end.isoformat().replace("+00:00", "Z"),
        "duration_ms": duration_ms,
        "outcome": outcome,
        "outcome_hash": outcome_hash,
    }
    if outcome == "failure":
        phase2_execution["error_code"] = str(result.returncode)
        phase2_execution["error_message"] = f"Command exited with code {result.returncode}"

    phase2_attestation = {
        "provider_id": f"provider:arc-shell:{AGENT_ID}",
        "provider_name": f"arc-shell-wrapper/{AGENT_ID}",
        "signed_at": signed_at,
        "signature": provider_signature,
        "signed_payload_hash": sha256_hex(signing_payload),
    }

    # Commit Phase 2 to log
    full_receipt = {
        "arc_version": "1.0",
        "receipt_id": receipt_id,
        "phase_1": phase1,
        "phase_2": {
            "execution": phase2_execution,
            "provider_attestation": phase2_attestation,
            "inverse": inverse,
        },
    }

    try:
        p2_commitment = log.commit_receipt(full_receipt)
        full_receipt["phase_2"]["log_proof"] = p2_commitment
    except Exception as e:
        print(f"[ARC] Phase 2 log commit failed: {e}", file=sys.stderr)

    # ── Write receipt ID to log file ───────────────────────────────────────────
    receipts_log = Path(RECEIPTS_LOG)
    with receipts_log.open("a") as f:
        entry = json.dumps({
            "receipt_id": receipt_id,
            "agent_id": AGENT_ID,
            "session_id": SESSION_ID,
            "command": command[:120],
            "outcome": outcome,
            "timestamp": signed_at,
            "provider_public_key": provider_kp.public_key_hex,
        })
        f.write(entry + "\n")

    # ── Print receipt summary to stderr ───────────────────────────────────────
    print(f"[ARC] ✓ Receipt: {receipt_id}", file=sys.stderr)
    print(f"[ARC]   outcome={outcome}  duration={duration_ms}ms", file=sys.stderr)
    print(f"[ARC]   before={primary_before['snapshot_hash'][:20]}...", file=sys.stderr)
    print(f"[ARC]   outcome_hash={outcome_hash[:20]}...", file=sys.stderr)
    print(f"[ARC]   reversible={inverse.get('is_reversible', False)}", file=sys.stderr)

    return result.returncode


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} \"shell command here\"", file=sys.stderr)
        sys.exit(1)

    command = " ".join(sys.argv[1:])
    exit_code = run(command)
    sys.exit(exit_code)
