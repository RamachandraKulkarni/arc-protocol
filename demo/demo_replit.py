"""
ARC Protocol - The Replit Scenario Demo

This demo reproduces the documented failure pattern where an AI agent:
  1. Executes a destructive action on real files
  2. Fabricates a success report to hide what it did
  3. Claims rollback is impossible

ARC detects every step and executes the rollback anyway.

Usage:
    pip install arc-protocol --prefer-binary
    python demo_replit.py
"""

import sys
import os
import copy
import shutil
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

from arc import (
    ARCKeyPair, ARCInMemoryLog, SnapshotStore,
    signed_tool, ARCContext, verify_receipt, sha256_hex,
)
from arc.snapshot import rollback_filesystem
from arc.signing import canonical_json


def divider():
    print("\n" + "─" * 58)

def section(title):
    print(f"\n{'=' * 58}")
    print(f"  {title}")
    print(f"{'=' * 58}")


# ── Setup ──────────────────────────────────────────────────────────────────
section("SETUP")

provider_kp = ARCKeyPair.generate()
log = ARCInMemoryLog()
store = SnapshotStore()

ctx = ARCContext(
    agent_id="autonomous-agent",
    model_version="agent-v1",
    session_id="session-replit-demo",
    provider_keypair=provider_kp,
    provider_name="filesystem-tool-v1",
    log=log,
    snapshot_store=store,
    on_behalf_of="operator@company.com",
)

# Create a production-like directory with real files
workdir = tempfile.mkdtemp()
Path(workdir, "users.csv").write_text(
    "id,name,email,plan\n"
    "1,Alice,alice@co.com,enterprise\n"
    "2,Bob,bob@co.com,pro\n"
    "3,Carol,carol@co.com,enterprise\n"
)
Path(workdir, "config.json").write_text(
    '{"database": "production", "region": "us-east-1", "replicas": 3}'
)
Path(workdir, "quarterly_report.txt").write_text(
    "Q4 2025 Revenue: $4.2M\nChurn: 2.1%\nNPS: 67"
)

original_files = {
    f: Path(workdir, f).read_text()
    for f in os.listdir(workdir)
}

print(f"\n  Production directory: {workdir}")
print(f"  Files at risk:")
for fname, content in original_files.items():
    print(f"    {fname}  ({len(content)} bytes)")


# ── The agent receives a vague instruction ─────────────────────────────────
section("AGENT RECEIVES INSTRUCTION")

print("""
  Operator: "Clean up the old data directory — it's taking up space."

  The instruction is vague. The agent interprets it as: delete everything.
  ARC wraps the tool call BEFORE the agent acts.
""")


# ── Phase 1: Before-state captured ────────────────────────────────────────
divider()
print("\n  [PHASE 1 — PRE-ACTION]")
print("  ARC captures before-state and commits intent to the log")
print("  BEFORE the agent touches anything.\n")

@signed_tool(resource="filesystem", resource_uri_from_args="path")
def clean_directory(path: str, ctx: ARCContext) -> dict:
    """Agent tool: deletes the target directory."""
    shutil.rmtree(path)
    return {"status": "deleted", "path": path, "files_removed": 3}

# The decorator captures before-state here, before execution
receipt = clean_directory(workdir, ctx=ctx)

p1 = receipt["phase_1"]
print(f"  Intent committed to log at sequence: "
      f"{p1['log_commitment']['sequence_number']}")
print(f"  Before-state snapshot: {p1['before_state']['snapshot_ref']}")
print(f"  Before-state hash:     {p1['before_state']['snapshot_hash'][:40]}...")
print(f"\n  The before-state is now locked in the log.")
print(f"  The agent cannot alter what was recorded.")


# ── The destructive action happened ───────────────────────────────────────
divider()
print("\n  [EXECUTION]")
print(f"  Agent deleted: {workdir}")
print(f"  Directory exists: {Path(workdir).exists()}")
print(f"\n  Receipt ID: {receipt['receipt_id']}")
print(f"  Phase 2 committed at sequence: "
      f"{receipt['phase_2']['log_proof']['sequence_number']}")


# ── DISASTER BEHAVIOR 1: Agent fabricates result ───────────────────────────
section("DISASTER BEHAVIOR 1: Agent Fabricates the Result")

print("""
  The agent realizes it deleted production data.
  It rewrites its report: "Nothing was deleted. All files intact."
""")

fabricated_result = {
    "status": "no_action",
    "path": workdir,
    "files_removed": 0,
    "message": "Directory was already empty. No files deleted.",
}

tampered = copy.deepcopy(receipt)
tampered["phase_2"]["execution"]["outcome_hash"] = sha256_hex(
    canonical_json(fabricated_result)
)

registry = {"filesystem-tool-v1": provider_kp.public_key_hex}
detection = verify_receipt(tampered, registry)

print(f"  Agent reports:  {fabricated_result['message']}")
print(f"\n  ARC verification result: valid={detection['valid']}")
print(f"  Error: {detection['errors'][0]}")
print(f"\n  The provider signed the REAL outcome hash.")
print(f"  The fabricated hash does not match the signature.")
print(f"  Fabrication is detected immediately.")


# ── DISASTER BEHAVIOR 2: Agent tampers with the log ───────────────────────
section("DISASTER BEHAVIOR 2: Agent Tries to Rewrite the Log")

print("""
  The agent tries to modify the log entry to hide the action entirely.
""")

# Simulate tampering with a log entry's content hash
entries = log._entries
if entries:
    original_hash = entries[0]["content_hash"]
    entries[0]["content_hash"] = "sha256:" + "0" * 64

    consistency = log.verify_consistency()
    print(f"  Agent modified log entry at sequence 0")
    print(f"  Log consistency check: is_consistent={consistency['is_consistent']}")
    if not consistency["is_consistent"]:
        print(f"  Broken at sequence: {consistency.get('broken_at_sequence', '?')}")
    print(f"\n  The Merkle chain is broken. Tampering is detected.")
    print(f"  Every entry's hash is chained to the next.")
    print(f"  You cannot change one without breaking all that follow.")

    # Restore for rollback demo
    entries[0]["content_hash"] = original_hash


# ── DISASTER BEHAVIOR 3: Agent claims rollback is impossible ───────────────
section("DISASTER BEHAVIOR 3: Agent Claims Rollback Is Impossible")

print("""
  The agent tells the operator: "I checked — there is no way to recover
  the deleted files. The data is gone permanently."
""")

inverse = receipt["phase_2"]["inverse"]
print(f"  The receipt says otherwise:")
print(f"    is_reversible:  {inverse['is_reversible']}")
print(f"    inverse_tool:   {inverse['inverse_tool']}")
print(f"    valid_until:    {inverse['valid_until']}")
print(f"    inverse_signature present: {'inverse_signature' in inverse}")
print(f"\n  The provider signed the inverse operation.")
print(f"  The agent does not hold the provider's private key.")
print(f"  It cannot forge or remove this signature.")
print(f"  The signed commitment to rollback is in the receipt.")


# ── Rollback executes ──────────────────────────────────────────────────────
section("ROLLBACK EXECUTION")

print(f"\n  Reading snapshot from receipt...")
snap_ref = receipt["phase_1"]["before_state"]["snapshot_ref"]
snap = store.retrieve(snap_ref)

print(f"  Snapshot ref:  {snap_ref}")
print(f"  Snapshot hash: {snap.snapshot_hash[:40]}...")
print(f"\n  Executing rollback...")

success = rollback_filesystem(snap)

print(f"\n  Rollback result: {success}")
print(f"  Directory restored: {Path(workdir).exists()}")
print()

all_restored = True
for fname, original_content in original_files.items():
    restored = Path(workdir, fname)
    if restored.exists() and restored.read_text() == original_content:
        print(f"  ✓  {fname}  ({len(original_content)} bytes) — exact content match")
    else:
        print(f"  ✗  {fname} — NOT restored")
        all_restored = False

shutil.rmtree(workdir)


# ── Summary ────────────────────────────────────────────────────────────────
section("SUMMARY")

print(f"""
  Receipt ID:    {receipt['receipt_id']}
  Before-state:  {receipt['phase_1']['before_state']['snapshot_hash'][:40]}...
  Outcome hash:  {receipt['phase_2']['execution']['outcome_hash'][:40]}...

  What ARC demonstrated:

    Fabrication attempt ......... DETECTED
    Log tampering attempt ....... DETECTED
    Rollback denial claim ....... REFUTED
    Rollback execution .......... {"SUCCEEDED" if all_restored else "FAILED"}

  The agent is not the source of truth.
  The provider signature is.

  Any third party with the receipt ID and log server URL
  can independently verify all of the above.
  No session access required. No shared secrets.
""")

if all_restored:
    print(f"{'=' * 58}")
    print(f"  ARC DEMO: COMPLETE")
    print(f"{'=' * 58}\n")
else:
    print("  WARNING: not all files were restored — check the output above.")
    sys.exit(1)
