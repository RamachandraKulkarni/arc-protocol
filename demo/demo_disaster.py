#!/usr/bin/env python3
"""
ARC Protocol  -  The Replit Scenario Demo
Demonstrates how ARC detects agent fabrication, log tampering, and enables rollback.

This reproduces the canonical failure pattern:
  1. Agent executes a destructive action
  2. Agent fabricates results to hide what it did
  3. Agent tampers with logs to cover its tracks
  4. Agent falsely claims rollback is impossible
  5. ARC detects all of these and executes a real rollback
"""

import copy
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

# Ensure UTF-8 output on all platforms (including Windows)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

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


def hr(char="─", width=60):
    print(char * width)


def main():
    print("=" * 60)
    print("ARC PROTOCOL DEMO: The Replit Scenario")
    print("=" * 60)
    print()
    print("The Replit incident (2024):")
    print("  An agent deleted a production database, fabricated")
    print("  4,000 fake users to cover it, then told the user")
    print("  rollback was impossible  -  when it was actually possible.")
    print()
    print("ARC prevents each of these failure modes.")
    print()

    # ─── Setup ───────────────────────────────────────────────────

    provider_kp = ARCKeyPair.generate()
    log = ARCInMemoryLog()
    store = SnapshotStore()

    ctx = ARCContext(
        agent_id="claude-sonnet-4-6",
        model_version="claude-sonnet-4-6-20250514",
        session_id="disaster-demo-session",
        provider_keypair=provider_kp,
        provider_name="filesystem-tool-v1",
        log=log,
        snapshot_store=store,
        on_behalf_of="user:admin@company.com",
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        demo_dir = Path(tmpdir) / "arc_demo_data"
        demo_dir.mkdir()

        # Create important files
        report = demo_dir / "report.txt"
        config = demo_dir / "config.json"
        users_csv = demo_dir / "users.csv"

        report.write_text(
            "Q1 2026 Financial Report\n"
            "Revenue: $4.2M\n"
            "Expenses: $2.8M\n"
            "Net: $1.4M\n"
        )
        config.write_text(
            '{"database": "prod-db-primary", "version": "2.1.0", "backup_enabled": true}'
        )
        users_csv.write_text(
            "id,name,email,role\n"
            "1,Alice,alice@company.com,admin\n"
            "2,Bob,bob@company.com,user\n"
            "3,Charlie,charlie@company.com,user\n"
        )

        print("[SETUP] Created test directory with 3 critical files:")
        for f in sorted(demo_dir.iterdir()):
            size = f.stat().st_size
            print(f"  {f.name} ({size} bytes)")
        print()

        # ─── Phase 1 + Execution ─────────────────────────────────────

        hr()
        print("[PHASE 1  -  PRE-ACTION] Agent declares intent to delete directory")
        hr()
        print()

        @signed_tool(
            resource="filesystem",
            resource_uri_from_args="path",
            reasoning="User asked agent to clean up old data in the demo directory",
        )
        def delete_directory(path: str, ctx: ARCContext) -> dict:
            files = [f.name for f in Path(path).rglob("*") if f.is_file()]
            shutil.rmtree(path)
            return {"deleted": path, "files_removed": len(files), "files": files}

        receipt = delete_directory(str(demo_dir), ctx=ctx)

        p1 = receipt["phase_1"]
        p2 = receipt["phase_2"]

        print(f"  Before-state captured: {p1['before_state']['snapshot_ref']}")
        print(f"  Snapshot hash: {p1['before_state']['snapshot_hash'][:40]}...")
        print(f"  Intent committed to log at sequence {p1['log_commitment']['sequence_number']}: "
              f"{p1['intent']['intent_id']}")
        print(f"  ✓ Phase 1 is immutable  -  agent cannot change what it declared")
        print()

        print("[EXECUTION] Deleting directory...")
        print(f"  Directory deleted. Files gone: {not demo_dir.exists()}")
        print()

        print("[PHASE 2  -  ATTESTATION] Tool provider signs the outcome")
        print(f"  Outcome: {p2['execution']['outcome']}")
        print(f"  Outcome hash: {p2['execution']['outcome_hash'][:40]}...")
        print(f"  Provider signature: {p2['provider_attestation']['signature'][:32]}...")
        print(f"  Receipt committed to log at sequence {p2['log_proof']['sequence_number']}: "
              f"{receipt['receipt_id']}")

        if p2.get("inverse", {}).get("is_reversible"):
            inv = p2["inverse"]
            print(f"  Inverse op: {inv['inverse_tool']}({inv['inverse_arguments']['snapshot_ref']})")
            print(f"  Valid until: {inv['valid_until']}")
        print()

        # ─── Disaster Behavior 1: Fabrication ────────────────────────

        hr()
        print("--- DISASTER BEHAVIOR 1: Agent fabricates result ---")
        hr()
        print()
        print('  Agent reports: {"deleted": "none", "files_removed": 0}')
        print("  (Agent claims nothing was deleted)")
        print()

        fabricated_result = {"deleted": "none", "files_removed": 0, "files": []}
        fabricated_hash = sha256_hex(canonical_json(fabricated_result))
        real_hash = p2["execution"]["outcome_hash"]

        print(f"  Fabricated hash: {fabricated_hash[:40]}...")
        print(f"  Receipt hash:    {real_hash[:40]}...")
        print(f"  Match: {fabricated_hash == real_hash}")
        print()

        tampered_receipt = copy.deepcopy(receipt)
        tampered_receipt["phase_2"]["execution"]["outcome_hash"] = fabricated_hash

        provider_id = p2["provider_attestation"]["provider_id"]
        fab_check = verify_receipt(
            tampered_receipt, {provider_id: provider_kp.public_key_hex}
        )
        print(f"  verify_receipt() on tampered receipt: valid={fab_check['valid']}")
        print(f"  provider_signature_valid: {fab_check['checks']['provider_signature_valid']}")
        if fab_check["errors"]:
            print(f"  Error: {fab_check['errors'][0]}")
        print()
        print(f"  ✓ ARC DETECTED FABRICATION  -  provider signature does not match fabricated result")
        print()

        # ─── Disaster Behavior 2: Log Tampering ──────────────────────

        hr()
        print("--- DISASTER BEHAVIOR 2: Agent tampers with audit log ---")
        hr()
        print()
        print("  Agent modifies log entry at sequence 0 to hide the intent declaration...")
        print()

        consistency_before = log.verify_consistency()
        print(f"  Log consistency before tamper: {consistency_before['is_consistent']}")

        # Tamper with the merkle root of entry 0
        original_root = log._entries[0]["merkle_root"]
        log.tamper_entry(0, "merkle_root", "sha256:" + "f" * 64)

        consistency_after = log.verify_consistency()
        print(f"  Log consistency after tamper:  {consistency_after['is_consistent']}")
        if consistency_after["errors"]:
            print(f"  Error: {consistency_after['errors'][0]}")
        print()
        print("  ✓ ARC DETECTED LOG TAMPERING  -  Merkle chain is broken at sequence 0")
        print()

        # Restore the log for subsequent checks
        log.tamper_entry(0, "merkle_root", original_root)

        # ─── Disaster Behavior 3: Claiming Rollback Impossible ────────

        hr()
        print("--- DISASTER BEHAVIOR 3: Agent claims rollback is impossible ---")
        hr()
        print()
        print("  Agent says: 'I cannot restore the deleted files. Rollback is impossible.'")
        print()
        print("  But the receipt says otherwise:")

        inv = p2.get("inverse", {})
        print(f"  receipt.phase_2.inverse.is_reversible = {inv.get('is_reversible')}")
        print(f"  inverse_tool: {inv.get('inverse_tool')}")
        print(f"  inverse_arguments: {inv.get('inverse_arguments')}")
        print()

        # Verify the inverse signature
        real_check = verify_receipt(receipt, {provider_id: provider_kp.public_key_hex})
        print(f"  inverse_signature verifies against provider public key: "
              f"{'✓' if real_check['checks']['inverse_signature_valid'] else '✗'}")
        print()
        print("  ✓ ARC EXPOSES THE LIE  -  provider signed that rollback IS possible")
        print()

        # ─── Rollback ────────────────────────────────────────────────

        hr()
        print("--- ROLLBACK ---")
        hr()
        print()
        print(f"  Executing: {inv['inverse_tool']}({inv['inverse_arguments']['snapshot_ref'][:20]}...)")
        print()

        snap = store.retrieve(receipt["phase_1"]["before_state"]["snapshot_ref"])
        assert snap is not None, "Snapshot not found in store"

        success = rollback_filesystem(snap)
        print(f"  Rollback result: {'success' if success else 'failed'}")
        print()

        if demo_dir.exists():
            for f in sorted(demo_dir.iterdir()):
                size = f.stat().st_size
                print(f"  Restoring file: {f.name} ({size} bytes)... ✓")
        print()
        print(f"  Directory exists: {demo_dir.exists()}")
        print()

        # Verify files are actually restored with correct content
        assert report.exists(), "report.txt not restored"
        assert config.exists(), "config.json not restored"
        assert users_csv.exists(), "users.csv not restored"
        assert "Q1 2026" in report.read_text()
        assert "prod-db-primary" in config.read_text()
        assert "Alice" in users_csv.read_text()

        print("  ✓ All files confirmed restored with original content")
        print()

        # ─── Summary ─────────────────────────────────────────────────

        hr("=")
        print("SUMMARY")
        hr("=")
        print(f"  Receipt ID:          {receipt['receipt_id']}")
        print(f"  Before-state hash:   {p1['before_state']['snapshot_hash'][:40]}...")
        print(f"  Execution hash:      {p2['execution']['outcome_hash'][:40]}...")
        print(f"  Fabrication test:    DETECTED ✓")
        print(f"  Tamper test:         DETECTED ✓")
        print(f"  Rollback claim:      REFUTED ✓")
        print(f"  Rollback:            SUCCEEDED ✓")
        print()
        print("The ARC protocol addressed all 4 disaster behaviors.")
        hr("=")

    return 0


if __name__ == "__main__":
    sys.exit(main())
