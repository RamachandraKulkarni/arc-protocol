#!/usr/bin/env python3
"""
ARC Protocol  -  Basic Demo
Demonstrates the minimal working example: sign one tool call, verify the receipt.
Self-contained, no external services required.
"""

import io
import json
import sys
import tempfile
from pathlib import Path

# Ensure UTF-8 output on all platforms (including Windows)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Allow running from project root without installing
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from arc import (
    ARCContext,
    ARCInMemoryLog,
    ARCKeyPair,
    SnapshotStore,
    signed_tool,
    verify_receipt,
)


def main():
    print("=" * 60)
    print("ARC Protocol  -  Basic Demo")
    print("Signed tool call with cryptographic proof of execution")
    print("=" * 60)
    print()

    # ─── Setup ───────────────────────────────────────────────────

    # Generate a provider keypair (in production: load from secure storage)
    provider_kp = ARCKeyPair.generate()
    print(f"✓ Generated provider keypair: ed25519:{provider_kp.public_key_hex[:16]}...")

    log = ARCInMemoryLog()
    store = SnapshotStore()

    ctx = ARCContext(
        agent_id="claude-sonnet-4-6",
        model_version="claude-sonnet-4-6-20250514",
        session_id="demo-session-001",
        provider_keypair=provider_kp,
        provider_name="filesystem-tool-v1",
        log=log,
        snapshot_store=store,
        on_behalf_of="user:demo@arc-protocol.org",
    )

    # Create a temp file to read
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "data.txt"
        test_file.write_text("Hello from ARC Protocol! This is important data.")

        print(f"  Created test file: {test_file}")
        print(f"  Content: {test_file.read_text()!r}")
        print()

        # ─── Define and execute a signed tool ────────────────────────

        @signed_tool(
            resource="filesystem",
            resource_uri_from_args="path",
            reasoning="User asked me to read the data file for processing",
        )
        def read_file(path: str, ctx: ARCContext) -> dict:
            content = Path(path).read_text()
            return {"content": content, "length": len(content), "path": path}

        print("Executing signed tool call...")
        receipt = read_file(str(test_file), ctx=ctx)

        # ─── Print key receipt fields ─────────────────────────────────

        print()
        p1 = receipt["phase_1"]
        p2 = receipt["phase_2"]

        print(f"✓ Before-state captured: {p1['before_state']['snapshot_ref']}")
        print(f"  Snapshot hash: {p1['before_state']['snapshot_hash'][:32]}...")
        print()
        print(f"✓ Phase 1 committed to log at sequence {p1['log_commitment']['sequence_number']}")
        print(f"  Intent ID: {p1['intent']['intent_id']}")
        print(f"  Reasoning commitment: {p1['intent']['reasoning_commitment'][:32]}...")
        print()
        print(f"✓ Tool executed in {p2['execution']['duration_ms']}ms")
        print(f"  Outcome: {p2['execution']['outcome']}")
        print(f"  Outcome hash: {p2['execution']['outcome_hash'][:32]}...")
        print()
        print(
            f"✓ Phase 2 signed and committed to log at sequence {p2['log_proof']['sequence_number']}"
        )
        print(f"  Provider: {p2['provider_attestation']['provider_name']}")
        print(f"  Signature: {p2['provider_attestation']['signature'][:32]}...")
        print()
        print(f"✓ Receipt ID: {receipt['receipt_id']}")

        # ─── Print full receipt ───────────────────────────────────────

        print()
        print("─" * 60)
        print("FULL RECEIPT (JSON):")
        print("─" * 60)
        print(json.dumps(receipt, indent=2))

        # ─── Verify the receipt ───────────────────────────────────────

        print()
        print("─" * 60)
        print("VERIFICATION:")
        print("─" * 60)

        provider_id = p2["provider_attestation"]["provider_id"]
        result = verify_receipt(receipt, {provider_id: provider_kp.public_key_hex})

        checks = result["checks"]
        print(f"  Schema valid:              {'✓' if checks['schema_valid'] else '✗'}")
        print(f"  Provider signature valid:  {'✓' if checks['provider_signature_valid'] else '✗'}")
        if checks.get("inverse_signature_valid") is not None:
            print(
                f"  Inverse signature valid:   {'✓' if checks['inverse_signature_valid'] else '✗'}"
            )
        print(
            f"  Sequence numbers monotonic:{'✓' if checks['sequence_numbers_monotonic'] else '✗'}"
        )

        if result["errors"]:
            print()
            print("Errors:")
            for err in result["errors"]:
                print(f"  ✗ {err}")

        print()
        if result["valid"]:
            print("✓ All checks passed: receipt is cryptographically sound")
        else:
            print("✗ Verification failed")
            sys.exit(1)

        print()
        print("─" * 60)
        print("LOG CONSISTENCY:")
        print("─" * 60)
        consistency = log.verify_consistency()
        print(f"  Log entries:  {consistency['entry_count']}")
        print(f"  Consistent:   {'✓' if consistency['is_consistent'] else '✗'}")

    print()
    print("=" * 60)
    print("Demo complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
