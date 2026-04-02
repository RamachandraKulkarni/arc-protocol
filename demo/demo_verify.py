#!/usr/bin/env python3
"""
ARC Protocol — Third-Party Verification Demo
Demonstrates verification of a receipt from the public log server alone.
No access to original context, keypairs, or tool runtime required.

USAGE: python demo/demo_verify.py arc_01JTXM9KP3F...
       (requires log server running: make log-server)
"""

import io
import sys
from pathlib import Path

# Ensure UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from arc.log_client import ARCLogClient, ARCLogError


def main():
    if len(sys.argv) < 2:
        print("Usage: python demo/demo_verify.py arc_<receipt_id>")
        print("       (requires log server: make log-server)")
        sys.exit(1)

    receipt_id = sys.argv[1]
    base_url = "http://localhost:8080"

    print("=" * 60)
    print("ARC Protocol — Third-Party Verification")
    print("=" * 60)
    print()
    print(f"  Receipt ID: {receipt_id}")
    print(f"  Log server: {base_url}")
    print()

    client = ARCLogClient(base_url)

    # Check server health
    try:
        import httpx
        with httpx.Client(timeout=5.0) as c:
            resp = c.get(f"{base_url}/health")
            if resp.status_code != 200:
                print(f"✗ Log server unavailable at {base_url}")
                sys.exit(1)
        print(f"  Log server status: ✓ online")
    except Exception as e:
        print(f"✗ Cannot reach log server at {base_url}: {e}")
        print("  Start it with: make log-server")
        sys.exit(1)

    # Get current tree head
    try:
        root_info = client.get_root()
        print(f"  Current Merkle root:  {root_info['merkle_root'][:40]}...")
        print(f"  Log entry count:      {root_info['sequence_number'] + 1}")
        print()
    except ARCLogError as e:
        print(f"  Warning: Could not fetch root: {e}")
        print()

    # Verify the receipt
    print("─" * 60)
    print("VERIFYING RECEIPT IN LOG:")
    print("─" * 60)
    print()

    try:
        result = client.verify(receipt_id)
    except ARCLogError as e:
        print(f"✗ Verification request failed: {e}")
        sys.exit(1)

    if not result["found"]:
        print(f"  ✗ Receipt {receipt_id} not found in log")
        sys.exit(1)

    print(f"  Found: ✓ ({len(result['entries'])} log entries)")
    print(f"  Intent committed:   {'✓' if result['intent_committed'] else '✗'}")
    print(f"  Receipt committed:  {'✓' if result['receipt_committed'] else '✗'}")
    print(f"  Log chain consistent: {'✓' if result['is_consistent'] else '✗'}")
    print(f"  Verification time:  {result['verification_time']}")
    print()

    if result["entries"]:
        print("  Log entries:")
        for entry in result["entries"]:
            print(f"    [{entry['sequence_number']}] {entry['entry_type'].upper()}")
            print(f"         committed at: {entry['timestamp']}")
            print(f"         content_hash: {entry['content_hash'][:40]}...")
            print(f"         merkle_root:  {entry['merkle_root'][:40]}...")
        print()

    # EU AI Act compliance check
    print("─" * 60)
    print("EU AI ACT ARTICLE 12 COMPLIANCE:")
    print("─" * 60)
    print()
    checks = {
        "Tamper-evident log": result["is_consistent"],
        "Pre-action intent recorded": result["intent_committed"],
        "Post-execution attestation recorded": result["receipt_committed"],
        "Both phases present": result["intent_committed"] and result["receipt_committed"],
    }
    all_pass = all(checks.values())
    for label, passed in checks.items():
        print(f"  {'✓' if passed else '✗'} {label}")

    print()
    if all_pass:
        print("  ✓ EU AI Act Article 12 compliance: SATISFIED")
        print("    (Tamper-evident log, both phases recorded)")
    else:
        print("  ✗ EU AI Act Article 12 compliance: INCOMPLETE")

    print()
    print("=" * 60)
    print("Verification complete (no private keys required).")
    print("=" * 60)


if __name__ == "__main__":
    main()
