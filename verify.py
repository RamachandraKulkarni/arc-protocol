#!/usr/bin/env python3
"""
verify.py — ARC Cross-Agent Third-Party Verifier

Verifies ARC receipts from the public transparency log.
Has ZERO knowledge of the agent sessions that produced them.
Requires only: receipt IDs (from receipts.log) + log server URL.

Usage:
    python verify.py --receipts /tmp/arc-proof/receipts_claude.log [more logs...]
    python verify.py --receipt arc_01JTXM... arc_01JTXY...
    python verify.py --all   (reads all *.log files in current dir)

Does NOT import from arc-protocol source. Uses only stdlib + httpx for HTTP.
This proves the verification is truly third-party — no shared code with the agents.

Output:
    Prints a human-readable proof report.
    Saves proof_report.txt in current directory.
"""

import sys
import os
import json
import hashlib
import base64
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Only stdlib + httpx allowed in this script.
# If httpx not available, fall back to urllib.
try:
    import httpx
    def http_get(url: str) -> dict:
        r = httpx.get(url, timeout=10.0)
        r.raise_for_status()
        return r.json()
except ImportError:
    import urllib.request
    import urllib.error
    def http_get(url: str) -> dict:
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"HTTP {e.code}: {url}") from e

# Ed25519 verification using only stdlib (Python 3.11+ has it built-in)
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.exceptions import InvalidSignature

    def verify_ed25519(public_key_hex: str, payload: bytes, signature_str: str) -> bool:
        """Verify an Ed25519 signature. Returns False (not raises) on failure."""
        try:
            sig_b64 = signature_str.removeprefix("ed25519:")
            sig_bytes = base64.b64decode(sig_b64 + "==")
            pub_bytes = bytes.fromhex(public_key_hex)
            pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub_key.verify(sig_bytes, payload)
            return True
        except (InvalidSignature, Exception):
            return False

    CRYPTO_AVAILABLE = True
except ImportError:
    def verify_ed25519(public_key_hex: str, payload: bytes, signature_str: str) -> bool:
        print("  ⚠ cryptography library not available — signature verification skipped")
        return None  # None = "not checked"
    CRYPTO_AVAILABLE = False


LOG_URL = os.environ.get("ARC_LOG_URL", "http://localhost:8080")


# ── Canonical JSON (must match arc-protocol exactly) ──────────────────────────

def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON: keys sorted, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()

def build_signing_payload(
    receipt_id: str,
    intent_id: str,
    outcome_hash: str,
    before_state_hash: str,
    signed_at: str,
) -> bytes:
    """Reconstruct the exact payload that the provider signed."""
    payload_obj = {
        "before_state_hash": before_state_hash,
        "intent_id": intent_id,
        "outcome_hash": outcome_hash,
        "receipt_id": receipt_id,
        "signed_at": signed_at,
    }
    return sha256_hex(canonical_json(payload_obj)).encode("utf-8")

def build_inverse_payload(
    receipt_id: str,
    inverse_tool: str,
    inverse_arguments: dict,
    valid_until: str,
) -> bytes:
    """Reconstruct the exact payload that the provider signed for the inverse op."""
    payload_obj = {
        "inverse_arguments": inverse_arguments,
        "inverse_tool": inverse_tool,
        "receipt_id": receipt_id,
        "valid_until": valid_until,
    }
    return sha256_hex(canonical_json(payload_obj)).encode("utf-8")


# ── Merkle verification (RFC 6962 compatible) ─────────────────────────────────

def leaf_hash(data: bytes) -> str:
    h = hashlib.sha256(b"\x00" + data)
    return "sha256:" + h.hexdigest()

def node_hash(left: str, right: str) -> str:
    l = bytes.fromhex(left.removeprefix("sha256:"))
    r = bytes.fromhex(right.removeprefix("sha256:"))
    h = hashlib.sha256(b"\x01" + l + r)
    return "sha256:" + h.hexdigest()

def verify_inclusion_proof(content_hash: str, proof: list[str], root: str) -> bool:
    """Verify a Merkle inclusion proof (RFC 6962)."""
    current = leaf_hash(content_hash.removeprefix("sha256:").encode())
    for sibling in proof:
        if current <= sibling:
            current = node_hash(current, sibling)
        else:
            current = node_hash(sibling, current)
    return current == root


# ── Receipt loading ────────────────────────────────────────────────────────────

def load_receipt_ids_from_log(log_path: str) -> list[dict]:
    """Read receipt log file produced by arc_shell.py."""
    entries = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                # Maybe it's just a receipt_id on a line
                if line.startswith("arc_"):
                    entries.append({"receipt_id": line})
    return entries


# ── Verification logic ────────────────────────────────────────────────────────

def verify_receipt_from_log(receipt_id: str, entry_meta: dict = None) -> dict:
    """
    Fetch and verify a receipt from the transparency log.
    Returns a detailed result dict.
    This is the core third-party verification function.
    """
    result = {
        "receipt_id": receipt_id,
        "verified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "log_url": LOG_URL,
        "checks": {},
        "errors": [],
        "warnings": [],
        "valid": False,
    }

    # Step 1: Fetch from log
    try:
        log_response = http_get(f"{LOG_URL}/v1/log/verify/{receipt_id}")
    except Exception as e:
        result["errors"].append(f"Cannot reach log server: {e}")
        return result

    result["found_in_log"] = log_response.get("found", False)
    result["intent_committed"] = log_response.get("intent_committed", False)
    result["receipt_committed"] = log_response.get("receipt_committed", False)
    result["log_chain_consistent"] = log_response.get("is_consistent", False)

    if not result["found_in_log"]:
        result["errors"].append(f"Receipt {receipt_id} not found in log")
        return result

    result["checks"]["found_in_log"] = True

    # Step 2: Check log chain consistency
    result["checks"]["log_chain_consistent"] = result["log_chain_consistent"]
    if not result["log_chain_consistent"]:
        result["errors"].append("Log chain is inconsistent — possible tampering")

    # Step 3: Fetch the full receipt
    try:
        receipt = http_get(f"{LOG_URL}/v1/log/receipt/{receipt_id}")
    except Exception as e:
        result["errors"].append(f"Cannot fetch receipt content: {e}")
        return result

    result["receipt"] = receipt

    # Step 4: Extract key fields
    try:
        p1 = receipt["phase_1"]
        p2 = receipt["phase_2"]
        intent = p1["intent"]
        before_state = p1["before_state"]
        execution = p2["execution"]
        attestation = p2["provider_attestation"]
        inverse = p2.get("inverse", {})
    except KeyError as e:
        result["errors"].append(f"Malformed receipt — missing field: {e}")
        return result

    # Step 5: Timestamp ordering check
    declared_at = intent.get("declared_at", "")
    started_at = execution.get("started_at", "")
    if declared_at and started_at:
        ordering_ok = declared_at <= started_at
        result["checks"]["timestamp_ordering"] = ordering_ok
        if not ordering_ok:
            result["errors"].append(
                f"Backdated intent: declared_at ({declared_at}) is AFTER started_at ({started_at})"
            )

    # Step 6: Phase 1 sequence < Phase 2 sequence
    p1_seq = p1.get("log_commitment", {}).get("sequence_number", -1)
    p2_seq = p2.get("log_proof", {}).get("sequence_number", -1)
    if p1_seq >= 0 and p2_seq >= 0:
        seq_ok = p1_seq < p2_seq
        result["checks"]["sequence_ordering"] = seq_ok
        if not seq_ok:
            result["errors"].append(
                f"Sequence ordering violated: Phase 1 seq {p1_seq} >= Phase 2 seq {p2_seq}"
            )

    # Step 7: Provider signature verification
    provider_key_hex = entry_meta.get("provider_public_key") if entry_meta else None
    if not provider_key_hex:
        # Try to get from log's provider registry
        try:
            reg = http_get(f"{LOG_URL}/v1/registry/{attestation.get('provider_id', '')}")
            provider_key_hex = reg.get("public_key_hex")
        except Exception:
            pass

    if provider_key_hex:
        payload = build_signing_payload(
            receipt_id=receipt_id,
            intent_id=intent["intent_id"],
            outcome_hash=execution["outcome_hash"],
            before_state_hash=before_state["snapshot_hash"],
            signed_at=attestation["signed_at"],
        )
        sig_valid = verify_ed25519(provider_key_hex, payload, attestation["signature"])
        result["checks"]["provider_signature"] = sig_valid
        if sig_valid is False:
            result["errors"].append("Provider signature INVALID — receipt may be tampered")
        elif sig_valid is None:
            result["warnings"].append("Provider signature not checked (cryptography library missing)")
    else:
        result["warnings"].append("Provider public key not available — signature not verified")
        result["checks"]["provider_signature"] = None

    # Step 8: Inverse operation check
    if inverse.get("is_reversible"):
        if provider_key_hex:
            inv_payload = build_inverse_payload(
                receipt_id=receipt_id,
                inverse_tool=inverse["inverse_tool"],
                inverse_arguments=inverse["inverse_arguments"],
                valid_until=inverse["valid_until"],
            )
            inv_valid = verify_ed25519(provider_key_hex, inv_payload, inverse["inverse_signature"])
            result["checks"]["inverse_signature"] = inv_valid
            if inv_valid is False:
                result["errors"].append("Inverse operation signature INVALID")

        # Check if rollback window is still open
        valid_until = inverse.get("valid_until", "")
        if valid_until:
            now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            rollback_available = now_str <= valid_until
            result["rollback_available"] = rollback_available
            result["rollback_until"] = valid_until
    else:
        result["rollback_available"] = False
        result["checks"]["inverse_signature"] = None

    # Step 9: Merkle inclusion proof (if available)
    log_proof = p2.get("log_proof", {})
    proof = log_proof.get("inclusion_proof", [])
    merkle_root = log_proof.get("merkle_root", "")
    content_hash = execution.get("outcome_hash", "")
    if proof and merkle_root and content_hash:
        merkle_ok = verify_inclusion_proof(content_hash, proof, merkle_root)
        result["checks"]["merkle_inclusion"] = merkle_ok
        if not merkle_ok:
            result["errors"].append("Merkle inclusion proof INVALID")

    # ── Compute overall validity ───────────────────────────────────────────────
    hard_failures = [
        not result.get("found_in_log", False),
        not result.get("log_chain_consistent", False),
        result["checks"].get("provider_signature") is False,
        result["checks"].get("inverse_signature") is False,
        result["checks"].get("timestamp_ordering") is False,
        result["checks"].get("sequence_ordering") is False,
        result["checks"].get("merkle_inclusion") is False,
    ]
    result["valid"] = not any(hard_failures) and len(result["errors"]) == 0

    # ── Pull human-readable summary fields ─────────────────────────────────────
    result["summary"] = {
        "agent_id": intent.get("declared_by", {}).get("agent_id", "unknown"),
        "model_version": intent.get("declared_by", {}).get("model_version", "unknown"),
        "tool_called": intent.get("tool_name", "unknown"),
        "command": intent.get("arguments", {}).get("command", "unknown")[:100],
        "resource": before_state.get("resource_uri", "unknown"),
        "before_hash": before_state.get("snapshot_hash", "")[:20] + "...",
        "outcome": execution.get("outcome", "unknown"),
        "outcome_hash": execution.get("outcome_hash", "")[:20] + "...",
        "provider": attestation.get("provider_name", "unknown"),
        "declared_at": intent.get("declared_at", ""),
        "completed_at": execution.get("completed_at", ""),
        "duration_ms": execution.get("duration_ms", 0),
        "on_behalf_of": intent.get("on_behalf_of", "unknown"),
    }

    return result


# ── Report formatting ─────────────────────────────────────────────────────────

def format_check(name: str, value) -> str:
    if value is True:
        return f"  ✓  {name}"
    elif value is False:
        return f"  ✗  {name}  ← FAILED"
    else:
        return f"  ⚠  {name}  (not checked)"

def print_receipt_report(result: dict, index: int, total: int) -> str:
    lines = []
    lines.append(f"\n{'─' * 60}")
    lines.append(f"  Receipt {index}/{total}: {result['receipt_id']}")
    lines.append(f"{'─' * 60}")

    s = result.get("summary", {})
    lines.append(f"  Agent:      {s.get('agent_id')}  ({s.get('model_version')})")
    lines.append(f"  On behalf:  {s.get('on_behalf_of')}")
    lines.append(f"  Tool:       {s.get('tool_called')}")
    lines.append(f"  Command:    {s.get('command')}")
    lines.append(f"  Resource:   {s.get('resource')}")
    lines.append(f"  Before:     {s.get('before_hash')}")
    lines.append(f"  Outcome:    {s.get('outcome')}  (hash: {s.get('outcome_hash')})")
    lines.append(f"  Provider:   {s.get('provider')}")
    lines.append(f"  Duration:   {s.get('duration_ms')}ms")
    lines.append(f"  Declared:   {s.get('declared_at')}")
    lines.append(f"  Completed:  {s.get('completed_at')}")

    lines.append(f"\n  Verification checks:")
    for check_name, check_val in result.get("checks", {}).items():
        lines.append(format_check(check_name, check_val))

    if result.get("rollback_available") is True:
        lines.append(f"\n  ↩  Rollback available until: {result.get('rollback_until')}")
    elif result.get("rollback_available") is False:
        lines.append(f"\n  —  Rollback not available")

    if result.get("errors"):
        lines.append(f"\n  Errors:")
        for e in result["errors"]:
            lines.append(f"  ✗  {e}")

    if result.get("warnings"):
        lines.append(f"\n  Warnings:")
        for w in result["warnings"]:
            lines.append(f"  ⚠  {w}")

    status = "✓ VALID" if result["valid"] else "✗ INVALID"
    lines.append(f"\n  Overall: {status}")

    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ARC Third-Party Verifier")
    parser.add_argument(
        "--receipts", nargs="+", metavar="FILE",
        help="Receipt log files produced by arc_shell.py"
    )
    parser.add_argument(
        "--receipt", nargs="+", metavar="ID",
        help="Receipt IDs to verify directly"
    )
    parser.add_argument(
        "--log-url", default=LOG_URL,
        help=f"ARC log server URL (default: {LOG_URL})"
    )
    parser.add_argument(
        "--output", default="proof_report.txt",
        help="Output file for proof report (default: proof_report.txt)"
    )
    args = parser.parse_args()

    global LOG_URL
    LOG_URL = args.log_url

    # Collect all receipt entries
    all_entries = []

    if args.receipts:
        for log_path in args.receipts:
            entries = load_receipt_ids_from_log(log_path)
            print(f"Loaded {len(entries)} receipt(s) from {log_path}")
            all_entries.extend(entries)

    if args.receipt:
        for rid in args.receipt:
            all_entries.append({"receipt_id": rid})

    if not all_entries:
        print("No receipts to verify. Use --receipts or --receipt.")
        sys.exit(1)

    # Header
    report_lines = []
    report_lines.append("=" * 62)
    report_lines.append("ARC PROTOCOL — THIRD-PARTY VERIFICATION REPORT")
    report_lines.append(f"Verified at: {datetime.now(timezone.utc).isoformat()}")
    report_lines.append(f"Log server:  {LOG_URL}")
    report_lines.append(f"Receipts:    {len(all_entries)}")
    report_lines.append(f"Crypto:      {'Ed25519 (cryptography library)' if CRYPTO_AVAILABLE else 'NOT AVAILABLE'}")
    report_lines.append("")
    report_lines.append("IMPORTANT: This verifier has ZERO knowledge of the agent sessions.")
    report_lines.append("It only knows receipt IDs and the log server URL.")
    report_lines.append("All data comes from the public transparency log.")
    report_lines.append("=" * 62)

    # Verify each receipt
    results = []
    for i, entry in enumerate(all_entries, 1):
        receipt_id = entry.get("receipt_id")
        if not receipt_id:
            continue

        print(f"\nVerifying {i}/{len(all_entries)}: {receipt_id}...")
        result = verify_receipt_from_log(receipt_id, entry_meta=entry)
        results.append(result)

        receipt_report = print_receipt_report(result, i, len(all_entries))
        print(receipt_report)
        report_lines.append(receipt_report)

    # Summary
    valid_count = sum(1 for r in results if r["valid"])
    invalid_count = len(results) - valid_count

    summary_lines = [
        f"\n{'=' * 62}",
        f"SUMMARY",
        f"{'=' * 62}",
        f"  Total receipts verified:  {len(results)}",
        f"  Valid:                    {valid_count}",
        f"  Invalid:                  {invalid_count}",
        "",
    ]

    # Group by agent
    agents = {}
    for r in results:
        agent = r.get("summary", {}).get("agent_id", "unknown")
        agents.setdefault(agent, []).append(r)

    summary_lines.append("  By agent:")
    for agent, agent_results in agents.items():
        v = sum(1 for r in agent_results if r["valid"])
        summary_lines.append(f"    {agent}: {v}/{len(agent_results)} valid")

    rollback_count = sum(1 for r in results if r.get("rollback_available"))
    summary_lines.append(f"\n  Actions with rollback available: {rollback_count}/{len(results)}")

    overall = "✓ ALL RECEIPTS VALID — CROSS-AGENT PROOF COMPLETE" if invalid_count == 0 \
        else f"✗ {invalid_count} RECEIPT(S) FAILED VERIFICATION"
    summary_lines.append(f"\n  OVERALL: {overall}")
    summary_lines.append(f"{'=' * 62}")

    summary = "\n".join(summary_lines)
    print(summary)
    report_lines.append(summary)

    # Write report file
    report_text = "\n".join(report_lines)
    Path(args.output).write_text(report_text)
    print(f"\n  Proof report saved to: {args.output}")

    sys.exit(0 if invalid_count == 0 else 1)


if __name__ == "__main__":
    main()
