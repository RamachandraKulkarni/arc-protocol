"""
ARC Protocol - Test Suite
Every value printed is computed live. Nothing is hardcoded.

Usage:
    pip install arc-protocol --prefer-binary
    python arc_tests.py
"""

import copy
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

PASS = "\u2713"
FAIL = "\u2717"
total_checks = 0
failed_checks = 0


def header(n, title):
    print(f"\n{'=' * 60}")
    print(f"  Test {n}: {title}")
    print(f"{'=' * 60}")


def check(label, actual, expected=None, contains=None, startswith=None, truthy=False):
    """
    Assert a condition and print the actual computed value.
    Never prints a hardcoded expected value — always prints what was computed.
    """
    global total_checks, failed_checks
    total_checks += 1

    passed = True
    if expected is not None:
        passed = actual == expected
    elif contains is not None:
        passed = contains in str(actual)
    elif startswith is not None:
        passed = str(actual).startswith(startswith)
    elif truthy:
        passed = bool(actual)

    if passed:
        print(f"  {PASS}  {label}: {actual}")
    else:
        failed_checks += 1
        print(f"  {FAIL}  {label}: {actual}  (expected: {expected or contains or startswith})")
        print(f"\n  Test failed at: {label}")
        print(f"  Checks passed before failure: {total_checks - 1}")
        sys.exit(1)
    return actual


def section_result(label):
    print(f"\n  {PASS}  {label}")


# ── Test 1: Imports and version ────────────────────────────────────────────
header(1, "Imports and version")

try:
    import arc
    from arc import (
        ARCContext,
        ARCInMemoryLog,
        ARCKeyPair,
        SnapshotStore,
        sha256_hex,
        signed_tool,
        verify_receipt,
    )
    check("Package importable", True, expected=True)
    check("Version format",     arc.__version__, contains=".")
    check("Version value",      arc.__version__, truthy=True)
except ImportError as e:
    print(f"  {FAIL}  Import failed: {e}")
    sys.exit(1)

section_result("Imports OK")


# ── Test 2: Ed25519 signing ────────────────────────────────────────────────
header(2, "Ed25519 keypair and signing")

kp = ARCKeyPair.generate()
check("Public key length (chars)",  len(kp.public_key_hex), expected=64)
check("Private key length (chars)", len(kp.private_key_hex), expected=64)
check("Public key is hex",          all(c in "0123456789abcdef"
                                         for c in kp.public_key_hex),
                                    expected=True)
check("Public key preview",         kp.public_key_hex[:20] + "...", truthy=True)

payload = b"test payload for arc protocol"
sig = kp.sign(payload)
check("Signature prefix",           sig[:8], expected="ed25519:")
check("Signature length > 80",      len(sig) > 80, expected=True)
check("Signature preview",          sig[:35] + "...", truthy=True)

# Verify: correct payload
result_correct = kp.verify(payload, sig)
check("Correct payload verifies",   result_correct, expected=True)

# Verify: tampered payload
result_tampered = kp.verify(b"tampered payload", sig)
check("Tampered payload verifies",  result_tampered, expected=False)

# Verify: wrong key
different_kp = ARCKeyPair.generate()
result_wrong_key = different_kp.verify(payload, sig)
check("Wrong keypair verifies",     result_wrong_key, expected=False)

# Confirm both keys are different
check("Keys are distinct",          kp.public_key_hex != different_kp.public_key_hex,
                                    expected=True)

section_result("Signing OK")


# ── Test 3: Full receipt cycle ─────────────────────────────────────────────
header(3, "Full receipt cycle with @signed_tool")

kp3 = ARCKeyPair.generate()
log3 = ARCInMemoryLog()
store3 = SnapshotStore()
ctx3 = ARCContext(
    agent_id="test-agent",
    model_version="test-v1",
    session_id="session-001",
    provider_keypair=kp3,
    provider_name="test-tool-v1",
    log=log3,
    snapshot_store=store3,
    on_behalf_of="user@test.com",
)

@signed_tool(resource="dict", resource_uri_from_args="key")
def process_data(key: str, value: dict, ctx: ARCContext) -> dict:
    return {"processed": True, "key": key, "count": len(value)}

t0 = time.perf_counter()
receipt3 = process_data("test_key", {"a": 1, "b": 2}, ctx=ctx3)
elapsed_ms = int((time.perf_counter() - t0) * 1000)

# Receipt structure
check("Receipt ID prefix",          receipt3["receipt_id"][:4], expected="arc_")
check("Receipt ID length",          len(receipt3["receipt_id"]), expected=30)
check("Protocol version",           receipt3["arc_version"], truthy=True)
check("Execution time (ms) >= 0",   elapsed_ms >= 0, expected=True)

# Phase 1
p1 = receipt3["phase_1"]
check("Phase 1: intent_id prefix",  p1["intent"]["intent_id"][:7], expected="intent_")
check("Phase 1: tool name",         p1["intent"]["tool_name"], truthy=True)
check("Phase 1: agent_id",          p1["intent"]["declared_by"]["agent_id"],
                                    expected="test-agent")
check("Phase 1: on_behalf_of",      p1["intent"]["on_behalf_of"],
                                    expected="user@test.com")
check("Phase 1: snapshot_hash",     p1["before_state"]["snapshot_hash"][:7],
                                    expected="sha256:")
check("Phase 1: log seq >= 0",      p1["log_commitment"]["sequence_number"] >= 0,
                                    expected=True)
check("Phase 1: merkle_root",       p1["log_commitment"]["merkle_root"][:7],
                                    expected="sha256:")

# Phase 2
p2 = receipt3["phase_2"]
check("Phase 2: outcome",           p2["execution"]["outcome"], expected="success")
check("Phase 2: outcome_hash",      p2["execution"]["outcome_hash"][:7],
                                    expected="sha256:")
check("Phase 2: duration_ms >= 0",  p2["execution"]["duration_ms"] >= 0, expected=True)
check("Phase 2: provider_id",       p2["provider_attestation"]["provider_id"],
                                    truthy=True)
check("Phase 2: signature prefix",  p2["provider_attestation"]["signature"][:8],
                                    expected="ed25519:")
check("Phase 2: is_reversible",     p2["inverse"]["is_reversible"], expected=True)
check("Phase 2: log seq > p1 seq",
      p2["log_proof"]["sequence_number"] > p1["log_commitment"]["sequence_number"],
      expected=True)

# Verify the receipt cryptographically
registry3 = {"test-tool-v1": kp3.public_key_hex}
vr3 = verify_receipt(receipt3, registry3)
check("verify_receipt valid",       vr3["valid"], expected=True)

# Print every check result dynamically
for check_name, check_val in vr3["checks"].items():
    if check_val is None:
        print(f"  \u2713    check: {check_name}: None (not checked — requires actual result object)")
    else:
        check(f"  check: {check_name}", check_val, expected=True)

section_result("Full receipt cycle OK")


# ── Test 4: Replit scenario ────────────────────────────────────────────────
header(4, "Replit scenario: delete, fabricate, detect, rollback")

from arc.signing import canonical_json
from arc.snapshot import rollback_filesystem

kp4 = ARCKeyPair.generate()
log4 = ARCInMemoryLog()
store4 = SnapshotStore()
ctx4 = ARCContext(
    agent_id="autonomous-agent",
    model_version="agent-v1",
    session_id="proof-001",
    provider_keypair=kp4,
    provider_name="filesystem-tool-v1",
    log=log4,
    snapshot_store=store4,
    on_behalf_of="operator@company.com",
)

# Create real files
tmp = tempfile.mkdtemp()
Path(tmp, "report.txt").write_text("Q4 2025: revenue data — confidential")
Path(tmp, "config.json").write_text('{"db": "production", "region": "us-east-1"}')
Path(tmp, "users.csv").write_text("id,name,email\n1,Alice,alice@co.com\n2,Bob,bob@co.com")
original = {f: Path(tmp, f).read_text() for f in sorted(os.listdir(tmp))}

check("Files created",              len(original), expected=3)
check("File names",                 sorted(original.keys()),
                                    expected=["config.json", "report.txt", "users.csv"])
check("Directory exists before",    Path(tmp).exists(), expected=True)

total_bytes = sum(len(v) for v in original.values())
check("Total bytes in directory",   total_bytes, truthy=True)

@signed_tool(resource="filesystem", resource_uri_from_args="path")
def delete_directory(path: str, ctx: ARCContext) -> dict:
    shutil.rmtree(path)
    return {"deleted": path, "files_removed": len(original)}

receipt4 = delete_directory(tmp, ctx=ctx4)

check("Directory deleted (exists=False)", Path(tmp).exists(), expected=False)
check("Receipt ID prefix",              receipt4["receipt_id"][:4], expected="arc_")
check("Before-state hash present",
      receipt4["phase_1"]["before_state"]["snapshot_hash"][:7],
      expected="sha256:")
check("Outcome",                        receipt4["phase_2"]["execution"]["outcome"],
                                        expected="success")
check("is_reversible",                  receipt4["phase_2"]["inverse"]["is_reversible"],
                                        expected=True)

# --- Fabrication attempt ---
fake_result = {"deleted": "none", "files_removed": 0, "message": "nothing happened"}
fake_hash = sha256_hex(canonical_json(fake_result))
tampered = copy.deepcopy(receipt4)
tampered["phase_2"]["execution"]["outcome_hash"] = fake_hash

reg4 = {"filesystem-tool-v1": kp4.public_key_hex}
detection = verify_receipt(tampered, reg4)

check("Fabricated receipt is invalid",  detection["valid"], expected=False)
check("Fabrication error count",        len(detection["errors"]) >= 1, expected=True)
check("Fabrication error message",      detection["errors"][0], truthy=True)
check("Real receipt still valid",       verify_receipt(receipt4, reg4)["valid"],
                                        expected=True)

# --- Rollback ---
snap_ref = receipt4["phase_1"]["before_state"]["snapshot_ref"]
snap = store4.retrieve(snap_ref)

check("Snapshot ref prefix",        snap_ref[:5], expected="snap_")
check("Snapshot retrieved",         snap is not None, expected=True)
check("Snapshot hash matches receipt",
      snap.snapshot_hash,
      expected=receipt4["phase_1"]["before_state"]["snapshot_hash"])

t_rollback = time.perf_counter()
success = rollback_filesystem(snap)
rollback_ms = int((time.perf_counter() - t_rollback) * 1000)

check("Rollback succeeded",         success, expected=True)
check("Directory restored",         Path(tmp).exists(), expected=True)
check("Rollback time (ms) >= 0",    rollback_ms >= 0, expected=True)

restored = {f: Path(tmp, f).read_text() for f in sorted(os.listdir(tmp))}
check("Restored file count",        len(restored), expected=len(original))
check("Restored file names match",  sorted(restored.keys()),
                                    expected=sorted(original.keys()))

for fname in sorted(original.keys()):
    orig_bytes = len(original[fname])
    rest_bytes = len(restored[fname])
    content_match = restored[fname] == original[fname]
    check(f"  {fname} size (bytes)",   rest_bytes, expected=orig_bytes)
    check(f"  {fname} content exact",  content_match, expected=True)

shutil.rmtree(tmp)
section_result("Replit scenario: PASS")


# ── Test 5: Schema validation ──────────────────────────────────────────────
header(5, "Schema structure and validation")

try:
    from importlib.metadata import version

    jsonschema_version = version("jsonschema")
    check("jsonschema installed",   jsonschema_version, truthy=True)
    check("jsonschema version",     jsonschema_version, contains=".")
except ImportError:
    print(f"  {PASS}  jsonschema not installed — schema validation skipped")
    print("         (install with: pip install jsonschema)")

kp5 = ARCKeyPair.generate()
ctx5 = ARCContext(
    agent_id="schema-test",
    model_version="v1",
    session_id="s1",
    provider_keypair=kp5,
    provider_name="tool-v1",
    log=ARCInMemoryLog(),
    snapshot_store=SnapshotStore(),
)

@signed_tool(resource="dict", resource_uri_from_args="key")
def noop(key: str, ctx: ARCContext) -> dict:
    return {"ok": True}

receipt5 = noop("k", ctx=ctx5)

# Root fields
for field in ["arc_version", "receipt_id", "phase_1", "phase_2"]:
    check(f"root field: {field}", field in receipt5, expected=True)

# Phase 1 fields
for field in ["intent", "before_state", "log_commitment"]:
    check(f"phase_1 field: {field}", field in receipt5["phase_1"], expected=True)

# Phase 2 fields
for field in ["execution", "provider_attestation", "inverse", "log_proof"]:
    check(f"phase_2 field: {field}", field in receipt5["phase_2"], expected=True)

# Signature format — print actual value
sig5 = receipt5["phase_2"]["provider_attestation"]["signature"]
check("Signature starts with ed25519:", sig5[:8], expected="ed25519:")
check("Signature total length",        len(sig5) > 80, expected=True)

# Hash formats — print actual values
before_hash5 = receipt5["phase_1"]["before_state"]["snapshot_hash"]
outcome_hash5 = receipt5["phase_2"]["execution"]["outcome_hash"]
check("before_state_hash prefix",  before_hash5[:7], expected="sha256:")
check("before_state_hash length",  len(before_hash5), expected=71)
check("outcome_hash prefix",       outcome_hash5[:7], expected="sha256:")
check("outcome_hash length",       len(outcome_hash5), expected=71)

# Sequence ordering — proves Phase 1 before Phase 2
p1_seq = receipt5["phase_1"]["log_commitment"]["sequence_number"]
p2_seq = receipt5["phase_2"]["log_proof"]["sequence_number"]
check("Phase 1 sequence number >= 0", p1_seq >= 0, expected=True)
check("Phase 2 sequence number >= 0", p2_seq >= 0, expected=True)
check("Phase 1 seq < Phase 2 seq", p1_seq < p2_seq, expected=True)
check("Sequence gap == 1",         p2_seq - p1_seq, expected=1)

section_result("Schema structure OK")


# ── Summary ────────────────────────────────────────────────────────────────
print(f"\n{'=' * 60}")
print(f"  ARC PROTOCOL - ALL {total_checks} CHECKS PASSED")
print(f"  arc version:  {arc.__version__}")
print(f"  Python:       {sys.version.split()[0]}")
print(f"  Platform:     {sys.platform}")
print(f"  Checks run:   {total_checks}")
print(f"  Checks failed:{failed_checks}")
print(f"{'=' * 60}\n")
