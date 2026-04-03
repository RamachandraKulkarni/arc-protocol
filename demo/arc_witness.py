"""
ARC Protocol - Full Witness Script
Runs the Replit scenario and exposes EVERYTHING ARC does internally:
  - Snapshot contents (what was captured, where, file-by-file)
  - Log entries (every Phase 1 and Phase 2 entry with Merkle proofs)
  - Signing payloads (exactly what the provider signed)
  - Fabrication detection (what changed, why it failed)
  - Rollback mechanics (what was restored, byte-by-byte match)
  - Merkle tree consistency (both passes)

Usage:
    pip install arc-protocol --prefer-binary
    python arc_witness.py
"""

import base64
import copy
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

# ── Helpers ────────────────────────────────────────────────────────────────

W  = 60   # line width

def banner(title):
    pad = W - len(title) - 4
    left = pad // 2
    right = pad - left
    print(f"\n{'#' * W}")
    print(f"##  {' ' * left}{title}{' ' * right}  ##")
    print(f"{'#' * W}")

def section(title):
    print(f"\n{'─' * W}")
    print(f"  {title}")
    print(f"{'─' * W}")

def field(label, value, indent=4):
    prefix = " " * indent
    label_w = 28
    print(f"{prefix}{label:<{label_w}} {value}")

def subfield(label, value, indent=6):
    prefix = " " * indent
    label_w = 26
    print(f"{prefix}{label:<{label_w}} {value}")

def ok(msg):
    print(f"  \u2713  {msg}")

def fail(msg):
    print(f"  \u2717  {msg}")
    sys.exit(1)

def short(s, n=52):
    s = str(s)
    return s if len(s) <= n else s[:n] + "..."

def bytes_human(n):
    if n < 1024:
        return f"{n} B"
    return f"{n/1024:.1f} KB"


# ── Imports ────────────────────────────────────────────────────────────────

banner("ARC PROTOCOL  FULL WITNESS")

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
    from arc.signing import build_signing_payload, canonical_json
    from arc.snapshot import rollback_filesystem
    ok(f"arc-protocol {arc.__version__} imported")
    ok(f"Python {sys.version.split()[0]}  |  Platform: {sys.platform}")
except ImportError as e:
    fail(f"Import failed: {e}")


# ── Setup ──────────────────────────────────────────────────────────────────

banner("STEP 1  SETUP")

provider_kp = ARCKeyPair.generate()
log         = ARCInMemoryLog()
store       = SnapshotStore()

ctx = ARCContext(
    agent_id        = "autonomous-agent",
    model_version   = "agent-v1",
    session_id      = "witness-session-001",
    provider_keypair = provider_kp,
    provider_name   = "filesystem-tool-v1",
    log             = log,
    snapshot_store  = store,
    on_behalf_of    = "operator@company.com",
)

section("Provider keypair")
field("provider_id",      "filesystem-tool-v1")
field("public_key_hex",   provider_kp.public_key_hex)
field("key_length",       f"{len(provider_kp.public_key_hex) // 2} bytes (Ed25519)")

section("Log")
field("log_id",           log.log_id)
field("log_operator_key", log._keypair.public_key_hex)
field("storage",          "ARCInMemoryLog (in-process Merkle tree)")
field("initial_root",     log.get_root()["merkle_root"])

# Create production-like files
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

original = {
    f: Path(workdir, f).read_text()
    for f in sorted(os.listdir(workdir))
}

section("Target directory")
field("path",       workdir)
field("file count", len(original))
for fname, content in sorted(original.items()):
    subfield(fname, f"{len(content)} bytes")


# ── Phase 1 (before execution) ─────────────────────────────────────────────

banner("STEP 2  PHASE 1  PRE-ACTION SNAPSHOT AND INTENT")

@signed_tool(resource="filesystem", resource_uri_from_args="path")
def delete_directory(path: str, ctx: ARCContext) -> dict:
    shutil.rmtree(path)
    return {"status": "deleted", "path": path, "files_removed": 3}

t0 = time.perf_counter()
receipt = delete_directory(workdir, ctx=ctx)
elapsed_ms = int((time.perf_counter() - t0) * 1000)

p1       = receipt["phase_1"]
p2       = receipt["phase_2"]
snap_ref = p1["before_state"]["snapshot_ref"]
snap     = store.retrieve(snap_ref)

# ── Snapshot internals ─────────────────────────────────────────────────────

section("Snapshot — what was captured")
field("snapshot_ref",        snap.snapshot_ref)
field("resource_uri",        snap.resource_uri)
field("resource_type",       snap.resource_type)
field("captured_at",         snap.captured_at)
field("snapshot_hash",       snap.snapshot_hash)
field("snapshot_size",       bytes_human(snap.snapshot_size_bytes))
field("is_reversible",       snap.is_reversible)
field("storage_location",    "SnapshotStore._memory[snapshot_ref]")

section("Snapshot — file-by-file contents")
snap_content = snap.content
field("type",       snap_content["type"])
field("path",       snap_content["path"])
field("file_count", snap_content["file_count"])

for i, f in enumerate(snap_content["files"]):
    print(f"\n    File {i+1}: {Path(f['path']).name}")
    subfield("full_path",      f["path"])
    subfield("relative_path",  f["relative_path"])
    subfield("size",           f"{f['size']} bytes")
    subfield("sha256",         f["sha256"])
    subfield("mtime",          f"{f['mtime']:.3f}")
    # Decode and show first 80 chars of content
    decoded = base64.b64decode(f["content_b64"]).decode("utf-8", errors="replace")
    preview = decoded.replace("\n", " | ")[:80]
    subfield("content_preview", f'"{preview}..."')
    subfield("content_b64",    f["content_b64"][:40] + "...")

section("Phase 1 intent declaration")
intent = p1["intent"]
field("intent_id",           intent["intent_id"])
field("tool_name",           intent["tool_name"])
field("agent_id",            intent["declared_by"]["agent_id"])
field("model_version",       intent["declared_by"]["model_version"])
field("session_id",          intent["declared_by"]["session_id"])
field("on_behalf_of",        intent["on_behalf_of"])
field("declared_at",         intent["declared_at"])
field("reasoning_commitment",intent["reasoning_commitment"])
print("\n    arguments:")
for k, v in intent["arguments"].items():
    subfield(k, short(v))

section("Phase 1 log commitment")
lc1 = p1["log_commitment"]
field("log_id",         lc1["log_id"])
field("sequence_number",lc1["sequence_number"])
field("merkle_root",    lc1["merkle_root"])
field("committed_at",   lc1["committed_at"])
field("inclusion_proof",f"[{len(lc1.get('inclusion_proof', []))} sibling hashes]")


# ── Execution and Phase 2 ──────────────────────────────────────────────────

banner("STEP 3  EXECUTION AND PHASE 2  PROVIDER ATTESTATION")

section("Execution result")
ex = p2["execution"]
field("outcome",        ex["outcome"])
field("outcome_hash",   ex["outcome_hash"])
field("started_at",     ex["started_at"])
field("completed_at",   ex["completed_at"])
field("duration_ms",    ex["duration_ms"])
field("directory_gone", not Path(workdir).exists())

section("Signing payload — exactly what the provider signed")
signing_payload = build_signing_payload(
    receipt_id        = receipt["receipt_id"],
    intent_id         = intent["intent_id"],
    outcome_hash      = ex["outcome_hash"],
    before_state_hash = p1["before_state"]["snapshot_hash"],
    signed_at         = p2["provider_attestation"]["signed_at"],
    outcome           = ex["outcome"],
    is_reversible     = p2["inverse"]["is_reversible"],
)
payload_obj = {
    "before_state_hash": p1["before_state"]["snapshot_hash"],
    "intent_id":         intent["intent_id"],
    "is_reversible":     p2["inverse"]["is_reversible"],
    "outcome":           ex["outcome"],
    "outcome_hash":      ex["outcome_hash"],
    "receipt_id":        receipt["receipt_id"],
    "signed_at":         p2["provider_attestation"]["signed_at"],
}
print("\n    canonical_json (sorted keys, no whitespace):")
print(f"    {json.dumps(payload_obj, sort_keys=True, separators=(',',':'))[:W-4]}")
print("\n    sha256 of canonical_json  (this is what gets signed):")
print(f"    {signing_payload.decode()}")

section("Provider attestation")
att = p2["provider_attestation"]
field("provider_id",         att["provider_id"])
field("provider_name",       att["provider_name"])
field("signed_at",           att["signed_at"])
field("signature",           att["signature"][:50] + "...")
field("signed_payload_hash", att["signed_payload_hash"])
field("signature_verified",  provider_kp.verify(signing_payload, att["signature"]))

section("Inverse operation (rollback specification)")
inv = p2["inverse"]
field("is_reversible",     inv["is_reversible"])
field("inverse_tool",      inv["inverse_tool"])
field("valid_until",       inv["valid_until"])
field("inverse_signature", inv["inverse_signature"][:50] + "...")
print("\n    inverse_arguments:")
for k, v in inv["inverse_arguments"].items():
    subfield(k, short(v))

section("Phase 2 log commitment")
lc2 = p2["log_proof"]
field("sequence_number", lc2["sequence_number"])
field("merkle_root",     lc2["merkle_root"])
field("committed_at",    lc2["committed_at"])
field("seq gap (p2-p1)", lc2["sequence_number"] - lc1["sequence_number"])


# ── Log internals ──────────────────────────────────────────────────────────

banner("STEP 4  TRANSPARENCY LOG  INTERNAL ENTRIES")

section("Log state after receipt committed")
root = log.get_root()
field("total entries",   root["sequence_number"] + 1)
field("current root",    root["merkle_root"])
field("log_signature",   root["log_signature"][:50] + "...")

print(f"\n  All log entries for receipt {receipt['receipt_id']}:")
vr_log = log.verify(receipt["receipt_id"])

for entry in vr_log["entries"]:
    print(f"\n    ── Entry (seq {entry['sequence_number']}) ─────────────")
    subfield("entry_id",      entry["entry_id"])
    subfield("entry_type",    entry["entry_type"])
    subfield("receipt_id",    entry["receipt_id"])
    subfield("content_hash",  entry["content_hash"])
    subfield("previous_root", entry["previous_root"])
    subfield("merkle_root",   entry["merkle_root"])
    subfield("timestamp",     entry["timestamp"])
    subfield("log_signature", entry["log_signature"][:40] + "...")

section("Log consistency check (both passes)")
consistency = log.verify_consistency()
field("is_consistent",  consistency["is_consistent"])
field("entry_count",    consistency["entry_count"])
field("errors",         consistency["errors"] if consistency["errors"] else "none")
field("pass_1",         "Merkle root chain: entry[n].merkle_root == entry[n+1].previous_root")
field("pass_2",         "Content integrity: rebuilt tree root matches stored final root")

if not consistency["is_consistent"]:
    fail(f"Log inconsistency: {consistency['errors']}")
ok("Both Merkle consistency passes: PASSED")


# ── Full receipt JSON ──────────────────────────────────────────────────────

banner("STEP 5  FULL RECEIPT JSON")

# Print receipt with sensitive fields truncated for readability
printable = copy.deepcopy(receipt)
attest = printable["phase_2"]["provider_attestation"]
attest["signature"]           = attest["signature"][:30] + "..."
attest["signed_payload_hash"] = attest["signed_payload_hash"][:30] + "..."
inv2 = printable["phase_2"]["inverse"]
if "inverse_signature" in inv2:
    inv2["inverse_signature"] = inv2["inverse_signature"][:30] + "..."
printable["phase_1"]["before_state"]["snapshot_hash"] = (
    printable["phase_1"]["before_state"]["snapshot_hash"][:30] + "..."
)
printable["phase_1"]["log_commitment"]["merkle_root"] = (
    printable["phase_1"]["log_commitment"]["merkle_root"][:30] + "..."
)
printable["phase_2"]["log_proof"]["merkle_root"] = (
    printable["phase_2"]["log_proof"]["merkle_root"][:30] + "..."
)
printable["phase_2"]["execution"]["outcome_hash"] = (
    printable["phase_2"]["execution"]["outcome_hash"][:30] + "..."
)

print(json.dumps(printable, indent=2))


# ── Fabrication detection ──────────────────────────────────────────────────

banner("STEP 6  FABRICATION DETECTION")

section("Attack: agent reports nothing was deleted")
fake_result  = {"status": "no_action", "files_removed": 0, "message": "directory was empty"}
fake_hash    = sha256_hex(canonical_json(fake_result))
real_hash    = ex["outcome_hash"]

field("real outcome_hash",  real_hash)
field("fake outcome_hash",  fake_hash)
field("hashes match",       real_hash == fake_hash)

tampered = copy.deepcopy(receipt)
tampered["phase_2"]["execution"]["outcome_hash"] = fake_hash

registry = {"filesystem-tool-v1": provider_kp.public_key_hex}
detection = verify_receipt(tampered, registry)

section("verify_receipt() on tampered receipt")
field("valid",         detection["valid"])
field("error",         detection["errors"][0] if detection["errors"] else "none")
for check_name, check_val in detection["checks"].items():
    field(f"  check: {check_name}", check_val)

if detection["valid"] is not False:
    fail("Fabrication was NOT detected — this is a protocol failure")
ok("Fabrication detected correctly")

section("verify_receipt() on real receipt")
real_check = verify_receipt(receipt, registry)
field("valid",  real_check["valid"])
for check_name, check_val in real_check["checks"].items():
    field(f"  check: {check_name}", check_val)

if real_check["valid"] is not True:
    fail(f"Real receipt failed verification: {real_check['errors']}")
ok("Real receipt verifies correctly")


# ── Rollback ───────────────────────────────────────────────────────────────

banner("STEP 7  ROLLBACK EXECUTION")

section("Before rollback")
field("directory exists",   Path(workdir).exists())
field("snapshot_ref",       snap_ref)
field("snapshot_hash",      snap.snapshot_hash)
field("files in snapshot",  snap.content["file_count"])

t_rb = time.perf_counter()
success = rollback_filesystem(snap)
rb_ms = int((time.perf_counter() - t_rb) * 1000)

section("After rollback")
field("rollback_result",    success)
field("rollback_time_ms",   rb_ms)
field("directory exists",   Path(workdir).exists())

restored = {
    f: Path(workdir, f).read_text()
    for f in sorted(os.listdir(workdir))
}
field("files restored",     len(restored))

section("File-by-file verification")
all_match = True
for fname in sorted(original.keys()):
    orig_bytes   = len(original[fname].encode())
    rest_bytes   = len(restored.get(fname, "").encode())
    content_ok   = restored.get(fname) == original[fname]
    sha_original = sha256_hex(original[fname].encode())
    sha_restored = sha256_hex(restored.get(fname, "").encode())
    print(f"\n    {fname}")
    subfield("original size",      f"{orig_bytes} bytes")
    subfield("restored size",      f"{rest_bytes} bytes")
    subfield("original sha256",    sha_original)
    subfield("restored sha256",    sha_restored)
    subfield("content exact match", content_ok)
    if not content_ok:
        all_match = False

shutil.rmtree(workdir)

if not all_match:
    fail("Content mismatch after rollback")
ok("All files restored with exact byte content")


# ── Final summary ──────────────────────────────────────────────────────────

banner("COMPLETE SUMMARY")

print(f"""
  Receipt ID:      {receipt['receipt_id']}
  Protocol:        ARC v{arc.__version__}
  Agent:           {ctx.agent_id}
  Provider:        filesystem-tool-v1

  Snapshot:
    ref:           {snap_ref}
    files:         {snap.content['file_count']}
    size:          {bytes_human(snap.snapshot_size_bytes)}
    hash:          {snap.snapshot_hash[:40]}...

  Log:
    Phase 1 seq:   {lc1['sequence_number']}
    Phase 2 seq:   {lc2['sequence_number']}
    total entries: {consistency['entry_count']}
    consistent:    {consistency['is_consistent']}

  Signing:
    payload fields: before_state_hash, intent_id, is_reversible,
                    outcome, outcome_hash, receipt_id, signed_at
    algorithm:      Ed25519

  Tests:
    fabrication detected:   {detection['valid'] is False}
    real receipt valid:     {real_check['valid'] is True}
    rollback succeeded:     {success}
    all files restored:     {all_match}
    log consistent:         {consistency['is_consistent']}
    total elapsed ms:       {elapsed_ms}

{'=' * 60}
  ARC WITNESS: ALL CHECKS PASSED
{'=' * 60}
""")
