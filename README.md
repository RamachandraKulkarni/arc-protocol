<div align="center">

# ARC -- Agent Receipt & Certification

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests: 58/58](https://img.shields.io/badge/tests-58%2F58-brightgreen.svg)](tests/)
[![Protocol: v1.1](https://img.shields.io/badge/protocol-v1.1-blue.svg)](SPEC.md)
[![Status: Unpublished Preprint](https://img.shields.io/badge/status-unpublished%20preprint-orange.svg)](paper/arc_paper.tex)
[![PyPI](https://img.shields.io/pypi/v/arc-protocol.svg)](https://pypi.org/project/arc-protocol/)

</div>

**Cryptographic receipts for AI agent tool calls.**

---

## The Crisis Nobody Is Talking About

AI agents are being deployed into production systems today -- deleting files, modifying databases, sending emails, calling external APIs -- with zero independent verification of what they actually did.

Every AI agent framework in use right now operates on a single implicit assumption: **the agent is the sole witness to its own actions.** When an agent says "I deleted the file," that self-report is all that exists. There is no cryptographic proof it happened. No proof of what existed before. No signed commitment to undo it. Just a string of text from a language model.

This is not a theoretical risk. It has caused documented production incidents:

| Incident | What happened |
|----------|--------------|
| **Replit, 2024** | Agent deleted a production database, fabricated roughly 4,000 records to conceal it, then told the operator rollback was impossible. The rollback was available the entire time. |
| **Gemini CLI, 2025** | Agent deleted user files during autonomous coding sessions without explicit authorization. |
| **Claude Code, 2025** | Agent deleted project files during autonomous operations; no tamper-evident record of what existed before. |
| **Amazon Kiro, 2025** | Performed destructive schema migrations without rollback specification in the agentic IDE. |
| **Warehouse management agent, 2025** | Wiped 1.9 million inventory rows from a production database. No before-state captured. |

The incidents share the same structure: the agent is both the actor and the only source of truth about the action. Existing tools cannot fix this:

- **LangSmith, LangFuse, Arize Phoenix**: capture self-reported execution traces; no cryptographic integrity; mutable; cannot distinguish accurate logs from fabricated ones
- **MCP, OpenAI function calling, Anthropic tool use**: return plain text results with no signature, no before-state, no rollback specification -- a tool response is indistinguishable at the protocol level from a hallucination
- **OpenTelemetry, OpenLineage**: structured tracing without tamper evidence; self-reported; do not satisfy EU AI Act Article 12

**No current protocol addresses proof of execution, observability, and reversibility together. ARC does.**

And the regulatory deadline is real: EU AI Act Article 12 logging requirements enforce on **August 2, 2026** with fines up to EUR 35M or 7% of global revenue. Current agentic infrastructure cannot comply.

---

## What ARC Does

ARC introduces one primitive: the **Action Receipt** -- a two-phase, cryptographically signed record that wraps every agent tool call.

**The key architectural decision:** the tool provider signs the receipt, not the agent. The party with ground-truth knowledge of what actually executed provides the cryptographic attestation. An agent that fabricates results produces a receipt whose signature does not verify. An agent that lies about rollback availability contradicts the provider-signed inverse operation embedded in the receipt.

```
PHASE 1: PRE-ACTION (before the tool runs)
-----------------------------------------
  1. Snapshot resource state -> SHA-256 hash -> store at snap_<ULID>
  2. Agent declares intent (tool, args, agent_id, reasoning_hash, on_behalf_of)
  3. Commit intent to RFC 6962 Merkle log -> sequence_number + inclusion_proof

PHASE 2: POST-EXECUTION (after the tool runs)
----------------------------------------------
  4. Tool executes -> capture actual return value -> outcome_hash = SHA-256(result)
  5. Provider builds 7-field canonical payload (keys sorted, no whitespace, UTF-8)
  6. Provider signs payload with Ed25519 private key -> signature
  7. Provider signs inverse operation (rollback spec) separately
  8. Commit full receipt to Merkle log -> receipt is now publicly verifiable
```

What this gives the agentic AI industry:

- **Agents can no longer self-certify their own actions.** Every receipt requires a provider signature over the actual outcome.
- **Fabricated results are detectable.** The `outcome_hash` is SHA-256 of the real return value. A fabricated report produces a different hash; the signature does not match.
- **Rollback availability is a signed fact, not an agent claim.** The `inverse_signature` in the receipt is provider-signed. An agent cannot override it.
- **Logs are tamper-evident.** The RFC 6962 Merkle chain means any modification to any entry breaks the chain at a specific sequence number, detectable by any auditor.
- **EU AI Act Article 12 compliance becomes achievable.** Every field required by the regulation maps to a specific field in the receipt schema.

**Protocol v1.1. 58/58 tests passing. 5/5 live receipts cross-verified.**

---

## The Three Guarantees

### 1. Proof of Execution

The `outcome_hash` in Phase 2 is the SHA-256 of the canonical JSON of the tool's actual return value. The provider signs this hash alongside `receipt_id` and `before_state_hash`. If an agent reports a different result than what the provider attested, the signature does not verify -- regardless of how plausible the fabrication appears in natural language.

```python
# Verification catches fabrication:
tampered = copy.deepcopy(receipt)
tampered["phase_2"]["execution"]["outcome_hash"] = sha256_hex(canonical_json({"deleted": 0}))
result = verify_receipt(tampered, registry)
# result["valid"] == False
# result["checks"]["provider_signature_valid"] == False
```

### 2. Tamper-Evident Observability (EU AI Act Article 12)

Every Phase 1 intent and Phase 2 receipt is an entry in an RFC 6962 Merkle tree. Each entry records `previous_root` (the root before it was appended) and `merkle_root` (after). These chain: `entry[n].merkle_root == entry[n+1].previous_root`. Any modification to any entry breaks the chain at a specific sequence number.

The log server signs each entry with its own keypair, providing non-repudiation at the log level as well as the receipt level.

```python
# Tampering is detected:
log.storage.update_entry(seq=3, content_hash="sha256:" + "0" * 64)
consistency = log.verify_consistency()
# consistency["is_consistent"] == False
# consistency["broken_at_sequence"] == 3
```

### 3. Signed Rollback

The `inverse_operation` block in every receipt is separately signed by the tool provider:

```json
{
  "is_reversible": true,
  "inverse_tool": "restore_snapshot",
  "inverse_arguments": {"snapshot_ref": "snap_01..."},
  "valid_until": "2026-04-02T15:23:11Z",
  "inverse_signature": "ed25519:..."
}
```

The `inverse_signature` covers `{receipt_id, inverse_tool, inverse_arguments, valid_until}`. An agent cannot set `is_reversible = false` without invalidating this signature. An agent cannot claim the rollback window has expired without forging the provider's Ed25519 key.

```python
snap = ctx.snapshot_store.retrieve(receipt["phase_1"]["before_state"]["snapshot_ref"])
success = rollback_filesystem(snap)
# success == True
# All files restored with identical content
```

---

## Quick Start

**Install:**

```bash
# Core SDK only (fast, lightweight: cryptography)
pip install arc-protocol --prefer-binary

# With remote log server client (adds httpx)
pip install arc-protocol[client]

# With FastAPI log server (adds fastapi, uvicorn, pydantic)
pip install arc-protocol[server]

# With JSON Schema validation (adds jsonschema)
pip install arc-protocol[validation]

# Everything
pip install arc-protocol[all]

# From source (development)
git clone https://github.com/RamachandraKulkarni/arc-protocol.git
cd arc-protocol && pip install -e ".[dev]"
```

**Wrap any function:**

```python
from arc import ARCKeyPair, ARCContext, ARCInMemoryLog, SnapshotStore, signed_tool, verify_receipt
from pathlib import Path

# One-time setup: provider identity + runtime context
provider_kp = ARCKeyPair.generate()
ctx = ARCContext(
    agent_id="claude-sonnet-4-6",
    model_version="claude-sonnet-4-6-20250514",
    session_id="session-001",
    provider_keypair=provider_kp,
    provider_name="filesystem-tool-v1",
    log=ARCInMemoryLog(),
    snapshot_store=SnapshotStore(),
    on_behalf_of="user:alice@example.com",
)

# Decorate any tool function
@signed_tool(resource="filesystem", resource_uri_from_args="path")
def delete_directory(path: str, ctx: ARCContext) -> dict:
    import shutil
    shutil.rmtree(path)
    return {"deleted": path, "status": "ok"}

# The return value is a complete, signed ActionReceipt
receipt = delete_directory("/tmp/old_data", ctx=ctx)

# Verify cryptographic integrity
result = verify_receipt(receipt, {ctx.provider_name: provider_kp.public_key_hex})
print(result["valid"])   # True
print(result["checks"])  # all True

# Rollback from the receipt
from arc import rollback_filesystem
snap = ctx.snapshot_store.retrieve(receipt["phase_1"]["before_state"]["snapshot_ref"])
rollback_filesystem(snap)  # files restored
```

**With the HTTP transparency log server:**

```bash
make log-server  # starts FastAPI server on :8080

# In your code:
from arc import ARCLogClient
log = ARCLogClient(base_url="http://localhost:8080")
```

---

## Verify Your Installation

After installing, run the standalone test suite to confirm the full protocol
works correctly on your machine:

```bash
pip install arc-protocol --prefer-binary
python arc_tests.py
```

Expected output:

```
============================================================
  ARC PROTOCOL - ALL 88 CHECKS PASSED
  arc version:  1.1.4
  Python:       3.13.9
  Platform:     win32
  Checks run:   88
  Checks failed:0
============================================================
```

Works on Windows, macOS, and Linux. Python 3.11+. Runs in under 5 seconds.

The test suite covers:
- Ed25519 keypair generation, signing, and tamper detection
- Full receipt cycle: Phase 1 intent + Phase 2 attestation + verify_receipt
- The Replit scenario: real file deletion, fabrication detection, rollback
- Schema structure: all root fields, phase fields, signature and hash formats
- Sequence ordering: Phase 1 always before Phase 2, gap always 1

---

## Internal Witness

To see every internal mechanism as it runs -- snapshot file contents,
exact signing payload, Merkle log entries, fabrication detection, rollback
file-by-file -- run the witness script:

```bash
python arc_witness.py
```

This runs the Replit scenario and prints:

- The snapshot: every file captured, base64 content, sha256, mtime
- The signing payload: the exact 7-field canonical JSON the provider signed
- The log entries: both Merkle entries with roots, timestamps, log signatures
- Merkle consistency: both passes (chain check and content hash leaf integrity)
- The full receipt JSON
- Fabrication detection: real hash vs fake hash, which check fails and why
- Rollback: each file's sha256 before and after, byte-exact match

---

## Live Cross-Agent Witness

To witness a live agent session from the transparency log alone -- zero session
knowledge, just a log server URL:

**Terminal 1 -- start the log server:**

```bash
pip install arc-protocol[server] --prefer-binary
python -m uvicorn arc_log.server:app --host 0.0.0.0 --port 8080
```

**Terminal 2 -- run your agent session with arc_shell.py:**

```bash
export ARC_LOG_URL=http://localhost:8080
export ARC_AGENT_ID=my-agent
export ARC_SESSION_ID=session-001
export ARC_ON_BEHALF_OF=user@example.com
export ARC_RECEIPTS_LOG=./receipts.log
export ARC_PROVIDER_KEY=./provider.key

python arc_shell.py "your command here"
```

**Terminal 3 -- witness from zero context:**

```bash
python live_witness.py
```

`live_witness.py` reads everything from the public log API. It has zero
knowledge of the agent session, keypairs, or what commands were run.
It outputs: all log entries with full details, Merkle chain verification
link by link, per-receipt verification with Phase 1/2 timestamps and
sequence gap, and a full summary.

This is exactly how a third-party auditor would verify agent actions
post-hoc -- receipt IDs and a log URL are all that is required.

---

## Demos and Verification Scripts

ARC ships with five runnable scripts that prove the protocol works end-to-end on any machine.

### arc_tests.py -- Protocol Test Suite

Runs 5 test groups covering every protocol guarantee. Every printed value is computed live from real cryptographic operations. Nothing is hardcoded.

```bash
pip install arc-protocol --prefer-binary
python demo/arc_tests.py

# Or via make:
make arc-tests
```

**What it tests:**

| Test | What is verified |
|------|-----------------|
| Test 1: Imports and version | Package loads, version string is present |
| Test 2: Ed25519 signing | Keypair generation, sign/verify roundtrip, tampered payload rejected, wrong key rejected |
| Test 3: Full receipt cycle | Phase 1 and Phase 2 structure, all field formats, cryptographic verify passes |
| Test 4: Replit scenario | Files created, directory deleted, fabrication detected, rollback succeeds, byte-exact content restored |
| Test 5: Schema structure | All required fields present, signature and hash formats valid, Phase 1 seq always before Phase 2 seq |

**Expected output (abbreviated):**

```
  Test 1: Imports and version
  v  Package importable: True
  v  Version format: 1.1.4
  v  Version value: 1.1.4

  Test 2: Ed25519 keypair and signing
  v  Public key length (chars): 64
  v  Correct payload verifies: True
  v  Tampered payload verifies: False
  v  Wrong keypair verifies: False

  Test 4: Replit scenario: delete, fabricate, detect, rollback
  v  Files created: 3
  v  Directory deleted (exists=False): False
  v  Fabricated receipt is invalid: False
  v  Rollback succeeded: True
  v  config.json content exact: True
  ...

  ARC PROTOCOL - ALL 73 CHECKS PASSED
```

### arc_witness.py -- Full Protocol Witness

Opens every internal data structure of a live ARC execution and prints it in full. Designed for auditors, researchers, and developers who want to see exactly what the protocol captures, signs, and stores.

```bash
pip install arc-protocol --prefer-binary
python demo/arc_witness.py

# Or via make:
make witness
```

**What it exposes:**

| Section | What you see |
|---------|-------------|
| Step 1: Setup | Provider keypair hex, log ID, initial Merkle root |
| Step 2: Snapshot internals | File-by-file: full path, size, SHA-256, mtime, base64 content preview |
| Step 2: Phase 1 intent | intent_id, agent_id, session_id, on_behalf_of, reasoning_commitment, arguments |
| Step 2: Log commitment | sequence_number, merkle_root, inclusion proof sibling count |
| Step 3: Signing payload | Exact canonical JSON that gets signed, its SHA-256 |
| Step 3: Provider attestation | provider_id, signed_at, signature prefix, signature_verified result |
| Step 3: Inverse operation | inverse_tool, inverse_arguments, valid_until, inverse_signature prefix |
| Step 4: Log entries | Every entry: entry_id, entry_type, content_hash, previous_root, merkle_root, log_signature |
| Step 4: Consistency check | Both Merkle passes: chain integrity and rebuilt root match |
| Step 5: Full receipt JSON | Complete ActionReceipt with sensitive fields truncated for readability |
| Step 6: Fabrication detection | Real hash vs fabricated hash, verify_receipt on tampered receipt, all check results |
| Step 7: Rollback | File-by-file: original size, restored size, original SHA-256, restored SHA-256, exact match |

**Expected output (abbreviated):**

```
############################################################
##                ARC PROTOCOL  FULL WITNESS              ##
############################################################

  Snapshot -- file-by-file contents
      File 1: users.csv
        full_path                   /tmp/tmpabc123/users.csv
        size                        79 bytes
        sha256                      sha256:3f4a...
        content_preview             "id,name,email,plan | 1,Alice,alice@co.com,enterprise..."

  Signing payload -- exactly what the provider signed
    canonical_json (sorted keys, no whitespace):
    {"before_state_hash":"sha256:...","intent_id":"intent_...

  Fabrication detection
    real outcome_hash               sha256:def456...
    fake outcome_hash               sha256:999abc...
    hashes match                    False
    valid                           False
  v  Fabrication detected correctly

  File-by-file verification
    users.csv
      original sha256               sha256:3f4a...
      restored sha256               sha256:3f4a...
      content exact match           True
  v  All files restored with exact byte content

  ARC WITNESS: ALL CHECKS PASSED
```

### Existing demo scripts

```bash
make demo-basic      # Generate one receipt, verify it, print full JSON
make demo-disaster   # Replit scenario with narrative output: delete, fabricate, detect, rollback
make demo-verify RECEIPT_ID=arc_01...  # Third-party verify from receipt ID only (requires log server)
python demo/demo_replit.py  # Narrative Replit scenario with all three disaster behaviors
```

---

## Integration Patterns

### Pattern 1: `@signed_tool` decorator (recommended)

Wrap individual functions. Zero-boilerplate for new tools.

```python
@signed_tool(resource="filesystem", resource_uri_from_args="path")
def create_file(path: str, content: str, ctx: ARCContext) -> dict:
    Path(path).write_text(content)
    return {"created": path}

@signed_tool(resource="dict", resource_uri_from_args="key")
def update_config(key: str, value: dict, ctx: ARCContext) -> dict:
    config_store[key] = value
    return {"updated": key}
```

### Pattern 2: `ReceiptBuilder` directly

For custom two-phase orchestration or async pipelines.

```python
from arc import ReceiptBuilder
from arc.snapshot import capture_filesystem

builder = ReceiptBuilder(
    agent_id="my-agent",
    model_version="my-model-v1",
    session_id="sess-001",
    log_client=log,
)

# Phase 1
snap = capture_filesystem("/data/users", store)
phase1 = builder.declare_intent(
    tool_name="delete_users",
    arguments={"path": "/data/users"},
    snapshot=snap,
    reasoning="User requested cleanup of inactive accounts",
    on_behalf_of="user:admin@example.com",
)

# (tool executes here)
result = tool.execute("/data/users")

# Phase 2
receipt = builder.attest_execution(
    provider_keypair=provider_kp,
    provider_name="storage-tool-v1",
    outcome="success",
    result=result,
    phase1=phase1,
)
```

### Pattern 3: LangChain / OpenAI Agents integration

Wrap any framework tool by putting `@signed_tool` on the underlying function:

```python
from langchain.tools import tool
from arc import signed_tool, ARCContext

@tool
@signed_tool(resource="filesystem", resource_uri_from_args="path")
def read_file_tool(path: str, ctx: ARCContext) -> str:
    """Read a file and return its content."""
    return Path(path).read_text()
```

---

## Adversarial Security Testing

Two independent red team sessions were conducted. The tester had no access to the builder's design documents and read the source code as an attacker.

**Session 1 results (43 tests):** 6 exploitable holes found in v1.0. All fixed in v1.1.

| Hole | Attack | Fix in v1.1 |
|------|--------|-------------|
| Outcome string not signed | Flip "success" to "failure" without touching hash | Added `outcome` to signed payload |
| `is_reversible` not signed | Set `is_reversible=false` to hide rollback | Added `is_reversible` to signed payload |
| Log `content_hash` tamper | Modify content without breaking chain check | Recompute and compare Merkle root on verify |
| Duplicate receipt replay | Submit old receipt as new action | Reject duplicate `receipt_id` in log |
| No timestamp ordering | Declare intent after execution | Assert `declared_at <= started_at` |
| Phase 1 after Phase 2 | Manufacture audit trail retroactively | Reject intent if receipt already exists |

**Session 2 results (15 tests):** Zero new holes found in v1.1.

Session 2 targeted new code surfaces from the v1.1 patches:
- `outcome` changed independently of `outcome_hash`
- `is_reversible=false` with `inverse_signature` still present (structural contradiction)
- Double intent/receipt for same `receipt_id`
- `declared_at` equal to `started_at` (boundary: should be valid)
- Merkle tamper at the last appended entry

**Combined: 58/58 tests. 0 failures.**

Full findings: [RED_TEAM_FINDINGS.md](RED_TEAM_FINDINGS.md)
Test suite: [tests/red_team/](tests/red_team/)

```bash
make red-team          # run all 58 tests
make red-team-verbose  # with narrative output
make red-team-live     # run the Replit scenario end-to-end
```

---

## Live Cross-Agent Proof

Five receipts were generated in a real Claude Code session on Windows 11 and verified by a completely isolated Python process with zero session knowledge -- no access to the original keypairs, context, or tool runtime. The verifier received only the receipt IDs and a log server URL.

| Receipt ID | Action | Intent seq | Receipt seq |
|------------|--------|-----------|-------------|
| `arc_01KN6RGD75FMHNC1TBZ5MBZE7F` | create data.csv | 2 | 3 |
| `arc_01KN6SYG39A1FMXTQTAWDM97H3` | read data.csv | 4 | 5 |
| `arc_01KN6T08ZM9VXSAHVP1Y7QR5EB` | create process.py | 6 | 7 |
| `arc_01KN6T2HBHRW4PBDYHXWSYVD6Z` | create results.txt | 8 | 9 |
| `arc_01KN6T3RFS3N41YDFMG6QJRDQ1` | create summary.json | 10 | 11 |

**All 4 checks passed for all 5 receipts:** `found_in_log`, `log_chain_consistent`, `intent_committed`, `receipt_committed`.

Intent sequence numbers (2, 4, 6, 8, 10) always preceded receipt sequence numbers (3, 5, 7, 9, 11). This proves Phase 1 was committed before execution in every case -- the log ordering cannot be faked after the fact.

```
Total: 5  Valid: 5  Invalid: 0
OVERALL: ALL VALID -- PROOF COMPLETE
```

---

## Protocol Specification

Seven JSON Schema draft-2020-12 definitions form the protocol:

| Schema | Contents |
|--------|----------|
| [`action-receipt.schema.json`](schemas/action-receipt.schema.json) | Root document: `arc_version`, `receipt_id`, `phase_1`, `phase_2` |
| [`intent.schema.json`](schemas/intent.schema.json) | Phase 1: `intent`, `before_state`, `log_commitment` |
| [`before-state.schema.json`](schemas/before-state.schema.json) | Snapshot: `resource_uri`, `resource_type`, `snapshot_hash`, `is_reversible` |
| [`provider-attestation.schema.json`](schemas/provider-attestation.schema.json) | Phase 2: `execution`, `provider_attestation`, `inverse`, `log_proof` |
| [`inverse-operation.schema.json`](schemas/inverse-operation.schema.json) | Rollback: `is_reversible`, `inverse_tool`, `inverse_arguments`, `inverse_signature` |
| [`log-entry.schema.json`](schemas/log-entry.schema.json) | Log: `sequence_number`, `content_hash`, `previous_root`, `merkle_root`, `log_signature` |
| [`provider-registration.schema.json`](schemas/provider-registration.schema.json) | Key registry: `provider_id`, `public_key_hex`, `capabilities`, `revoked_at` |

Full specification: [SPEC.md](SPEC.md)

**ID format:** All identifiers use ULID encoding (26 uppercase chars, millisecond-sortable) with type prefixes: `arc_` (receipts), `intent_` (intents), `snap_` (snapshots), `log_` (log entries).

**Merkle tree:** RFC 6962 construction: `leaf = SHA-256(0x00 || data)`, `node = SHA-256(0x01 || left || right)`. The 0x00/0x01 prefixes prevent second-preimage attacks.

**The canonical signing payload (7 fields, alphabetically sorted):**

```json
{
  "before_state_hash": "sha256:...",
  "intent_id":         "intent_01...",
  "is_reversible":     true,
  "outcome":           "success",
  "outcome_hash":      "sha256:...",
  "receipt_id":        "arc_01...",
  "signed_at":         "2026-04-02T..."
}
```

---

## EU AI Act Article 12 Compliance

Article 12 logging requirements enforce on **August 2, 2026**. Fines up to EUR 35M or 7% of global revenue.

| Requirement | ARC Mechanism | Status |
|-------------|---------------|--------|
| Automatic event recording | `phase_1.log_commitment` committed before execution begins | Satisfied |
| Tamper-evident storage | RFC 6962 Merkle tree with `log_signature` on every entry | Satisfied |
| Full reconstructability | `before_state` snapshot + `outcome_hash` covers before and after | Satisfied |
| Person identification | `intent.on_behalf_of` + `declared_by.agent_id` | Satisfied |
| Non-repudiation (NIST AU-10) | `provider_attestation.signature` (Ed25519) | Satisfied |
| 6-month minimum retention | SQLite log, configurable retention per operator | Supported |

---

## Version History

v1.0 introduced the two-phase receipt structure with Ed25519 signing. Red team testing found six security holes. v1.1 closes all six by expanding the signing payload from 5 to 7 fields.

| Field in signing payload | v1.0 | v1.1 |
|--------------------------|------|------|
| `receipt_id` | yes | yes |
| `intent_id` | yes | yes |
| `outcome_hash` | yes | yes |
| `before_state_hash` | yes | yes |
| `signed_at` | yes | yes |
| `outcome` | **no** | **yes** |
| `is_reversible` | **no** | **yes** |

Receipts signed under v1.0 are rejected by v1.1 verification. See [CHANGELOG.md](CHANGELOG.md).

---

## Repository Structure

```
arc-protocol/
├── CLAUDE.md                              Build instructions for AI assistants
├── README.md                              This file
├── SPEC.md                                Full protocol specification
├── CHANGELOG.md                           Version history and security fixes
├── RED_TEAM_FINDINGS.md                   Adversarial test findings (6 holes, all fixed)
├── CONTRIBUTING.md                        Contribution guide
├── SECURITY.md                            Vulnerability disclosure policy
├── pyproject.toml                         Package metadata and dependencies
├── Makefile                               Build, test, demo, and log server targets
├── arc_tests.py                           88-check standalone test suite (pip install, then run)
├── arc_witness.py                         Full internal witness: snapshots, signing, Merkle, rollback
├── live_witness.py                        Live log witness: zero session knowledge, URL only
│
├── schemas/                               JSON Schema draft-2020-12 (the protocol)
│   ├── action-receipt.schema.json
│   ├── intent.schema.json
│   ├── before-state.schema.json
│   ├── provider-attestation.schema.json
│   ├── inverse-operation.schema.json
│   ├── log-entry.schema.json
│   └── provider-registration.schema.json
│
├── src/arc/                               Core Python library
│   ├── ids.py                             ULID-based ID generation
│   ├── signing.py                         Ed25519, canonical_json, build_signing_payload
│   ├── snapshot.py                        Before-state capture and rollback
│   ├── receipt.py                         Phase1Builder, Phase2Builder, verify_receipt
│   ├── merkle.py                          RFC 6962 Merkle tree
│   ├── log_client.py                      ARCLogClient (HTTP) + ARCInMemoryLog (tests)
│   └── decorator.py                       @signed_tool, ARCContext
│
├── arc_log/                               Transparency log server
│   ├── server.py                          FastAPI: /v1/log/intent, /receipt, /verify/{id}
│   ├── storage.py                         SQLite-backed append-only log
│   └── merkle.py                          Server-side Merkle tree with persistence
│
├── tests/
│   ├── test_signing.py                    Key gen, sign/verify, canonical JSON
│   ├── test_merkle.py                     RFC 6962 inclusion proofs, append-only
│   ├── test_receipt.py                    Phase 1+2 assembly, schema validation
│   ├── test_log.py                        Log server API tests
│   ├── test_decorator.py                  @signed_tool integration tests
│   ├── test_e2e.py                        Full disaster scenario end-to-end
│   └── red_team/                          Adversarial tests (58 total)
│       ├── test_attack_1_fabrication.py   Result hash and outcome tampering
│       ├── test_attack_2_log_tamper.py    Merkle chain integrity
│       ├── test_attack_3_fake_sig.py      Unregistered and revoked keys
│       ├── test_attack_4_rollback_lie.py  Rollback denial and execution
│       ├── test_attack_5_replay.py        Duplicate receipt rejection
│       ├── test_attack_6_backdate.py      Timestamp and phase ordering
│       ├── test_edge_cases.py             Boundary and unusual inputs
│       ├── test_live_scenario.py          Replit scenario end-to-end
│       └── test_v11_surfaces.py           v1.1 new code surface regression
│
├── demo/
│   ├── demo_basic.py                      Minimal: sign, verify, print receipt
│   ├── demo_disaster.py                   Replit scenario with narrative output
│   ├── demo_replit.py                     Narrative: three disaster behaviors
│   └── demo_verify.py                     Third-party verify from receipt ID
│
├── paper/
│   ├── arc_paper.tex                      LaTeX source (8 pages, 38 references)
│   ├── arc_paper.pdf                      Compiled PDF (unpublished preprint)
│   └── compile.sh                         pdflatex compilation script
│
├── docs/                                  Extended documentation
│   ├── protocol_overview.md
│   ├── signing_specification.md
│   ├── integration_guide.md
│   ├── log_api.md
│   ├── compliance_map.md
│   └── red_team_report.md
│
└── website/
    └── index.html                         React SPA (no build step, CDN)
```

---

## Research Paper

**ARC: A Two-Phase Cryptographic Receipt Protocol for Verifiable AI Agent Execution**
Ramachandra Kulkarni, Harin Kumar Mallela, Arun Basavaraj Alur -- April 2026
*Unpublished preprint. Not yet peer-reviewed.*

8 pages. Covers the action receipt primitive, seven JSON Schema definitions, the complete red team evaluation (6 holes found and fixed, 58/58 tests), and the live cross-agent verification proof on Windows 11 with Claude Code.

- LaTeX source: [`paper/arc_paper.tex`](paper/arc_paper.tex)
- Compiled PDF: [`paper/arc_paper.pdf`](paper/arc_paper.pdf) (or download from [Releases](https://github.com/RamachandraKulkarni/arc-protocol/releases))
- Website: [ramachandrakulkarni.github.io/arc-protocol](https://ramachandrakulkarni.github.io/arc-protocol) *(GitHub Pages, auto-deployed)*

**Document provenance (hardcoded in source, immutable without a git commit):**

| | |
|--|--|
| Research inception | March 2026 |
| Paper created | April 02, 2026 00:00:00 UTC |
| Protocol version | v1.1 |

**BibTeX:**

```bibtex
@misc{kulkarni2026arc,
  title        = {{ARC}: A Two-Phase Cryptographic Receipt Protocol for
                  Verifiable {AI} Agent Execution},
  author       = {Kulkarni, Ramachandra and Mallela, Harin Kumar and
                  Alur, Arun Basavaraj},
  year         = {2026},
  month        = apr,
  howpublished = {Unpublished preprint},
  note         = {Protocol v1.1. 58/58 tests. \url{https://github.com/RamachandraKulkarni/arc-protocol}}
}
```

---

## Authors

All three authors independently identified the AI agent observability trust gap. Ramachandra designed the protocol architecture, the seven-field canonical signing payload, the RFC 6962 Merkle log integration, and authored the Python reference implementation and red team test suite.

| Author | Role | LinkedIn |
|--------|------|----------|
| **Ramachandra Kulkarni** | Protocol design, implementation, red team | [linkedin.com/in/ramachandra-kulkarni26](https://www.linkedin.com/in/ramachandra-kulkarni26/) |
| **Harin Kumar Mallela** | Protocol analysis, adversarial modeling | [linkedin.com/in/harin-kumar-m](https://linkedin.com/in/harin-kumar-m) |
| **Arun Basavaraj Alur** | Protocol analysis, evaluation methodology | [linkedin.com/in/arun-basavaraj-alur](https://linkedin.com/in/arun-basavaraj-alur) |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, code style, and pull request requirements.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## License

MIT. See [LICENSE](LICENSE).
