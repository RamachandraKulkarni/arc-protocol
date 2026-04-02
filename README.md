# ARC Protocol

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests: 58/58](https://img.shields.io/badge/tests-58%2F58-brightgreen.svg)](tests/)
[![Protocol: v1.1](https://img.shields.io/badge/protocol-v1.1-blue.svg)](SPEC.md)
[![Status: Unpublished Preprint](https://img.shields.io/badge/status-unpublished%20preprint-orange.svg)](paper/arc_paper.tex)

**Cryptographic receipts for AI agent tool calls.**

The tool provider signs every action receipt with Ed25519  -  not the agent. Before execution, the resource state is snapshotted and the declared intent is committed to an RFC 6962 Merkle transparency log. After execution, the provider signs a seven-field canonical payload and commits the full receipt. An agent cannot forge the provider's signature to deny what happened, claim a different result, or lie about rollback availability.

**Protocol v1.1. 58/58 tests passing. 5/5 live receipts cross-verified. EU AI Act Article 12 ready.**

---

## The Problem

AI agents self-report their actions with no independent verification. When an agent says "I deleted the file," there is no cryptographic proof it happened, no proof of what existed before, and no signed commitment to undo it.

This failure mode has been documented repeatedly in production:

| Incident | What happened |
|----------|--------------|
| **Replit, 2024** | Agent deleted a production database, fabricated ~4,000 records to conceal it, then told the operator rollback was impossible. The rollback was available the entire time. |
| **Gemini CLI, 2025** | Agent deleted user files during autonomous coding sessions without explicit authorization. |
| **Claude Code, 2025** | Agent deleted project files during autonomous operations; no tamper-evident record of what existed before. |
| **Amazon Kiro, 2025** | Performed destructive schema migrations without rollback specification in the agentic IDE. |
| **Warehouse management agent, 2025** | Wiped 1.9 million inventory rows from a production database. No before-state captured. |

These incidents share the same structure: the agent is the only witness to its own actions. Existing tools cannot help:

- **LangSmith, LangFuse, Arize Phoenix**: capture self-reported execution traces; no cryptographic integrity; mutable; cannot distinguish accurate logs from fabricated ones.
- **MCP, OpenAI function calling, Anthropic tool use**: return plain text results with no signature, no before-state, and no rollback specification. A tool response is indistinguishable at the protocol level from a hallucination.
- **OpenTelemetry, OpenLineage**: structured tracing without tamper evidence; self-reported; do not satisfy EU AI Act Article 12.

**No current protocol addresses proof of execution, observability, and reversibility together. ARC does.**

---

## How ARC Works

Every tool call produces an **Action Receipt** in two phases:

```
PHASE 1: PRE-ACTION (before the tool runs)
─────────────────────────────────────────
  1. Snapshot resource state → SHA-256 hash → store at snap_<ULID>
  2. Agent declares intent (tool, args, agent_id, reasoning_hash, on_behalf_of)
  3. Commit intent to RFC 6962 Merkle log → get sequence_number + inclusion_proof

PHASE 2: POST-EXECUTION (after the tool runs)
──────────────────────────────────────────────
  4. Tool executes → capture actual return value → outcome_hash = SHA-256(result)
  5. Provider builds 7-field canonical payload (keys sorted, no whitespace, UTF-8)
  6. Provider signs payload with Ed25519 private key → signature
  7. Provider signs inverse operation (rollback spec) separately
  8. Commit full receipt to Merkle log → receipt now publicly verifiable
```

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

The tool provider signs this payload  -  not the agent. This is the core architectural decision: the party with ground-truth knowledge of what actually executed provides the cryptographic attestation. An agent that fabricates results produces a receipt whose signature does not verify. An agent that claims rollback is impossible contradicts the provider-signed `inverse_signature` in the receipt.

---

## The Three Guarantees

### 1. Proof of Execution

The `outcome_hash` in Phase 2 is the SHA-256 of the canonical JSON of the tool's actual return value. The provider signs this hash alongside the `receipt_id` and `before_state_hash`. If an agent reports a different result than what the provider attested, the signature does not verify  -  regardless of how plausible the fabrication appears in natural language.

```python
# Verification catches fabrication:
tampered = copy.deepcopy(receipt)
tampered["phase_2"]["execution"]["outcome_hash"] = sha256_hex(canonical_json({"deleted": 0}))
result = verify_receipt(tampered, registry)
# result["valid"] == False
# result["checks"]["provider_signature_valid"] == False
```

### 2. Tamper-Evident Observability (EU AI Act Article 12)

Every Phase 1 intent and Phase 2 receipt is an entry in an RFC 6962 Merkle tree. Each entry records `previous_root` (the Merkle root before it was appended) and `merkle_root` (after). These chain: `entry[n].merkle_root == entry[n+1].previous_root`. Any modification to any entry breaks the chain at a specific sequence number, detectable by any auditor with read access to the log.

The log server signs each entry with its own keypair (the log operator signature), providing non-repudiation at the log level as well as the receipt level.

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

The `inverse_signature` covers `{receipt_id, inverse_tool, inverse_arguments, valid_until}`. An agent cannot set `is_reversible = false` without invalidating this signature. An agent cannot claim the rollback window has expired without forging the provider's Ed25519 key. The `rollback_filesystem()` function restores the before-state from the snapshot.

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
pip install arc-protocol
# or from source:
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

## Demo Scenarios

```bash
make demo-basic      # Generate one receipt, verify it, print full JSON
make demo-disaster   # Full Replit scenario: delete, fabricate, detect, rollback
make demo-verify RECEIPT_ID=arc_01...  # Third-party verify from receipt ID only
```

**`demo_disaster.py` output structure:**

```
=== ARC PROTOCOL DEMO: The Replit Scenario ===

[SETUP] Creating test directory with 3 files...
[PHASE 1] Agent declares intent to delete...
  Before-state captured: snap_01JTXM... (sha256:abc123...)
  Intent committed to log at sequence 0
  ✓ Phase 1 is immutable  -  agent cannot change what it declared

[EXECUTION] Deleting directory...
  Directory deleted. Receipt ID: arc_01JTXM...

--- BEHAVIOR 1: Agent fabricates result ---
  Fabricated hash: sha256:jkl012...
  Receipt hash:    sha256:def456...
  ✗ MISMATCH  -  provider signature does not match
  ✓ ARC detected fabrication

--- BEHAVIOR 2: Agent tampers with log ---
  Merkle chain broken at sequence 0
  ✓ ARC detected log tampering

--- BEHAVIOR 3: Agent claims rollback impossible ---
  receipt.phase_2.inverse.is_reversible = TRUE (signed by provider)
  ✓ ARC refuted the rollback denial

--- ROLLBACK ---
  Restored: report.txt  ✓
  Restored: config.json ✓
  Restored: users.csv   ✓
  ✓ All files restored
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

Five receipts were generated in a real Claude Code session on Windows 11 and verified by a completely isolated Python process with zero session knowledge  -  no access to the original keypairs, context, or tool runtime. The verifier received only the receipt IDs and a log server URL.

| Receipt ID | Action | Intent seq | Receipt seq |
|------------|--------|-----------|-------------|
| `arc_01KN6RGD75FMHNC1TBZ5MBZE7F` | create data.csv | 2 | 3 |
| `arc_01KN6SYG39A1FMXTQTAWDM97H3` | read data.csv | 4 | 5 |
| `arc_01KN6T08ZM9VXSAHVP1Y7QR5EB` | create process.py | 6 | 7 |
| `arc_01KN6T2HBHRW4PBDYHXWSYVD6Z` | create results.txt | 8 | 9 |
| `arc_01KN6T3RFS3N41YDFMG6QJRDQ1` | create summary.json | 10 | 11 |

**All 4 checks passed for all 5 receipts:** `found_in_log`, `log_chain_consistent`, `intent_committed`, `receipt_committed`.

Intent sequence numbers (2, 4, 6, 8, 10) always preceded receipt sequence numbers (3, 5, 7, 9, 11). This proves Phase 1 was committed before execution in every case  -  the log ordering cannot be faked after the fact.

```
Total: 5  Valid: 5  Invalid: 0
OVERALL: ALL VALID  -  PROOF COMPLETE
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

---

## EU AI Act Article 12 Compliance

Article 12 logging requirements enforce on **August 2, 2026**. Fines up to €35M or 7% of global revenue.

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
Ramachandra Kulkarni, Harin Kumar Mallela, Arun Basavaraj Alur  -  April 2026
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
